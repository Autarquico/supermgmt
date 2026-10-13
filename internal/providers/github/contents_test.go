package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

const (
	commitB      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	manifestPath = ".supermgmt/app.yaml"
)

func envWithRepo(t *testing.T) (*ghfake.Fake, *client, Repo) {
	t.Helper()
	f, c := newEnv(t)
	f.AddRepo(ghfake.Repo{ID: 42, OwnerID: 7, Owner: "acme", Name: "shop"})
	return f, c, Repo{ID: 42, OwnerID: 7, Owner: "acme", Name: "shop"}
}

func TestFile_ReadsTheExactCommitWithItsBlobSHA(t *testing.T) {
	f, c, repo := envWithRepo(t)
	content := []byte(strings.Repeat("services:\n  web:\n    image: nginx\n", 10)) // several base64 lines
	f.AddFile(42, commitA, manifestPath, content)
	f.AddFile(42, commitB, manifestPath, []byte("other commit"))

	got, err := c.File(context.Background(), repo, commitA, manifestPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Content) != string(content) || got.Path != manifestPath {
		t.Errorf("File = %q at %q", got.Content, got.Path)
	}
	if got.BlobSHA != ghfake.BlobSHA(content) || got.BlobSHA != blobSHA(content) {
		t.Errorf("BlobSHA = %s", got.BlobSHA)
	}
	if ref := f.Requests()[0].Query.Get("ref"); ref != commitA {
		t.Errorf("ref sent = %q: the read must be pinned to the commit, never a branch", ref)
	}
	assertNothingRejected(t, f)
}

func TestFile_EscapesPathSegments(t *testing.T) {
	f, c, repo := envWithRepo(t)
	f.AddFile(42, commitA, "deploy/my app/compose#1?.yaml", []byte("x"))
	got, err := c.File(context.Background(), repo, commitA, "deploy/my app/compose#1?.yaml", 0)
	if err != nil || string(got.Content) != "x" {
		t.Fatalf("File = %+v, %v", got, err)
	}
}

func TestFile_Failures(t *testing.T) {
	f, c, repo := envWithRepo(t)
	f.AddFile(42, commitA, "dir/a.yaml", []byte("a"))
	f.AddFile(42, commitA, "big.bin", make([]byte, 300<<10))
	f.AddFile(42, commitA, "huge.bin", make([]byte, 2<<20))
	f.AddFile(42, commitA, "small.txt", []byte("0123456789"))
	tests := []struct {
		name, path string
		limit      int64
		wantTooBig bool
		wantStatus int
	}{
		{name: "missing file", path: "nope.yaml", wantStatus: http.StatusNotFound},
		{name: "above the default cap", path: "big.bin", wantTooBig: true},
		{name: "above 1 MiB (GitHub sends no content)", path: "huge.bin", wantTooBig: true},
		{name: "above the caller's cap", path: "small.txt", limit: 5, wantTooBig: true},
		{name: "directory", path: "dir"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.File(context.Background(), repo, commitA, tc.path, tc.limit)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantTooBig && !errors.Is(err, ErrFileTooLarge) {
				t.Errorf("err = %v, want ErrFileTooLarge", err)
			}
			var apiErr *APIError
			if tc.wantStatus != 0 && (!errors.As(err, &apiErr) || apiErr.Status != tc.wantStatus) {
				t.Errorf("err = %v, want status %d", err, tc.wantStatus)
			}
		})
	}
}

func TestFile_CapEqualToTheSizePasses(t *testing.T) {
	f, c, repo := envWithRepo(t)
	f.AddFile(42, commitA, "ten.txt", []byte("0123456789"))
	if _, err := c.File(context.Background(), repo, commitA, "ten.txt", 10); err != nil {
		t.Errorf("a file of exactly the cap must pass: %v", err)
	}
}

func TestFile_RefusesInvalidArgumentsBeforeAnyRequest(t *testing.T) {
	f, c, repo := envWithRepo(t)
	tests := []struct{ name, sha, path string }{
		{"branch instead of commit", "main", manifestPath},
		{"short sha", "abc123", manifestPath},
		{"empty path", commitA, ""},
		{"absolute path", commitA, "/etc/passwd"},
		{"dot-dot", commitA, "a/../../b"},
		{"leading dot-dot", commitA, "../a"},
		{"dot segment", commitA, "a/./b"},
		{"empty segment", commitA, "a//b"},
		{"trailing slash", commitA, "a/"},
		{"backslash", commitA, `a\b`},
		{"newline", commitA, "a\nb"},
		{"NUL", commitA, "a\x00b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.File(context.Background(), repo, tc.sha, tc.path, 0); err == nil {
				t.Error("expected an error")
			}
		})
	}
	if _, err := c.File(context.Background(), Repo{Owner: "a/b", Name: "c"}, commitA, manifestPath, 0); err == nil {
		t.Error("an owner with a slash must be refused")
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("requests = %d, want 0", n)
	}
}

func TestDecodeFile_RefusesAnswersThatDoNotMatchTheRequest(t *testing.T) {
	good := []byte("hello")
	doc := func(mutate func(map[string]any)) []byte {
		m := map[string]any{
			"type": "file", "encoding": "base64", "path": "a.txt", "size": len(good),
			"sha": blobSHA(good), "content": base64.StdEncoding.EncodeToString(good),
		}
		mutate(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if f, err := decodeFile(doc(func(map[string]any) {}), "a.txt", 100); err != nil || string(f.Content) != "hello" {
		t.Fatalf("baseline: %+v, %v", f, err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"symlink", func(m map[string]any) { m["type"] = "symlink" }},
		{"submodule", func(m map[string]any) { m["type"] = "submodule" }},
		{"other path", func(m map[string]any) { m["path"] = "b.txt" }},
		{"other encoding", func(m map[string]any) { m["encoding"] = "none" }},
		{"bad base64", func(m map[string]any) { m["content"] = "!!!" }},
		{"size mismatch", func(m map[string]any) { m["size"] = 3 }},
		{"blob sha mismatch", func(m map[string]any) { m["sha"] = strings.Repeat("0", 40) }},
		{"content swapped", func(m map[string]any) { m["content"] = base64.StdEncoding.EncodeToString([]byte("HELLO")) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeFile(doc(tc.mutate), "a.txt", 100); err == nil {
				t.Error("expected an error")
			}
		})
	}
	if _, err := decodeFile([]byte("not json"), "a.txt", 100); err == nil {
		t.Error("non-JSON must be refused")
	}
}
