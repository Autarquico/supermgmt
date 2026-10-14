package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenFileAt(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTokenFile_ReadsTheTokenWithoutItsNewline(t *testing.T) {
	path := tokenFileAt(t, "smm_abc\n", 0o600)
	got, err := readTokenFile(path, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "smm_abc" {
		t.Errorf("token = %q", string(got))
	}
}

func TestTokenFile_Refusals(t *testing.T) {
	linkTarget := tokenFileAt(t, "smm_abc", 0o600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		euid int
		want string
	}{
		{"group readable", tokenFileAt(t, "smm_abc", 0o640), os.Geteuid(), "0600"},
		{"world writable", tokenFileAt(t, "smm_abc", 0o666), os.Geteuid(), "0600"},
		{"foreign owner", tokenFileAt(t, "smm_abc", 0o600), os.Geteuid() + 1, "not owned by you"},
		{"symlink", link, os.Geteuid(), "--token-file"},
		{"directory", t.TempDir(), os.Geteuid(), "--token-file"},
		{"missing", filepath.Join(t.TempDir(), "nope"), os.Geteuid(), "--token-file"},
		{"empty", tokenFileAt(t, " \n", 0o600), os.Geteuid(), "empty"},
		{"two words", tokenFileAt(t, "smm_a smm_b", 0o600), os.Geteuid(), "single word"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readTokenFile(tt.path, tt.euid)
			if err == nil {
				t.Fatalf("accepted, token %q", string(got))
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
			if exitCode(err) != 2 {
				t.Errorf("exit code = %d, want 2", exitCode(err))
			}
		})
	}
}

func TestTokenFile_KeychainToken(t *testing.T) {
	store := &sinkMemCredentials{entries: map[string]string{"agent": "smm_kc\n"}}
	got, err := readKeychainToken(t.Context(), store, "agent")
	if err != nil || string(got) != "smm_kc" {
		t.Fatalf("token = %q, err = %v", string(got), err)
	}
	if _, err := readKeychainToken(t.Context(), store, "other"); exitCode(err) != 2 {
		t.Errorf("missing entry: exit code = %d, err = %v", exitCode(err), err)
	}
}
