package m1

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

// privateKeyMarkers are byte strings that only a serialized private key
// contains: the PEM armor and the OpenSSH key magic, raw and in base64.
var privateKeyMarkers = [][]byte{
	[]byte("PRIVATE KEY"),
	[]byte("openssh-key-v1"),
	[]byte("b3BlbnNzaC1rZXktdjE"),
}

func keksOf(t *testing.T, in *instance) map[string][]byte {
	t.Helper()
	dir := filepath.Join(in.dir, "keys")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the keys directory: %v", err)
	}
	keks := map[string][]byte{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		keks[e.Name()] = b
	}
	if len(keks) == 0 {
		t.Fatal("the daemon wrote no key-encryption key; the scan would be vacuous")
	}
	return keks
}

// scanForSecrets fails if a private key or a KEK appears in any file of the
// instance outside the KEK files, or in any of the captured API responses.
func scanForSecrets(t *testing.T, in *instance, responses map[string][]byte) {
	t.Helper()
	keks := keksOf(t, in)
	needles := map[string][]byte{}
	for _, m := range privateKeyMarkers {
		needles["private key marker "+string(m)] = m
	}
	for name, kek := range keks {
		trimmed := bytes.TrimSpace(kek)
		needles["raw KEK "+name] = trimmed
		needles["hex KEK "+name] = []byte(hex.EncodeToString(trimmed))
		needles["base64 KEK "+name] = []byte(base64.StdEncoding.EncodeToString(trimmed))
	}
	check := func(where string, data []byte) {
		for what, needle := range needles {
			if len(needle) >= 16 && bytes.Contains(data, needle) {
				t.Errorf("%s contains %s", where, what)
			}
		}
	}
	scanned := 0
	err := filepath.WalkDir(in.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || filepath.Dir(path) == filepath.Join(in.dir, "keys") {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		check(strings.TrimPrefix(path, in.dir+"/"), data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk the instance directory: %v", err)
	}
	if scanned < 2 {
		t.Fatalf("scanned %d files; the database and the daemon log should both exist", scanned)
	}
	for name, body := range responses {
		check("API response "+name, body)
	}
}

// apiDump fetches every readable collection raw, as an operator tool would.
func apiDump(t *testing.T, in *instance, paths ...string) map[string][]byte {
	t.Helper()
	dump := map[string][]byte{}
	for _, p := range paths {
		r := in.raw(t, http.MethodGet, p, nil, "")
		if r.Status != http.StatusOK {
			t.Fatalf("GET %s = %d %s", p, r.Status, r.Body)
		}
		dump[p] = r.Body
	}
	return dump
}

func baseDumpPaths() []string {
	return []string{
		wire.PathMe, wire.PathSSHKey, wire.PathNodes, wire.PathProviders, wire.PathJobs + "?limit=500",
		wire.PathApprovals, wire.PathEvents + "?limit=500",
	}
}

func eventActions(t *testing.T, in *instance) []string {
	t.Helper()
	var actions []string
	cursor := ""
	for {
		page, err := in.client().ListEvents(t.Context(), wire.EventQuery{PageQuery: wire.PageQuery{Limit: wire.MaxLimit, Cursor: cursor}})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Items {
			actions = append(actions, e.Action)
		}
		if page.NextCursor == "" {
			return actions
		}
		cursor = page.NextCursor
	}
}

func count(items []string, want string) int {
	n := 0
	for _, item := range items {
		if item == want {
			n++
		}
	}
	return n
}

// Secrets (ADR-0016): the instance identity is generated once, audited by
// fingerprint, and survives a restart; no plaintext key reaches disk or the API.
func TestM1Secrets_IdentityIsGeneratedOnceAndNeverStoredInPlaintext(t *testing.T) {
	in := startedInstance(t)
	api := in.client()
	first, err := api.SSHKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || !strings.HasPrefix(first.AuthorizedKey, "ssh-ed25519 ") || !strings.HasPrefix(first.FingerprintSHA256, "SHA256:") {
		t.Fatalf("instance key = %+v, want ed25519 version 1 with a SHA256 fingerprint", first)
	}

	in.stopDaemon(syscall.SIGTERM)
	in.startDaemon()
	second, err := in.client().SSHKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("the identity changed across a restart: %+v -> %+v", first, second)
	}
	if got := count(eventActions(t, in), "ssh_identity.generated"); got != 1 {
		t.Errorf("%d ssh_identity.generated events after a restart, want exactly 1", got)
	}

	dump := apiDump(t, in, baseDumpPaths()...)
	if event := string(dump[wire.PathEvents+"?limit=500"]); strings.Contains(event, strings.Fields(first.AuthorizedKey)[1]) {
		t.Errorf("an event carries the public key material; the audit trail should carry the fingerprint only")
	} else if !strings.Contains(event, first.FingerprintSHA256) {
		t.Errorf("the identity event lacks the fingerprint %s", first.FingerprintSHA256)
	}
	scanForSecrets(t, in, dump)
}

// Secrets (§10): the key-encryption key is a precondition of starting.
func TestM1Secrets_MissingOrUnsafeKEKStopsTheDaemonWithExitFour(t *testing.T) {
	in := startedInstance(t)
	keysDir := filepath.Join(in.dir, "keys")
	entries, err := os.ReadDir(keysDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("keys dir = %v, %v; want exactly one KEK", entries, err)
	}
	kek := filepath.Join(keysDir, entries[0].Name())
	in.stopDaemon(syscall.SIGTERM)

	start := func() (int, string) {
		cmd := exec.CommandContext(t.Context(), in.bin, in.daemonArgs()...)
		cmd.Env = in.env
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), string(out)
		}
		return 0, string(out)
	}

	t.Run("a KEK with group and other permissions is refused", func(t *testing.T) {
		if err := os.Chmod(kek, 0o644); err != nil {
			t.Fatal(err)
		}
		code, out := start()
		if code != 4 {
			t.Errorf("daemon with a 0644 KEK exited %d, want 4\n%s", code, out)
		}
		if err := os.Chmod(kek, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a missing KEK is refused and named", func(t *testing.T) {
		moved := kek + ".moved"
		if err := os.Rename(kek, moved); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Rename(moved, kek) }()
		code, out := start()
		if code != 4 {
			t.Errorf("daemon without its KEK exited %d, want 4\n%s", code, out)
		}
		id := strings.TrimSuffix(filepath.Base(kek), ".key")
		if !strings.Contains(out, id) {
			t.Errorf("the failure does not name the missing KEK %s:\n%s", id, out)
		}
	})

	t.Run("the KEK back in place lets the daemon start", func(t *testing.T) {
		in.startDaemon()
		if _, err := in.client().SSHKey(t.Context()); err != nil {
			t.Fatalf("identity unreadable after the KEK came back: %v", err)
		}
	})
}
