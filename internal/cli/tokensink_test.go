package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/autarquico/supermgmt/internal/client"
)

const sinkToken = "smm_abcdefghijklmnop"

func TestFileSinkPreflightRefusals(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) string // returns the --token-file path
	}{
		{"existing file", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "token")
			writeFile(t, path, "keep me")
			return path
		}},
		{"symlink at the path", func(t *testing.T) string {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			writeFile(t, target, "keep me")
			path := filepath.Join(dir, "token")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"dangling symlink at the path", func(t *testing.T) string {
			dir := t.TempDir()
			path := filepath.Join(dir, "token")
			if err := os.Symlink(filepath.Join(dir, "nowhere"), path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"group-writable directory", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "token")
		}},
		{"world-writable directory", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o707); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "token")
		}},
		{"missing directory", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "absent", "token")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			before := sinkDirListing(t, filepath.Dir(path))
			sink, err := openFileSink(path)
			if err == nil {
				t.Fatalf("preflight accepted %s", path)
			}
			if sink != nil || exitCode(err) != exitUsage {
				t.Errorf("sink=%v exit=%d, want nil and %d", sink, exitCode(err), exitUsage)
			}
			if got := sinkDirListing(t, filepath.Dir(path)); got != before {
				t.Errorf("directory changed: %q -> %q", before, got)
			}
		})
	}
}

func sinkDirListing(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "<unreadable>"
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return strings.Join(names, ",")
}

func TestFileSinkRefusesForeignOwner(t *testing.T) {
	dir := t.TempDir()
	if err := checkTokenDir(dir, os.Geteuid()+1); err == nil {
		t.Error("a directory owned by someone else was accepted")
	}
	file, err := os.OpenFile(filepath.Join(dir, "f"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := checkTokenFile(file, os.Geteuid()+1); err == nil {
		t.Error("a file owned by someone else was accepted")
	}
	if err := checkTokenFile(file, os.Geteuid()); err != nil {
		t.Errorf("own 0600 file refused: %v", err)
	}
}

func TestFileSinkRefusesLooseFileMode(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "f"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Chmod(0o640); err != nil {
		t.Fatal(err)
	}
	if err := checkTokenFile(file, os.Geteuid()); err == nil {
		t.Error("a 0640 file was accepted")
	}
}

func TestFileSinkStoresTokenWithMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	sink, err := openFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	location, err := sink.Store(context.Background(), sinkToken)
	if err != nil || location != path {
		t.Fatalf("Store = %q, %v", location, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != sinkToken {
		t.Fatalf("file = %q, %v", got, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
}

// sinkFaultyFile fails one step of the write path.
type sinkFaultyFile struct {
	file                   *os.File
	shortWrite             bool
	writeErr, syncErr, cls error
}

func (f *sinkFaultyFile) Write(b []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.shortWrite {
		return f.file.Write(b[:len(b)/2])
	}
	return f.file.Write(b)
}

func (f *sinkFaultyFile) Sync() error  { return f.syncErr }
func (f *sinkFaultyFile) Close() error { _ = f.file.Close(); return f.cls }

func TestFileSinkFailureRemovesPartialFile(t *testing.T) {
	tests := []struct {
		name  string
		fault func(*os.File) *sinkFaultyFile
		want  string
	}{
		{"short write", func(f *os.File) *sinkFaultyFile { return &sinkFaultyFile{file: f, shortWrite: true} }, io.ErrShortWrite.Error()},
		{"no space left", func(f *os.File) *sinkFaultyFile { return &sinkFaultyFile{file: f, writeErr: syscall.ENOSPC} }, "no space left"},
		{"fsync failure", func(f *os.File) *sinkFaultyFile { return &sinkFaultyFile{file: f, syncErr: syscall.EIO} }, "sync"},
		{"close failure", func(f *os.File) *sinkFaultyFile { return &sinkFaultyFile{file: f, cls: syscall.EIO} }, "close"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			sink, err := openFileSink(path)
			if err != nil {
				t.Fatal(err)
			}
			sink.out = tt.fault(sink.out.(*os.File))
			_, err = sink.Store(context.Background(), sinkToken)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("partial file left behind (stat: %v)", statErr)
			}
		})
	}
}

func TestFileSinkAbandonRemovesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	sink, err := openFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	sink.Abandon()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file left behind (stat: %v)", err)
	}
}

// sinkMemCredentials is an in-memory client.CredentialStore.
type sinkMemCredentials struct {
	entries  map[string]string
	getErr   error
	setErr   error
	deleted  []string
	location string
}

func (m *sinkMemCredentials) Get(_ context.Context, name string) (string, error) {
	if m.getErr != nil {
		return "", m.getErr
	}
	if v, ok := m.entries[name]; ok {
		return v, nil
	}
	return "", client.ErrNoCredential
}

func (m *sinkMemCredentials) Set(_ context.Context, name, token string) (string, error) {
	if m.setErr != nil {
		return "", m.setErr
	}
	if m.entries == nil {
		m.entries = map[string]string{}
	}
	m.entries[name] = token
	return m.location, nil
}

func (m *sinkMemCredentials) Delete(_ context.Context, name string) error {
	m.deleted = append(m.deleted, name)
	delete(m.entries, name)
	return nil
}

func TestKeychainSinkRefusesAnExistingEntry(t *testing.T) {
	store := &sinkMemCredentials{entries: map[string]string{"desk": "old"}}
	if _, err := openKeychainSink(context.Background(), store, "desk"); exitCode(err) != exitUsage {
		t.Errorf("exit = %d (%v), want %d", exitCode(err), err, exitUsage)
	}
	if store.entries["desk"] != "old" {
		t.Error("the existing entry was touched")
	}
}

func TestKeychainSinkRefusesWhenTheLookupFails(t *testing.T) {
	store := &sinkMemCredentials{getErr: errors.New("keychain locked")}
	if _, err := openKeychainSink(context.Background(), store, "desk"); exitCode(err) != exitUsage {
		t.Errorf("exit = %d (%v), want %d", exitCode(err), err, exitUsage)
	}
}

func TestKeychainSinkStoresTheToken(t *testing.T) {
	store := &sinkMemCredentials{location: "the keychain"}
	sink, err := openKeychainSink(context.Background(), store, "desk")
	if err != nil {
		t.Fatal(err)
	}
	location, err := sink.Store(context.Background(), sinkToken)
	if err != nil || !strings.Contains(location, "desk") {
		t.Fatalf("Store = %q, %v", location, err)
	}
	if store.entries["desk"] != sinkToken {
		t.Error("token not stored")
	}
}

func TestKeychainSinkFailureLeavesNoEntry(t *testing.T) {
	store := &sinkMemCredentials{setErr: errors.New("denied")}
	sink, err := openKeychainSink(context.Background(), store, "desk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Store(context.Background(), sinkToken); err == nil {
		t.Fatal("Store succeeded")
	}
	if len(store.deleted) != 1 || store.deleted[0] != "desk" {
		t.Errorf("deleted = %v, want the partial entry removed", store.deleted)
	}
}
