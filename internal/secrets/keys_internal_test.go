package secrets

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func statOf(t *testing.T, path string) fs.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestOwnershipIsPartOfTheKeyFileCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.key")
	if err := os.WriteFile(path, make([]byte, keySize), 0o600); err != nil {
		t.Fatal(err)
	}
	info := statOf(t, path)

	if got := keyFileProblem(info, os.Getuid()); got != "" {
		t.Errorf("own file refused: %s", got)
	}
	if got := keyFileProblem(info, os.Getuid()+1); !strings.Contains(got, "not owned") {
		t.Errorf("foreign owner accepted: %q", got)
	}
}

func TestOwnershipIsPartOfTheKeysDirCheck(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	info := statOf(t, dir)

	if got := dirProblem(info, os.Getuid()); got != "" {
		t.Errorf("own dir refused: %s", got)
	}
	if got := dirProblem(info, os.Getuid()+1); !strings.Contains(got, "not owned") {
		t.Errorf("foreign owner accepted: %q", got)
	}
}

func TestKeyFileMustBeRegular(t *testing.T) {
	if got := keyFileProblem(statOf(t, t.TempDir()), os.Getuid()); !strings.Contains(got, "regular") {
		t.Errorf("a directory was accepted as a key file: %q", got)
	}
}
