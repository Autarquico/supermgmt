package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOfflineImportRefusesASymlinkedSourceAndLeavesBothPathsAlone(t *testing.T) {
	s, _ := keyedSandbox(t)
	target := sourceFile(t, "pve-api-token-value", 0o600)
	link := filepath.Join(filepath.Dir(target), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	r := s.runIn("", "secrets", "import", "--offline", "--delete-source", "--name", "a/b", "--from-file", link)

	if r.code != exitUsage || !strings.Contains(r.stderr, "symbolic link") {
		t.Errorf("exit %d, %q; want a usage error naming the link", r.code, r.stderr)
	}
	for _, path := range []string{target, link} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s was removed: %v", path, err)
		}
	}
}

func TestSecretFileThatIsNotARegularFileIsRefusedWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readSecretFile(fifo)

	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("err = %v", err)
	}
}

func TestSecretFileOwnedBySomeoneElseIsRefused(t *testing.T) {
	path := sourceFile(t, "v", 0o600)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	err = checkSecretFile(path, info, os.Geteuid()+1)

	if err == nil || !strings.Contains(err.Error(), "not owned by you") {
		t.Errorf("err = %v", err)
	}
}

func TestSecretFileIsNotRemovedOnceItsPathNamesAnotherFile(t *testing.T) {
	path := sourceFile(t, "original", 0o600)
	source, err := readSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "swapped in")

	if err := source.remove(); err == nil {
		t.Error("remove succeeded on a swapped path")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the swapped-in file was removed: %v", err)
	}
}

func TestSecretFileIsRemovedWhileItsPathStillNamesIt(t *testing.T) {
	path := sourceFile(t, "original", 0o600)
	source, err := readSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := source.remove(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the file survived: %v", err)
	}
}
