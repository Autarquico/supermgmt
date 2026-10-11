package join

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// systemRoot is a temporary tree whose /etc/passwd names the running user as
// "supermgmt", so ownership changes need no privilege.
func systemRoot(t *testing.T) System {
	t.Helper()
	root := t.TempDir()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "etc/passwd"),
		fmt.Sprintf("root:x:0:0:root:/root:/bin/bash\nsupermgmt:x:%s:%s::%s:/bin/sh\n", me.Uid, me.Gid, templates.HomeDir))
	mustWrite(t, filepath.Join(root, "etc/group"), fmt.Sprintf("root:x:0:\nsupermgmt:x:%s:\n", me.Gid))
	if err := os.MkdirAll(filepath.Join(root, templates.HomeDir), 0o750); err != nil {
		t.Fatal(err)
	}
	return System{Root: root}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLookupAccountReadsPasswdAndGroup(t *testing.T) {
	sys := systemRoot(t)
	me, _ := user.Current()

	account, found, err := sys.LookupAccount("supermgmt")

	uid, _ := strconv.Atoi(me.Uid)
	if err != nil || !found || account.UID != uid || account.Home != templates.HomeDir || account.Shell != "/bin/sh" || account.PrimaryGroup != "supermgmt" {
		t.Fatalf("LookupAccount = %+v, %v, %v", account, found, err)
	}
	if _, found, _ := sys.LookupAccount("nobody-here"); found {
		t.Fatal("found an account that is not in passwd")
	}
}

func TestEnsureDirCreatesWithTheModeAndRefusesSymlinksAndFiles(t *testing.T) {
	sys := systemRoot(t)
	ssh := filepath.Join(sys.Root, templates.SSHDir)

	if err := sys.EnsureDir(templates.SSHDir, 0o700, "supermgmt"); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if info, err := os.Stat(ssh); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("stat = %v, %v; want mode 0700", info, err)
	}

	markers := filepath.Join(sys.Root, templates.MarkerDir)
	if err := os.Symlink("/etc", markers); err != nil {
		t.Fatal(err)
	}
	if err := sys.EnsureDir(templates.MarkerDir, 0o700, "supermgmt"); err == nil {
		t.Fatal("a symlink in place of a directory must be refused")
	}
}

func TestInstallFileReplacesAtomicallyWithModeAndNeverFollowsSymlinks(t *testing.T) {
	sys := systemRoot(t)
	if err := sys.EnsureDir(templates.SSHDir, 0o700, "supermgmt"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sys.Root, templates.AuthorizedKeysPath)
	victim := filepath.Join(t.TempDir(), "victim")
	mustWrite(t, victim, "untouched")
	// A planted symlink at the staging name and at the destination.
	for _, planted := range []string{target + templates.StagingSuffix, target} {
		if err := os.Symlink(victim, planted); err != nil {
			t.Fatal(err)
		}
	}

	if err := sys.InstallFile(templates.AuthorizedKeysPath, []byte("key\n"), 0o600, "supermgmt"); err != nil {
		t.Fatalf("InstallFile: %v", err)
	}

	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatalf("victim = %q, want it untouched", got)
	}
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("target = %v, %v; want a regular 0600 file", info, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "key\n" {
		t.Fatalf("target = %q", got)
	}
	if _, err := os.Lstat(target + templates.StagingSuffix); !os.IsNotExist(err) {
		t.Fatal("the staging file was left behind")
	}
}
