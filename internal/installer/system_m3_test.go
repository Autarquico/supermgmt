package installer

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOSFilesAppendSyncCreatesTheFilePrivately(t *testing.T) {
	f := osFiles{}
	p := filepath.Join(t.TempDir(), "journal.jsonl")
	for _, line := range []string{"a\n", "b\n"} {
		if err := f.AppendSync(p, []byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(p)
	info, _ := os.Stat(p)
	if string(got) != "a\nb\n" || info.Mode().Perm() != 0o600 {
		t.Errorf("content %q mode %v", got, info.Mode())
	}
	if err := f.SyncDir(filepath.Dir(p)); err != nil {
		t.Errorf("SyncDir: %v", err)
	}
	if err := f.SyncDir(filepath.Join(filepath.Dir(p), "missing")); err == nil {
		t.Error("SyncDir of a missing directory must fail")
	}
}

func TestOSFilesRenameLinkAndHash(t *testing.T) {
	f := osFiles{}
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	_ = os.WriteFile(a, []byte("abc"), 0o600)
	if err := f.Link(a, b); err != nil {
		t.Fatal(err)
	}
	if err := f.Link(a, b); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second link: %v", err)
	}
	if err := f.Rename(b, c); err != nil {
		t.Fatal(err)
	}
	sum, err := f.Hash(c)
	if err != nil || sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("hash %q %v", sum, err)
	}
	if _, err := f.Hash(filepath.Join(dir, "none")); err == nil {
		t.Error("hash of a missing file")
	}
}

func TestOSFilesLockIsExclusiveUntilReleased(t *testing.T) {
	f := osFiles{}
	p := filepath.Join(t.TempDir(), "lock")
	release, err := f.Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Lock(p); err == nil {
		t.Fatal("a second holder got the lock")
	}
	release()
	again, err := f.Lock(p)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again()
}

func TestOSFilesListDir(t *testing.T) {
	f := osFiles{}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "x"), nil, 0o600)
	_ = os.Mkdir(filepath.Join(dir, "y"), 0o700)
	names, err := f.ListDir(dir)
	if err != nil || len(names) != 2 {
		t.Errorf("%v %v", names, err)
	}
	if names, err := f.ListDir(filepath.Join(dir, "none")); err != nil || len(names) != 0 {
		t.Errorf("missing dir: %v %v", names, err)
	}
}

func TestSensitiveCommandsKeepTheirOutputInMemory(t *testing.T) {
	var shown bytes.Buffer
	r := execRunner{stderr: &shown}
	out, err := r.Run(context.Background(), Command{Name: "/bin/sh", Args: []string{"-c", "echo STDOUT-SECRET; echo STDERR-SECRET >&2"}, Sensitive: true})
	if err != nil || strings.TrimSpace(string(out)) != "STDOUT-SECRET" || shown.Len() != 0 {
		t.Fatalf("success: out %q shown %q err %v", out, shown.String(), err)
	}
	out, err = r.Run(context.Background(), Command{Name: "/bin/sh", Args: []string{"-c", "echo STDOUT-SECRET; echo STDERR-SECRET >&2; exit 3"}, Sensitive: true})
	var status *ExitStatus
	if !errors.As(err, &status) || status.Code != 3 {
		t.Fatalf("err = %v", err)
	}
	if len(out) != 0 || shown.Len() != 0 || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("failure leaked: out %q shown %q err %v", out, shown.String(), err)
	}
	_, err = r.Run(context.Background(), Command{Name: "/nonexistent/secret-tool", Sensitive: true})
	if err == nil {
		t.Error("missing tool must fail")
	}
}

func TestPlainCommandsStillStreamStderr(t *testing.T) {
	var shown bytes.Buffer
	r := execRunner{stderr: &shown}
	_, _ = r.Run(context.Background(), Command{Name: "/bin/sh", Args: []string{"-c", "echo oops >&2"}})
	if !strings.Contains(shown.String(), "oops") {
		t.Errorf("stderr not streamed: %q", shown.String())
	}
}

func TestStoppedState(t *testing.T) {
	for show, want := range map[string]bool{
		"ActiveState=inactive\nMainPID=0\n":     true,
		"ActiveState=failed\nMainPID=0\n":       true,
		"ActiveState=active\nMainPID=42\n":      false,
		"ActiveState=inactive\nMainPID=42\n":    false,
		"ActiveState=deactivating\nMainPID=0\n": false,
		"":                                      false,
	} {
		if got := stoppedState(show); got != want {
			t.Errorf("stoppedState(%q) = %t", show, got)
		}
	}
}

func TestSystemdStopDisableLoadAndWait(t *testing.T) {
	var shows int
	r := &recordingRunner{answer: func(c Command) ([]byte, error) {
		if c.Args[0] == "show" {
			shows++
			if shows < 3 {
				return []byte("ActiveState=deactivating\nMainPID=7\n"), nil
			}
			return []byte("ActiveState=inactive\nMainPID=0\n"), nil
		}
		return nil, nil
	}}
	s := systemd{runner: r}
	u := Unit{Name: UnitName}
	ctx := context.Background()
	for _, err := range []error{s.Load(ctx, u), s.Stop(ctx, u), s.Disable(ctx, u), s.WaitStopped(ctx, u, 5*time.Second)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	for _, c := range r.cmds {
		seen = append(seen, c.Args[0])
	}
	if strings.Join(seen[:3], " ") != "daemon-reload stop disable" || shows != 3 {
		t.Errorf("commands %v, %d show calls", seen, shows)
	}
}

func TestSystemdLoadDoesNotEnable(t *testing.T) {
	r := &recordingRunner{}
	if err := (systemd{runner: r}).Load(context.Background(), Unit{Name: UnitName}); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.cmds {
		if c.Args[0] == "enable" || c.Args[0] == "restart" || c.Args[0] == "start" {
			t.Errorf("Load ran %v", c.Args)
		}
	}
}

func TestSystemdWaitStoppedTimesOut(t *testing.T) {
	r := &recordingRunner{answer: func(Command) ([]byte, error) { return []byte("ActiveState=active\nMainPID=7\n"), nil }}
	if err := (systemd{runner: r}).WaitStopped(context.Background(), Unit{Name: UnitName}, 300*time.Millisecond); err == nil {
		t.Fatal("a running unit must time out")
	}
}
