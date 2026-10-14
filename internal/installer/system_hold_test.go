package installer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func holdUnit(t *testing.T) Unit {
	t.Helper()
	return Unit{Name: UnitName, Path: filepath.Join(t.TempDir(), UnitName)}
}

func holdArgv(r *recordingRunner) string {
	var out []string
	for _, c := range r.cmds {
		out = append(out, c.Name+" "+strings.Join(c.Args, " "))
	}
	return strings.Join(out, "|")
}

func TestSystemd_HoldDropInIsWrittenBeforeReloadAndDisable(t *testing.T) {
	u := holdUnit(t)
	dropIn := filepath.Join(u.Path+".d", "50-upgrade-hold.conf")
	r := &recordingRunner{answer: func(Command) ([]byte, error) {
		if _, err := os.Stat(dropIn); err != nil {
			t.Errorf("a command ran before the drop-in existed: %v", err)
		}
		return nil, nil
	}}
	if err := (systemd{runner: r}).Hold(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	want := "[Unit]\nRefuseManualStart=yes\nConditionPathExists=/nonexistent/supermgmt-upgrade-hold\n"
	if string(got) != want {
		t.Errorf("drop-in = %q", got)
	}
	if argv := holdArgv(r); argv != "systemctl daemon-reload|systemctl disable "+UnitName {
		t.Errorf("argv = %s", argv)
	}
}

func TestSystemd_HoldInUserScopeUsesTheUserManager(t *testing.T) {
	r := &recordingRunner{}
	if err := (systemd{runner: r, user: true}).Hold(context.Background(), holdUnit(t)); err != nil {
		t.Fatal(err)
	}
	if argv := holdArgv(r); argv != "systemctl --user daemon-reload|systemctl --user disable "+UnitName {
		t.Errorf("argv = %s", argv)
	}
}

func TestSystemd_RegisterLiftsTheHoldThenEnables(t *testing.T) {
	r := &recordingRunner{}
	u := holdUnit(t)
	s := systemd{runner: r}
	if err := s.Hold(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	if err := s.Register(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(u.Path + ".d"); !os.IsNotExist(err) {
		t.Errorf("the hold directory is still there: %v", err)
	}
	if argv := holdArgv(r); argv != "systemctl daemon-reload|systemctl enable "+UnitName {
		t.Errorf("argv = %s", argv)
	}
}

func TestSystemd_RegisterKeepsOtherDropIns(t *testing.T) {
	u := holdUnit(t)
	s := systemd{runner: &recordingRunner{}}
	if err := s.Hold(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(u.Path+".d", "10-operator.conf")
	if err := os.WriteFile(other, []byte("[Service]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("the operator's drop-in was removed: %v", err)
	}
}

func TestSystemd_RegisterWithoutAHoldSucceeds(t *testing.T) {
	if err := (systemd{runner: &recordingRunner{}}).Register(context.Background(), holdUnit(t)); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchd_HoldDisablesAndRegisterEnables(t *testing.T) {
	r := &recordingRunner{}
	l := launchd{runner: r, uid: 501}
	u := Unit{Name: LaunchdLabel, Path: "/Users/a/Library/LaunchAgents/" + LaunchdLabel + ".plist"}
	if err := l.Hold(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if err := l.Register(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	want := "launchctl disable gui/501/" + LaunchdLabel + "|launchctl enable gui/501/" + LaunchdLabel
	if got := holdArgv(r); got != want {
		t.Errorf("argv = %s", got)
	}
}
