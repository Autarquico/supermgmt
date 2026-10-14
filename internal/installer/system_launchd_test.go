package installer

import (
	"context"
	"errors"
	"testing"
)

func launchdStopRunner(bootout, print error) *recordingRunner {
	return &recordingRunner{answer: func(c Command) ([]byte, error) {
		if c.Args[0] == "bootout" {
			return nil, bootout
		}
		return nil, print
	}}
}

func TestLaunchd_StopTreatsAnUnloadedJobAsStopped(t *testing.T) {
	bootoutFailed := &ExitStatus{Command: "launchctl", Code: 5}
	notFound := &ExitStatus{Command: "launchctl", Code: launchctlServiceNotFound}
	tests := []struct {
		name    string
		bootout error
		print   error
		wantErr bool
	}{
		{"bootout succeeds", nil, nil, false},
		{"bootout fails and the job is not loaded", bootoutFailed, notFound, false},
		{"bootout fails and the job is still loaded", bootoutFailed, nil, true},
		{"bootout fails and the state is unknowable", bootoutFailed, &ExitStatus{Command: "launchctl", Code: 1}, true},
		{"bootout fails and print cannot run", bootoutFailed, errors.New("exec failed"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := launchd{runner: launchdStopRunner(tc.bootout, tc.print), uid: 501}
			err := l.Stop(context.Background(), Unit{Name: LaunchdLabel, Path: "/p.plist"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, tc.bootout) {
				t.Errorf("the bootout failure must be returned, got %v", err)
			}
		})
	}
}

func TestLaunchd_StopAsksLaunchctlAboutTheLabelOnlyAfterBootoutFails(t *testing.T) {
	r := launchdStopRunner(&ExitStatus{Command: "launchctl", Code: 5}, &ExitStatus{Command: "launchctl", Code: launchctlServiceNotFound})
	l := launchd{runner: r, uid: 501}
	if err := l.Stop(context.Background(), Unit{Name: LaunchdLabel, Path: "/p.plist"}); err != nil {
		t.Fatal(err)
	}
	want := "launchctl bootout gui/501 /p.plist|launchctl print gui/501/" + LaunchdLabel
	if got := holdArgv(r); got != want {
		t.Errorf("argv = %s", got)
	}
}
