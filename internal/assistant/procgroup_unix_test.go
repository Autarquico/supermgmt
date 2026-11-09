//go:build darwin || linux

package assistant

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSession_ChildRunsInItsOwnProcessGroupAndCloseKillsTheGroup(t *testing.T) {
	claude, capture := fakeClaude(t, `sleep 60 &
echo $! > "$CAPTURE.sleep"
ps -o pgid= -p $$ > "$CAPTURE"
read line
wait
`)
	s := startSession(t, sessionConfig(claude))
	var pgid, sleeper int
	waitFor(t, func() bool {
		a, _ := os.ReadFile(capture)
		b, _ := os.ReadFile(capture + ".sleep")
		var err1, err2 error
		pgid, err1 = strconv.Atoi(strings.TrimSpace(string(a)))
		sleeper, err2 = strconv.Atoi(strings.TrimSpace(string(b)))
		return err1 == nil && err2 == nil
	})
	if pgid == syscall.Getpgrp() {
		t.Fatal("the child shares the process group of sm, so a terminal Ctrl-C reaches it")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return errors.Is(syscall.Kill(sleeper, 0), syscall.ESRCH) })
}

func TestSession_CancelKillsTheGroup(t *testing.T) {
	claude, capture := fakeClaude(t, "sleep 60 &\necho $! > \"$CAPTURE\"\nwait\n")
	cfg := sessionConfig(claude)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var sleeper int
	waitFor(t, func() bool {
		b, _ := os.ReadFile(capture)
		sleeper, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	})
	cancel()
	waitFor(t, func() bool { return errors.Is(syscall.Kill(sleeper, 0), syscall.ESRCH) })
	_ = s.Close()
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 5000 {
		if ok() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("timed out")
}
