package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	defaultAutostartWait = 5 * time.Second
	defaultAutostartPoll = 50 * time.Millisecond
)

// Autostart says how to spawn the daemon (ADR-0014): the executable runs in
// its own session with stdio redirected to LogPath, and the client polls the
// socket for Wait.
type Autostart struct {
	// Executable is normally os.Executable(); Args normally ["daemon"].
	Executable string
	Args       []string
	LogPath    string
	Wait       time.Duration
	Poll       time.Duration
}

// autostarter serializes spawns inside one process; across processes the
// daemon's own locks make the losers exit quietly.
type autostarter struct{ mu sync.Mutex }

type dialFunc func(context.Context) (net.Conn, error)

func (a *autostarter) ensure(ctx context.Context, cfg *Autostart, dial dialFunc) (net.Conn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if conn, err := dial(ctx); err == nil || !daemonAbsent(err) {
		return conn, err
	}
	if err := spawn(cfg); err != nil {
		return nil, &DaemonUnavailableError{Detail: "cannot start the daemon: " + err.Error(), Err: err}
	}
	return poll(ctx, cfg, dial)
}

func poll(ctx context.Context, cfg *Autostart, dial dialFunc) (net.Conn, error) {
	wait := cmpOr(cfg.Wait, defaultAutostartWait)
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(cmpOr(cfg.Poll, defaultAutostartPoll))
	defer ticker.Stop()
	for {
		conn, err := dial(ctx)
		if err == nil || !daemonAbsent(err) {
			return conn, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, &DaemonUnavailableError{
				Detail: fmt.Sprintf("the daemon did not start within %s; see %s", wait, cfg.LogPath), Err: err,
			}
		case <-ticker.C:
		}
	}
}

func spawn(cfg *Autostart) error {
	log, err := openLog(cfg.LogPath)
	if err != nil {
		return err
	}
	defer func() { _ = log.Close() }()
	cmd := exec.Command(cfg.Executable, cfg.Args...) //nolint:gosec,noctx // our own binary with caller-fixed args; the daemon outlives this process
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap a daemon that loses the lock race
	return nil
}

func openLog(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // the instance state dir
	if err != nil {
		return nil, fmt.Errorf("open daemon log: %w", err)
	}
	return f, nil
}
