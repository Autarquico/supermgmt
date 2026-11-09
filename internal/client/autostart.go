package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/textsafe"
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
	child, err := spawn(cfg)
	if err != nil {
		return nil, &DaemonUnavailableError{Detail: "cannot start the daemon: " + err.Error(), Err: err}
	}
	return poll(ctx, cfg, dial, child)
}

// poll dials until the daemon answers. A daemon that exits with an error may
// only have lost the lock race to another daemon that is still starting, so the
// wait goes on; if it ends unanswered, the message carries what the daemon
// logged.
func poll(ctx context.Context, cfg *Autostart, dial dialFunc, child *daemonProcess) (net.Conn, error) {
	wait := cmpOr(cfg.Wait, defaultAutostartWait)
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(cmpOr(cfg.Poll, defaultAutostartPoll))
	defer ticker.Stop()
	var exitErr error
	for {
		conn, err := dial(ctx)
		if err == nil || !daemonAbsent(err) {
			return conn, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			detail := fmt.Sprintf("the daemon did not start within %s; see %s", wait, cfg.LogPath)
			if exitErr != nil {
				detail = fmt.Sprintf("the daemon did not start (%v): %s; see %s", exitErr, child.startError(cfg.LogPath), cfg.LogPath)
			}
			return nil, &DaemonUnavailableError{Detail: detail, Err: err}
		case exited := <-child.exited:
			child.exited = nil
			exitErr = exited
		case <-ticker.C:
		}
	}
}

// daemonProcess is a spawned daemon: where its output starts in the log, and
// how it ended (one value, nil for a clean exit).
type daemonProcess struct {
	logStart int64
	exited   chan error
}

// startError is the last lines the daemon logged since it was spawned, scrubbed
// and capped.
func (d *daemonProcess) startError(logPath string) string {
	f, err := os.Open(logPath) //nolint:gosec // the instance state dir
	if err != nil {
		return "it logged nothing"
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.NewSectionReader(f, d.logStart, maxStartLog))
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return "it logged nothing"
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	tail := textsafe.Line(audit.ScrubString(strings.Join(lines[max(0, len(lines)-3):], " | ")))
	return string([]rune(tail)[:min(len([]rune(tail)), maxStartLogShown)])
}

const (
	maxStartLog      = 16 << 10 // read at most this much of the log after the spawn
	maxStartLogShown = 400      // runes of it put in the error
)

func spawn(cfg *Autostart) (*daemonProcess, error) {
	log, err := openLog(cfg.LogPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = log.Close() }()
	start, err := log.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("read daemon log: %w", err)
	}
	cmd := exec.Command(cfg.Executable, cfg.Args...) //nolint:gosec,noctx // our own binary with caller-fixed args; the daemon outlives this process
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	child := &daemonProcess{logStart: start, exited: make(chan error, 1)}
	go func() { child.exited <- cmd.Wait() }() // also reaps a daemon that loses the lock race
	return child, nil
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
