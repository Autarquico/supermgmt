// Package jointest holds the node stand-in the CLI tests of `sm join --tunnel`
// use: the cli package may not name the transport types itself.
package jointest

import (
	"context"
	"errors"
	"io/fs"

	"github.com/autarquico/supermgmt/internal/join"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// ErrStopped ends the install at its first change.
var ErrStopped = errors.New("jointest: stopped at the first change")

// StoppingHost passes every check of a Debian 13 node without cloudflared and
// without a supermgmt account, then fails the first step that would change it.
type StoppingHost struct {
	HostKey      string // the host public key line
	PreflightErr error
	// Mutated reports whether anything that changes the node was attempted.
	Mutated bool
}

var _ join.TunnelHost = (*StoppingHost)(nil)

func (h *StoppingHost) Preflight() error             { return h.PreflightErr }
func (h *StoppingHost) PreflightTunnel() error       { return h.PreflightErr }
func (h *StoppingHost) Executor() transport.Executor { return h }
func (h *StoppingHost) Hostname() (string, error)    { return "edge-1", nil }
func (h *StoppingHost) Addresses() []string          { return nil }
func (h *StoppingHost) ReadFile(string) ([]byte, error) {
	return []byte(h.HostKey + " root@edge-1\n"), nil
}

func (h *StoppingHost) LookupAccount(string) (join.Account, bool, error) {
	return join.Account{}, false, nil
}
func (h *StoppingHost) AddAccount(context.Context, string) error              { return h.stop() }
func (h *StoppingHost) DisablePassword(context.Context, string) error         { return h.stop() }
func (h *StoppingHost) EnsureDir(string, fs.FileMode, string) error           { return h.stop() }
func (h *StoppingHost) InstallFile(string, []byte, fs.FileMode, string) error { return h.stop() }

func (h *StoppingHost) stop() error {
	h.Mutated = true
	return ErrStopped
}

// Run answers the read-only checks and stops at any other step.
func (h *StoppingHost) Run(_ context.Context, c templates.Command) (transport.Result, error) {
	switch c.Template {
	case "setup.os_release":
		return transport.Result{Stdout: []byte("debian trixie\n")}, nil
	case "setup.cloudflared_package":
		return transport.Result{ExitStatus: 1}, nil
	case "setup.file_sha256":
		return transport.Result{ExitStatus: 3}, nil
	}
	return transport.Result{}, h.stop()
}
