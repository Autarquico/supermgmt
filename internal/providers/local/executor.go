// Package local is the local provider (spec §14): it lets SuperMgmt read the
// machine it runs on through the same rendered templates it sends over SSH.
// It is read-only in M1; macOS has no systemd, and capabilities follow what
// the probe finds.
package local

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/textsafe"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	// ProviderType is the providers.type of the local provider.
	ProviderType = "local"
	// NodeKind is the nodes.kind of the machine itself.
	NodeKind = "local"
	// NativeID is the node's id within the provider.
	NativeID = "local"

	defaultCommandTimeout = 30 * time.Second
	waitDelay             = 2 * time.Second
)

// Executor runs rendered read templates through /bin/sh -c on this machine.
// It implements transport.Executor, so discovery and the runtime adapters
// cannot tell it from an SSH node.
type Executor struct {
	// CommandTimeout bounds a command that carries no deadline of its own.
	CommandTimeout time.Duration
}

var _ transport.Executor = Executor{}

// Run executes c. Mutating and sudo commands are refused: the local provider
// is read-only (spec §14, plan Q10). A non-zero exit status is a Result.
func (e Executor) Run(ctx context.Context, c templates.Command) (transport.Result, error) {
	if c.Mutating {
		return transport.Result{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "the local provider is read-only")
	}
	limit := e.CommandTimeout
	if c.Deadline > 0 {
		limit = c.Deadline
	}
	if limit <= 0 {
		limit = defaultCommandTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	stdout, stderr := &capped{maxBytes: c.MaxBytes, maxLines: c.MaxLines}, &capped{maxBytes: c.MaxBytes, maxLines: c.MaxLines}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", c.Line) //nolint:gosec // the line comes from the closed template catalog
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = waitDelay
	if len(c.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	err := cmd.Run()

	res := transport.Result{
		Stdout:    []byte(textsafe.Sanitize(stdout.buf.Bytes())),
		Stderr:    []byte(textsafe.Sanitize(stderr.buf.Bytes())),
		Truncated: stdout.truncated || stderr.truncated,
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		return transport.Withhold(c, res), nil
	case errors.As(err, &exit) && ctx.Err() == nil:
		res.ExitStatus = exit.ExitCode()
		return transport.Withhold(c, res), nil
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return transport.Result{}, smerr.Wrap(err, smerr.CodeTimeout, "", "local command exceeded its deadline")
	case ctx.Err() != nil:
		return transport.Result{}, ctx.Err()
	}
	return transport.Result{}, smerr.Wrap(err, smerr.CodeInternal, "", "local command could not run")
}

// capped keeps output up to maxBytes and maxLines (0 = unlimited lines) and
// discards the rest, always reporting full consumption so the child never
// blocks on a full pipe.
type capped struct {
	buf       bytes.Buffer
	maxBytes  int
	maxLines  int
	lines     int
	truncated bool
}

func (b *capped) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && !b.truncated {
		room := b.maxBytes - b.buf.Len()
		if room <= 0 || (b.maxLines > 0 && b.lines >= b.maxLines) {
			b.truncated = true
			break
		}
		take := min(len(p), room)
		if b.maxLines > 0 {
			if i := bytes.IndexByte(p[:take], '\n'); i >= 0 {
				take = i + 1
				b.lines++
			}
		}
		b.buf.Write(p[:take])
		p = p[take:]
	}
	return n, nil
}
