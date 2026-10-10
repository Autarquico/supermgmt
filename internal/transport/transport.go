// Package transport is the seam between node-facing code (discovery, runtimes,
// app handlers) and how a rendered command reaches a node: over SSH
// (transport/ssh, ADR-0015) or on the local machine (providers/local). Both
// run the same rendered templates.
package transport

import (
	"context"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Result is what one command returned. Output is capped by the command's
// MaxBytes and MaxLines; Truncated says a cap was hit. Remote output is
// untrusted (spec §30): callers parse it, never execute or display it raw.
type Result struct {
	Stdout     []byte
	Stderr     []byte
	ExitStatus int
	Truncated  bool
}

// Executor runs rendered commands on the one node it is bound to. A non-zero
// exit status is a Result, not an error; errors are transport failures
// (NODE_UNREACHABLE, SSH_HOST_KEY_MISMATCH, TIMEOUT) or context cancellation.
type Executor interface {
	Run(ctx context.Context, c templates.Command) (Result, error)
}
