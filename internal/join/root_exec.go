package join

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/textsafe"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	// rootCommandTimeout bounds a command that carries no deadline of its own;
	// an apt install on a slow mirror is the longest one.
	rootCommandTimeout = 10 * time.Minute
	rootWaitDelay      = 2 * time.Second
	// rootOutputLimit bounds what one command may hand back.
	rootOutputLimit = 64 << 10
)

// rootExecutor runs rendered setup templates on this machine, as the root
// process that runs `sm join`: no SSH and no sudo. The lines come from the
// closed template catalog; content (the connector token) arrives only on
// stdin, so no line, error or result carries it.
type rootExecutor struct{}

var _ transport.Executor = rootExecutor{}

func (rootExecutor) Run(ctx context.Context, c templates.Command) (transport.Result, error) {
	limit := rootCommandTimeout
	if c.Deadline > 0 {
		limit = c.Deadline
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	maxBytes := rootOutputLimit
	if c.MaxBytes > 0 {
		maxBytes = c.MaxBytes
	}
	stdout, stderr := &boundedBuffer{max: maxBytes}, &boundedBuffer{max: maxBytes}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", c.Line) //nolint:gosec // the line comes from the closed template catalog
	cmd.Env = append(os.Environ(), "PATH="+os.Getenv("PATH")+sbinPath)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = rootWaitDelay
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
		return transport.Result{}, smerr.New(smerr.CodeTimeout, "", "a command on this node exceeded its deadline")
	case ctx.Err() != nil:
		return transport.Result{}, ctx.Err()
	}
	return transport.Result{}, smerr.New(smerr.CodeInternal, "", "a command on this node could not run")
}

// boundedBuffer keeps the first max bytes and discards the rest while still
// reporting full consumption, so the child never blocks on a full pipe.
type boundedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	consumed := len(p)
	room := max(b.max-b.buf.Len(), 0)
	if len(p) > room {
		b.truncated = true
		p = p[:room]
	}
	b.buf.Write(p)
	return consumed, nil
}
