package ssh

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/textsafe"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

type executor struct {
	pool   *Pool
	target Target
}

// Run executes one rendered command on the node over a pooled connection.
// A non-zero exit status is a Result. A command is never retried once it may
// have started; only a failure to open the session (a stale connection) is
// retried, once, on a fresh connection.
func (e executor) Run(ctx context.Context, c templates.Command) (transport.Result, error) {
	if limit := e.pool.commandLimit(c); limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	for attempt := 0; ; attempt++ {
		res, stale, err := e.runOnce(ctx, c)
		if !stale || attempt > 0 {
			return res, err
		}
	}
}

func (p *Pool) commandLimit(c templates.Command) time.Duration {
	limit := p.cfg.CommandTimeout
	if c.Deadline > 0 {
		limit = c.Deadline
	}
	if c.Mutating {
		limit += templates.KillAfter + commandSlack
	}
	return limit
}

// runOnce reports stale=true only when the session could not even be opened.
func (e executor) runOnce(ctx context.Context, c templates.Command) (res transport.Result, stale bool, err error) {
	lc, err := e.pool.acquire(ctx, e.target)
	if err != nil {
		return transport.Result{}, false, err
	}
	defer e.pool.release(lc)

	select {
	case lc.sessions <- struct{}{}:
		defer func() { <-lc.sessions }()
	case <-lc.closed:
		return transport.Result{}, true, unreachable("ssh connection closed", errors.New("closed"))
	case <-ctx.Done():
		return transport.Result{}, false, ctxError("ssh run", ctx.Err())
	}
	return runSession(ctx, lc, c)
}

type sessionOutcome struct {
	res   transport.Result
	stale bool
	err   error
}

// runSession drives one exec request. On cancellation or timeout it closes
// the session, and the whole connection only when the session never opened
// (the connection is then presumed dead).
func runSession(ctx context.Context, lc *liveConn, c templates.Command) (transport.Result, bool, error) {
	var (
		mu      sync.Mutex
		session *cryptossh.Session
	)
	done := make(chan sessionOutcome, 1)
	go func() {
		s, err := lc.client.NewSession()
		if err != nil {
			done <- sessionOutcome{stale: true, err: unreachable("open ssh session", err)}
			return
		}
		mu.Lock()
		session = s
		mu.Unlock()
		defer s.Close()
		done <- execute(s, c)
	}()

	select {
	case out := <-done:
		if out.stale {
			lc.close()
		}
		return out.res, out.stale, out.err
	case <-ctx.Done():
		mu.Lock()
		s := session
		mu.Unlock()
		if s != nil {
			_ = s.Close()
		} else {
			lc.close()
		}
		return transport.Result{}, false, ctxError("ssh run", ctx.Err())
	}
}

func execute(s *cryptossh.Session, c templates.Command) sessionOutcome {
	stdout, stderr := newLimitedBuffer(c.MaxBytes, c.MaxLines), newLimitedBuffer(c.MaxBytes, c.MaxLines)
	s.Stdout, s.Stderr = stdout, stderr
	if len(c.Stdin) > 0 {
		s.Stdin = bytes.NewReader(c.Stdin)
	}
	err := s.Run(c.Line)

	res := transport.Result{
		Stdout:    []byte(textsafe.Sanitize(stdout.Bytes())),
		Stderr:    []byte(textsafe.Sanitize(stderr.Bytes())),
		Truncated: stdout.truncated || stderr.truncated,
	}
	var exit *cryptossh.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		res.ExitStatus = exit.ExitStatus()
	default:
		return sessionOutcome{err: unreachable("ssh command did not complete", err)}
	}
	return sessionOutcome{res: res}
}
