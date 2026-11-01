package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// OpenStream runs a streaming command on the node over a pooled connection and
// returns its stdout (an export) or stdin (an import) as a transport.Stream.
// The session counts against max_sessions_per_connection and holds its
// connection's lease until the command has ended or was aborted. Only opening
// is bounded by ssh.connect_timeout; afterwards o.Total, o.Idle, o.Ceiling and
// ctx end the stream.
func (p *Pool) OpenStream(ctx context.Context, t Target, c templates.Command, o transport.StreamOptions) (transport.Stream, error) {
	if c.Stream == templates.StreamNone {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "only a streaming command can be opened as a stream")
	}
	if err := o.Valid(); err != nil {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", err.Error())
	}
	openCtx := ctx
	if p.cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		openCtx, cancel = context.WithTimeout(ctx, p.cfg.ConnectTimeout)
		defer cancel()
	}
	for attempt := 0; ; attempt++ {
		st, stale, err := p.openStreamOnce(openCtx, ctx, t, c, o)
		if !stale || attempt > 0 {
			return st, err
		}
	}
}

// openStreamOnce reports stale=true only when the session could not even be
// opened, as runOnce does.
func (p *Pool) openStreamOnce(openCtx, ctx context.Context, t Target, c templates.Command, o transport.StreamOptions) (transport.Stream, bool, error) {
	lc, err := p.acquire(openCtx, t)
	if err != nil {
		return nil, false, err
	}
	select {
	case lc.sessions <- struct{}{}:
	case <-lc.closed:
		p.release(lc)
		return nil, true, unreachable("ssh connection closed", io.ErrClosedPipe)
	case <-openCtx.Done():
		p.release(lc)
		return nil, false, ctxError("ssh stream", openCtx.Err())
	}

	st := &stream{pool: p, lc: lc, kind: c.Stream, opts: o, ctx: ctx, done: make(chan struct{})}
	opened := make(chan startOutcome, 1)
	go func() { opened <- st.start(c.Line) }()
	select {
	case out := <-opened:
		if out.err != nil {
			st.abandon()
			return nil, out.stale, out.err
		}
		go st.supervise()
		go st.watch()
		return st, false, nil
	case <-openCtx.Done():
		// As in OpenRelay: a session that never opened means a connection
		// presumed dead, closed so the hung NewSession returns. Whoever gets a
		// session ends it, and only then are its slot and lease given back.
		if s := st.currentSession(); s != nil {
			_ = s.Close()
		} else {
			lc.close()
		}
		go func() { <-opened; st.abandon() }()
		return nil, false, ctxError("ssh stream", openCtx.Err())
	}
}

type stream struct {
	pool *Pool
	lc   *liveConn
	kind templates.StreamKind
	opts transport.StreamOptions
	ctx  context.Context // the caller's: its end aborts the stream

	stdin  io.WriteCloser
	stdout io.Reader
	tail   tailBuffer

	moved   atomic.Int64
	drained atomic.Bool // no more bytes will move: only the total deadline applies

	mu         sync.Mutex // guards session and reason
	session    *cryptossh.Session
	reason     error // why the stream was aborted; the first one wins
	stderrDone chan struct{}

	terminateOnce sync.Once
	releaseOnce   sync.Once
	closeOnce     sync.Once
	done          chan struct{} // closed once exit, waitErr are set and the slot is free
	exit          int
	waitErr       error
}

func (st *stream) currentSession() *cryptossh.Session {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.session
}

// start opens the session and runs the command. A failure leaves st for
// abandon to unwind.
func (st *stream) start(line string) startOutcome {
	s, err := st.lc.client.NewSession()
	if err != nil {
		st.lc.close() // the connection is presumed dead, as in runSession
		return startOutcome{stale: true, err: unreachable("open ssh session", err)}
	}
	st.mu.Lock()
	st.session = s
	st.mu.Unlock()
	pipes := func() (err error) {
		if st.stdin, err = s.StdinPipe(); err != nil {
			return err
		}
		if st.stdout, err = s.StdoutPipe(); err != nil {
			return err
		}
		stderr, err := s.StderrPipe()
		if err != nil {
			return err
		}
		st.stderrDone = make(chan struct{})
		go func() {
			defer close(st.stderrDone)
			buf := make([]byte, 1024)
			for {
				n, err := stderr.Read(buf)
				st.tail.write(buf[:n])
				if err != nil {
					return
				}
			}
		}()
		return s.Start(line)
	}
	if err := pipes(); err != nil {
		return startOutcome{err: unreachable("start ssh stream", err)}
	}
	if st.kind == templates.StreamExport {
		_ = st.stdin.Close() // an export reads nothing
	}
	return startOutcome{}
}

// supervise waits for the command to end, then settles the result and gives
// back the slot and the lease. It is the only path that closes done.
func (st *stream) supervise() {
	err := st.currentSession().Wait()
	st.awaitStderr()

	st.mu.Lock()
	reason := st.reason
	st.mu.Unlock()
	var exit *cryptossh.ExitError
	switch {
	case reason != nil:
		st.waitErr = reason
	case err == nil:
	case errors.As(err, &exit):
		st.exit = exit.ExitStatus()
	default:
		st.waitErr = unreachable("ssh stream did not complete", err)
	}
	st.drained.Store(true)
	st.releaseSlot()
	close(st.done)
}

func (st *stream) awaitStderr() {
	if st.stderrDone == nil {
		return
	}
	select {
	case <-st.stderrDone:
	case <-time.After(diagnosticsWaitF):
	}
}

// abandon ends a session that never became a supervised stream.
func (st *stream) abandon() {
	st.endSession()
	st.releaseSlot()
}

// endSession asks the command to stop and closes its session.
func (st *stream) endSession() {
	if s := st.currentSession(); s != nil {
		_ = s.Signal(cryptossh.SIGTERM)
		_ = s.Close()
	}
}

func (st *stream) releaseSlot() {
	st.releaseOnce.Do(func() {
		<-st.lc.sessions
		st.pool.release(st.lc)
	})
}

// watch aborts the stream when the caller's context ends or a deadline passes.
func (st *stream) watch() {
	total := time.NewTimer(st.opts.Total)
	defer total.Stop()
	// The idle deadline is two quiet half-periods in a row, so a stall is
	// noticed after Idle and before 1.5 times Idle.
	idle := time.NewTicker(st.opts.Idle / 2)
	defer idle.Stop()
	seen, quiet := st.moved.Load(), 0
	for {
		select {
		case <-st.done:
			return
		case <-st.ctx.Done():
			st.abort(ctxError("ssh stream", context.Cause(st.ctx)))
			return
		case <-total.C:
			st.abort(smerr.Wrap(transport.ErrStreamTotal, smerr.CodeTimeout, "", "ssh stream: total deadline exceeded"))
			return
		case <-idle.C:
			if now := st.moved.Load(); now != seen || st.drained.Load() {
				seen, quiet = now, 0
				continue
			}
			if quiet++; quiet >= 2 {
				st.abort(smerr.Wrap(transport.ErrStreamIdle, smerr.CodeTimeout, "", "ssh stream: idle deadline exceeded"))
				return
			}
		}
	}
}

// Abort ends the command: it is signalled and its session closed, and a node
// that does not acknowledge within a second is presumed dead and its
// connection closed, which ends any read or write blocked on it.
func (st *stream) Abort() { st.abort(transport.ErrStreamAborted) }

func (st *stream) abort(reason error) {
	st.mu.Lock()
	if st.reason == nil {
		st.reason = reason
	}
	st.mu.Unlock()
	go st.terminate()
}

func (st *stream) terminate() {
	st.terminateOnce.Do(func() {
		st.endSession()
		select {
		case <-st.done:
		case <-time.After(diagnosticsWaitF):
			st.lc.close()
		}
	})
}

func (st *stream) failure(err error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reason != nil {
		return st.reason
	}
	return err
}

func (st *stream) progress(n int) bool {
	if st.moved.Add(int64(n)) > st.opts.Ceiling {
		st.abort(fmt.Errorf("%w: more than %d bytes", transport.ErrStreamCeiling, st.opts.Ceiling))
		return false
	}
	return true
}

func (st *stream) Read(p []byte) (int, error) {
	if st.kind != templates.StreamExport {
		return 0, transport.ErrStreamDirection
	}
	n, err := st.stdout.Read(p)
	if !st.progress(n) {
		return 0, st.failure(nil)
	}
	switch {
	case errors.Is(err, io.EOF):
		st.drained.Store(true)
		return n, st.failure(io.EOF) // an aborted stream never ends cleanly
	case err != nil:
		return n, st.failure(err)
	}
	return n, nil
}

func (st *stream) Write(p []byte) (int, error) {
	if st.kind != templates.StreamImport {
		return 0, transport.ErrStreamDirection
	}
	if st.moved.Load()+int64(len(p)) > st.opts.Ceiling {
		st.progress(len(p))
		return 0, st.failure(nil)
	}
	n, err := st.stdin.Write(p)
	st.progress(n)
	if err != nil {
		return n, st.failure(err)
	}
	return n, nil
}

func (st *stream) Close() error {
	st.closeOnce.Do(func() {
		st.drained.Store(true)
		_ = st.stdin.Close()
	})
	return nil
}

func (st *stream) Wait() (int, string, error) {
	<-st.done
	// The command can end before the caller has consumed or sent every byte, so
	// an abort (the ceiling, typically) can land after supervise settled the result.
	return st.exit, sanitizeDiagnostic(st.tail.String()), st.failure(st.waitErr)
}

var _ transport.Stream = (*stream)(nil)
