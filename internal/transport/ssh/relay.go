package ssh

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// OpenRelay runs the relay command on the node as t.User over a pooled
// connection and returns the session's stdin/stdout as a net.Conn. The session
// counts against max_sessions_per_connection and holds its connection's lease
// until Close, so the connection is neither evicted as idle nor closed under
// it. Only opening is bounded (ssh.connect_timeout, ctx); the stream lives
// until Close.
func (p *Pool) OpenRelay(ctx context.Context, t Target, r templates.Relay) (net.Conn, error) {
	cmd, err := r.Command()
	if err != nil {
		return nil, err
	}
	if p.cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.cfg.ConnectTimeout)
		defer cancel()
	}
	for attempt := 0; ; attempt++ {
		rc, stale, err := p.openRelayOnce(ctx, t, cmd.Line)
		if !stale || attempt > 0 {
			return rc, err
		}
	}
}

// openRelayOnce reports stale=true only when the session could not even be
// opened, as runOnce does.
func (p *Pool) openRelayOnce(ctx context.Context, t Target, line string) (net.Conn, bool, error) {
	lc, err := p.acquire(ctx, t)
	if err != nil {
		return nil, false, err
	}
	select {
	case lc.sessions <- struct{}{}:
	case <-lc.closed:
		p.release(lc)
		return nil, true, unreachable("ssh connection closed", io.ErrClosedPipe)
	case <-ctx.Done():
		p.release(lc)
		return nil, false, ctxError("ssh relay", ctx.Err())
	}

	rc := &relayConn{
		pool: p, lc: lc, addr: relayAddr(net.JoinHostPort(t.Host, strconv.Itoa(t.Port))),
	}
	opened := make(chan startOutcome, 1)
	go func() { opened <- rc.start(line) }()
	select {
	case out := <-opened:
		if out.err != nil {
			_ = rc.Close()
			return nil, out.stale, out.err
		}
		return rc, false, nil
	case <-ctx.Done():
		// As in runSession: a session that never opened means a connection
		// presumed dead, closed so the hung NewSession returns. Whoever gets a
		// session closes it, and only then are its slot and lease given back.
		if s := rc.currentSession(); s != nil {
			_ = s.Close()
		} else {
			lc.close()
		}
		go func() { <-opened; _ = rc.Close() }()
		return nil, false, ctxError("ssh relay", ctx.Err())
	}
}

type relayAddr string

func (relayAddr) Network() string  { return "ssh-relay" }
func (a relayAddr) String() string { return string(a) }

// relayConn is the stdio of one relay session. The caller holds one end of a
// net.Pipe, which supplies deadlines and concurrent-safe I/O; two goroutines
// copy the other end to and from the session.
type relayConn struct {
	net.Conn // the caller's end of the pipe
	pool     *Pool
	lc       *liveConn
	addr     relayAddr

	peer       net.Conn // our end of the pipe
	session    *cryptossh.Session
	copies     sync.WaitGroup
	stderrDone chan struct{}
	tail       tailBuffer

	mu        sync.Mutex // guards session while start runs
	closeOnce sync.Once
}

type startOutcome struct {
	stale bool
	err   error
}

func (rc *relayConn) currentSession() *cryptossh.Session {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.session
}

// start opens the session and begins the relay. A failure leaves rc for Close
// to unwind.
func (rc *relayConn) start(line string) startOutcome {
	s, err := rc.lc.client.NewSession()
	if err != nil {
		rc.lc.close() // the connection is presumed dead, as in runSession
		return startOutcome{stale: true, err: unreachable("open ssh session", err)}
	}
	rc.mu.Lock()
	rc.session = s
	rc.mu.Unlock()
	stdin, err := s.StdinPipe()
	if err != nil {
		return startOutcome{err: unreachable("open ssh relay", err)}
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		return startOutcome{err: unreachable("open ssh relay", err)}
	}
	stderr, err := s.StderrPipe()
	if err != nil {
		return startOutcome{err: unreachable("open ssh relay", err)}
	}
	if err := s.Start(line); err != nil {
		return startOutcome{err: unreachable("start ssh relay", err)}
	}
	rc.Conn, rc.peer = net.Pipe()
	rc.stderrDone = make(chan struct{})

	rc.copies.Add(2)
	go func() { // node to caller; its end is the caller's EOF
		defer rc.copies.Done()
		_, _ = io.Copy(rc.peer, stdout)
		_ = rc.peer.Close()
	}()
	go func() { // caller to node; its end is the node's EOF
		defer rc.copies.Done()
		_, _ = io.Copy(stdin, rc.peer)
		_ = stdin.Close()
	}()
	go func() {
		defer close(rc.stderrDone)
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			rc.tail.write(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	return startOutcome{}
}

func (rc *relayConn) LocalAddr() net.Addr  { return rc.addr }
func (rc *relayConn) RemoteAddr() net.Addr { return rc.addr }

// Close ends the session and gives back its slot and the connection's lease,
// once. Safe to call concurrently and repeatedly; every call blocks until the
// first finishes.
func (rc *relayConn) Close() error {
	rc.closeOnce.Do(func() {
		if rc.Conn != nil {
			_ = rc.Conn.Close()
			_ = rc.peer.Close()
		}
		if s := rc.currentSession(); s != nil {
			_ = s.Close()
		}
		rc.awaitCopies()
		rc.awaitStderr()
		<-rc.lc.sessions
		rc.pool.release(rc.lc)
	})
	return nil
}

// awaitCopies waits, bounded, for the copies to see the session end. A node
// that stopped answering never acknowledges the close, so past the bound the
// connection is presumed dead and closed, which ends the reads.
func (rc *relayConn) awaitCopies() {
	done := make(chan struct{})
	go func() { rc.copies.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(diagnosticsWaitF):
		rc.lc.close()
	}
}

// awaitStderr waits, bounded, for the stderr drain to see the session end.
func (rc *relayConn) awaitStderr() {
	if rc.stderrDone == nil {
		return // the session never started
	}
	select {
	case <-rc.stderrDone:
	case <-time.After(diagnosticsWaitF):
	}
}

// Diagnostics is what the relay command said on stderr, bounded, on one line
// and scrubbed of anything shaped like a credential. Call after Close.
func (rc *relayConn) Diagnostics() string {
	rc.awaitStderr()
	return sanitizeDiagnostic(rc.tail.String())
}

var _ Diagnoser = (*relayConn)(nil)
