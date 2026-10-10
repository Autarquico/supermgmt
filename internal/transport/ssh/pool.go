// Package ssh is the agentless transport (spec §12, ADR-0015): a pool of
// persistent, keepalive'd, multiplexed connections authenticated against a
// database-pinned host key, plus credential resolution, host-key scanning and
// output limits. Commands come only from the templates sub-package.
package ssh

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
)

const (
	backoffBase  = time.Second
	backoffMax   = 5 * time.Minute
	commandSlack = 5 * time.Second
)

// Target identifies where and how to connect to one node. User is chosen by the
// app per ADR-0009(b); HostKey is the pinned key in authorized_keys form.
type Target struct {
	NodeID        domain.ID
	Host          string
	Port          int
	User          string
	HostKey       string
	CredentialRef string
}

// PoolConfig holds the ssh.* limits of spec §8.2.
type PoolConfig struct {
	ConnectTimeout           time.Duration
	CommandTimeout           time.Duration
	KeepaliveInterval        time.Duration
	MaxDialsInFlight         int
	MaxConnections           int
	MaxSessionsPerConnection int
	IdleConnectionTTL        time.Duration
}

// ConnStatus is the pool's view of one node.
type ConnStatus string

const (
	ConnConnected ConnStatus = "connected" // a live connection with a session in flight
	ConnIdle      ConnStatus = "idle"      // a live connection with none
	ConnBackoff   ConnStatus = "backoff"   // dials are suspended until NextDialAt
	ConnUnknown   ConnStatus = "unknown"   // no connection, no failure on record
)

// ConnState is a snapshot for the UI; it never dials.
type ConnState struct {
	Status     ConnStatus
	LastError  error
	NextDialAt time.Time
}

// connKey: one connection per node and login user. A node switches from
// admin_user to supermgmt after setup, and the setup verify step must reach
// the node as supermgmt while the bootstrap session is still running.
type connKey struct {
	node domain.ID
	user string
}

// Pool owns the connections. It is safe for concurrent use.
type Pool struct {
	cfg   PoolConfig
	creds CredentialResolver
	clock domain.Clock

	ctx  context.Context
	stop context.CancelFunc

	dials         chan struct{}
	janitorOnce   sync.Once
	mu            sync.Mutex
	peers         map[connKey]*peer
	janitorPeriod time.Duration
}

type peer struct {
	target   Target
	conn     *liveConn
	dial     *dialCall
	failures int
	nextDial time.Time
	lastErr  error
}

type dialCall struct {
	done chan struct{}
	err  error
}

type liveConn struct {
	client    *cryptossh.Client
	sessions  chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	active    int       // leases held; guarded by Pool.mu
	lastUsed  time.Time // guarded by Pool.mu
}

func (c *liveConn) close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.client.Close()
	})
}

func (c *liveConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// NewPool builds an empty pool. Counts below 1 are raised to 1.
func NewPool(cfg PoolConfig, creds CredentialResolver, clock domain.Clock) *Pool {
	cfg.MaxDialsInFlight = max(cfg.MaxDialsInFlight, 1)
	cfg.MaxConnections = max(cfg.MaxConnections, 1)
	cfg.MaxSessionsPerConnection = max(cfg.MaxSessionsPerConnection, 1)
	ctx, stop := context.WithCancel(context.Background())
	return &Pool{
		cfg: cfg, creds: creds, clock: clock, ctx: ctx, stop: stop,
		dials: make(chan struct{}, cfg.MaxDialsInFlight), peers: map[connKey]*peer{},
		janitorPeriod: max(cfg.IdleConnectionTTL/2, time.Second),
	}
}

// For binds an Executor to one node. Connecting is lazy: errors
// (NODE_UNREACHABLE, SSH_HOST_KEY_MISMATCH, TIMEOUT) surface from Run.
func (p *Pool) For(t Target) transport.Executor { return executor{pool: p, target: t} }

// State reports what the pool knows about a node without dialing.
func (p *Pool) State(node domain.ID) ConnState {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := ConnState{Status: ConnUnknown}
	for key, pe := range p.peers {
		if key.node != node {
			continue
		}
		switch {
		case pe.conn != nil && !pe.conn.isClosed() && pe.conn.active > 0:
			return ConnState{Status: ConnConnected}
		case pe.conn != nil && !pe.conn.isClosed():
			state = ConnState{Status: ConnIdle}
		case pe.lastErr != nil && state.Status == ConnUnknown:
			state = ConnState{Status: ConnBackoff, LastError: pe.lastErr, NextDialAt: pe.nextDial}
		}
	}
	return state
}

// Close stops background work and closes every connection.
func (p *Pool) Close() {
	p.stop()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pe := range p.peers {
		if pe.conn != nil {
			pe.conn.close()
			pe.conn = nil
		}
	}
}

func backoffDelay(failures int) time.Duration {
	d := backoffBase
	for i := 1; i < failures && d < backoffMax; i++ {
		d *= 2
	}
	return min(d, backoffMax)
}

// acquire returns a live connection with a lease already taken (so the
// connection cannot be evicted as idle), dialing at most once per node.
func (p *Pool) acquire(ctx context.Context, t Target) (*liveConn, error) {
	for {
		p.mu.Lock()
		pe := p.peerFor(t)
		now := p.clock.Now()
		if c := pe.conn; c != nil && !c.isClosed() {
			c.active++
			c.lastUsed = now
			p.mu.Unlock()
			return c, nil
		}
		call := pe.dial
		if call == nil {
			if now.Before(pe.nextDial) {
				err := pe.lastErr
				p.mu.Unlock()
				return nil, err
			}
			if err := p.makeRoomLocked(); err != nil {
				p.mu.Unlock()
				return nil, err
			}
			call = &dialCall{done: make(chan struct{})}
			pe.dial = call
			go p.dialPeer(ctx, connKey{t.NodeID, t.User}, pe, t, call)
		}
		p.mu.Unlock()

		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctxError("ssh connect", ctx.Err())
		}
		if call.err != nil {
			return nil, call.err
		}
	}
}

// peerFor returns the peer for t, replacing it when the target changed (new
// address, key or credential): the old connection is closed, backoff resets.
func (p *Pool) peerFor(t Target) *peer {
	key := connKey{t.NodeID, t.User}
	pe, ok := p.peers[key]
	if ok && pe.target == t {
		return pe
	}
	if ok && pe.conn != nil {
		pe.conn.close()
	}
	pe = &peer{target: t}
	p.peers[key] = pe
	return pe
}

// makeRoomLocked enforces max_connections by closing the least recently used
// idle connection. When every connection is busy the caller gets an error
// rather than an over-limit dial.
func (p *Pool) makeRoomLocked() error {
	for p.countLocked() >= p.cfg.MaxConnections {
		var victim *peer
		for _, pe := range p.peers {
			if pe.conn == nil || pe.conn.isClosed() || pe.conn.active > 0 {
				continue
			}
			if victim == nil || pe.conn.lastUsed.Before(victim.conn.lastUsed) {
				victim = pe
			}
		}
		if victim == nil {
			return smerr.New(smerr.CodeNodeUnreachable, "",
				"ssh connection limit reached: every pooled connection is busy")
		}
		victim.conn.close()
		victim.conn = nil
	}
	return nil
}

func (p *Pool) countLocked() int {
	n := 0
	for _, pe := range p.peers {
		if (pe.conn != nil && !pe.conn.isClosed()) || pe.dial != nil {
			n++
		}
	}
	return n
}

// detached keeps ctx's values but not its cancellation: a dial is shared by
// every caller waiting on the node, so one caller giving up must not abort it.
// Closing the pool does.
func (p *Pool) detached(ctx context.Context) (context.Context, func()) {
	dialCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(p.ctx, cancel)
	return dialCtx, func() { stop(); cancel() }
}

func (p *Pool) dialPeer(ctx context.Context, key connKey, pe *peer, t Target, call *dialCall) {
	dialCtx, release := p.detached(ctx)
	defer release()
	conn, err := p.connect(dialCtx, t)

	p.mu.Lock()
	defer p.mu.Unlock()
	defer close(call.done)
	pe.dial = nil
	now := p.clock.Now()
	switch {
	case err != nil:
		pe.failures++
		pe.lastErr = err
		pe.nextDial = now.Add(backoffDelay(pe.failures))
		call.err = err
	case p.peers[key] != pe || p.ctx.Err() != nil:
		conn.close()
		call.err = smerr.New(smerr.CodeNodeUnreachable, "", "ssh connection superseded while connecting")
	default:
		conn.lastUsed = now
		pe.conn, pe.failures, pe.lastErr, pe.nextDial = conn, 0, nil, time.Time{}
		p.watch(pe, conn)
	}
}

// connect performs one dial and handshake. The dial slot is held only while
// connecting, never during backoff.
func (p *Pool) connect(parent context.Context, t Target) (*liveConn, error) {
	if err := validateTarget(t); err != nil {
		return nil, err
	}
	select {
	case p.dials <- struct{}{}:
		defer func() { <-p.dials }()
	case <-p.ctx.Done():
		return nil, smerr.New(smerr.CodeNodeUnreachable, "", "ssh pool is closed")
	}
	ctx := parent
	if p.cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.cfg.ConnectTimeout)
		defer cancel()
	}
	pinned, err := parsePinned(t.HostKey)
	if err != nil {
		return nil, err
	}
	cred, err := p.creds.Resolve(ctx, t.CredentialRef)
	if err != nil {
		return nil, err
	}
	defer cred.Release()

	var mismatch *hostKeyMismatch
	cfg := &cryptossh.ClientConfig{
		User: t.User, Auth: []cryptossh.AuthMethod{cred.Auth},
		HostKeyCallback: pinned.callback(&mismatch), HostKeyAlgorithms: pinned.algorithms(),
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	nc, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, unreachable("connect to node", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	conn, chans, reqs, err := cryptossh.NewClientConn(nc, addr, cfg)
	stop()
	if err != nil {
		_ = nc.Close()
		return nil, classifyHandshake(ctx, err, mismatch, t.User)
	}
	return &liveConn{
		client:   cryptossh.NewClient(conn, chans, reqs),
		sessions: make(chan struct{}, p.cfg.MaxSessionsPerConnection),
		closed:   make(chan struct{}),
	}, nil
}

func classifyHandshake(ctx context.Context, err error, mismatch *hostKeyMismatch, user string) error {
	text := err.Error()
	switch {
	case mismatch != nil:
		return smerr.Wrap(mismatch, smerr.CodeSSHHostKeyMismatch, "", "ssh host key changed: "+mismatch.Error())
	case strings.Contains(text, "no common algorithm for host key"):
		return smerr.Wrap(err, smerr.CodeSSHHostKeyMismatch, "", "server does not offer the pinned host key type")
	case ctx.Err() != nil:
		return smerr.Wrap(err, smerr.CodeNodeUnreachable, "", "ssh handshake timed out")
	case strings.Contains(text, "unable to authenticate"):
		return smerr.Wrap(err, smerr.CodeNodeUnreachable, "", "ssh authentication failed for user "+user)
	}
	return unreachable("ssh handshake", err)
}

func validateTarget(t Target) error {
	if err := validateEndpoint(t.Host, t.Port); err != nil {
		return err
	}
	if t.User == "" || strings.HasPrefix(t.User, "-") || strings.ContainsAny(t.User, " \t\r\n\x00@") {
		return smerr.New(smerr.CodeInvalidArgument, "", "invalid ssh user")
	}
	return nil
}

// watch starts the goroutines that drop a dead connection and keep a live
// one probed. p.mu is held by the caller.
func (p *Pool) watch(pe *peer, c *liveConn) {
	go func() {
		_ = c.client.Wait()
		c.close()
		p.mu.Lock()
		defer p.mu.Unlock()
		if pe.conn == c {
			pe.conn = nil
		}
	}()
	if p.cfg.KeepaliveInterval > 0 {
		go p.keepalive(c)
	}
	if p.cfg.IdleConnectionTTL > 0 {
		p.janitorOnce.Do(func() { go p.janitor() })
	}
}

func (p *Pool) keepalive(c *liveConn) {
	ticker := time.NewTicker(p.cfg.KeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if !p.ping(c) {
				c.close()
				return
			}
		}
	}
}

// ping sends an OpenSSH keepalive and waits at most one interval for the reply.
func (p *Pool) ping(c *liveConn) bool {
	replied := make(chan error, 1)
	go func() {
		_, _, err := c.client.SendRequest("keepalive@openssh.com", true, nil)
		replied <- err
	}()
	timer := time.NewTimer(p.cfg.KeepaliveInterval)
	defer timer.Stop()
	select {
	case err := <-replied:
		return err == nil
	case <-timer.C:
		return false
	case <-c.closed:
		return false
	}
}

func (p *Pool) janitor() {
	ticker := time.NewTicker(p.janitorPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.reapIdle()
		}
	}
}

// reapIdle closes connections idle for at least idle_connection_ttl.
func (p *Pool) reapIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock.Now()
	for _, pe := range p.peers {
		if c := pe.conn; c != nil && c.active == 0 && now.Sub(c.lastUsed) >= p.cfg.IdleConnectionTTL {
			c.close()
			pe.conn = nil
		}
	}
}

func (p *Pool) release(c *liveConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c.active--
	c.lastUsed = p.clock.Now()
}
