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
	// Transport and TunnelHostname come from the node endpoint. Absent
	// Transport means direct; TunnelHostname matters only for cloudflare.
	Transport      domain.Transport
	TunnelHostname string
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
//
// The transport is part of the key: a connection made through one transport is
// never handed out for another, so the candidate transport can be verified
// while the old one still serves.
type connKey struct {
	node      domain.ID
	user      string
	transport domain.Transport
}

func keyOf(t Target) connKey { return connKey{t.NodeID, t.User, t.Transport.Effective()} }

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
	dialers       map[domain.Transport]Dialer
	peers         map[connKey]*peer
	retiring      map[*liveConn]struct{} // replaced or invalidated connections that still hold leases
	closing       []*liveConn            // to close once mu is released; guarded by mu
	closesRunning int                    // connections handed to closeConns and not yet closed; guarded by mu
	janitorPeriod time.Duration
}

type peer struct {
	target   Target
	conn     *liveConn
	dial     *dialCall
	failures int
	nextDial time.Time
	lastErr  error
	epoch    int // bumped by Invalidate; a dial begun in an older epoch is discarded
}

type dialCall struct {
	done  chan struct{}
	err   error
	retry bool // the dial predates an Invalidate: callers dial again
}

type liveConn struct {
	client    *cryptossh.Client
	sessions  chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	retired   bool      // no new leases; closes when the last one is released
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
		dials: make(chan struct{}, cfg.MaxDialsInFlight), peers: map[connKey]*peer{}, dialers: map[domain.Transport]Dialer{domain.TransportDirect: directDialer{}}, retiring: map[*liveConn]struct{}{},
		janitorPeriod: max(cfg.IdleConnectionTTL/2, time.Second),
	}
}

// For binds an Executor to one node. Connecting is lazy: errors
// (NODE_UNREACHABLE, SSH_HOST_KEY_MISMATCH, TIMEOUT) surface from Run.
func (p *Pool) For(t Target) transport.Executor { return executor{pool: p, target: t} }

// State reports what the pool knows about a node without dialing.
func (p *Pool) State(node domain.ID) ConnState {
	p.mu.Lock()
	defer p.unlock()
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

// Close stops background work and closes every connection, in parallel: a
// carrier that is slow to exit costs one grace period, not one per node.
func (p *Pool) Close() {
	p.stop()
	p.mu.Lock()
	for _, pe := range p.peers {
		if pe.conn != nil {
			p.closeLater(pe.conn)
			pe.conn = nil
		}
	}
	for c := range p.retiring {
		p.closeLater(c)
	}
	clear(p.retiring)
	p.unlock()
}

// closeLater queues c to be closed when mu is released. Closing a connection
// can wait for its carrier child to exit, which must never happen under mu.
func (p *Pool) closeLater(c *liveConn) { p.closing = append(p.closing, c) }

// unlock releases mu, then closes what was queued, a bounded number at a time.
func (p *Pool) unlock() {
	conns := p.closing
	p.closing = nil
	p.closesRunning += len(conns)
	p.mu.Unlock()
	closeConns(conns)
	if len(conns) > 0 {
		p.mu.Lock()
		p.closesRunning -= len(conns)
		p.mu.Unlock()
	}
}

// maxParallelCloses bounds the closes running at once. A connection that is
// closing no longer counts toward max_connections, so a new dial is refused
// while this many are still closing: the live carriers never exceed
// max_connections + maxParallelCloses.
const maxParallelCloses = 16

func closeConns(conns []*liveConn) {
	if len(conns) == 1 {
		conns[0].close()
		return
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, maxParallelCloses)
	for _, c := range conns {
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			c.close()
		}()
	}
	wg.Wait()
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
			p.unlock()
			return c, nil
		}
		call := pe.dial
		if call == nil {
			if now.Before(pe.nextDial) {
				err := pe.lastErr
				p.unlock()
				return nil, err
			}
			if err := p.makeRoomLocked(); err != nil {
				p.unlock()
				return nil, err
			}
			call = &dialCall{done: make(chan struct{})}
			pe.dial = call
			go p.dialPeer(ctx, keyOf(t), pe, pe.epoch, t, call)
		}
		p.unlock()

		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctxError("ssh connect", ctx.Err())
		}
		if call.err != nil && !call.retry {
			return nil, call.err
		}
	}
}

// peerFor returns the peer for t, replacing it when the target changed (new
// address, key or credential): the old connection is closed, backoff resets.
func (p *Pool) peerFor(t Target) *peer {
	key := keyOf(t)
	pe, ok := p.peers[key]
	if ok && pe.target == t {
		return pe
	}
	if ok && pe.conn != nil {
		p.retireLocked(pe.conn)
	}
	pe = &peer{target: t}
	p.peers[key] = pe
	return pe
}

// makeRoomLocked enforces max_connections by closing the least recently used
// idle connection. When every connection is busy the caller gets an error
// rather than an over-limit dial.
func (p *Pool) makeRoomLocked() error {
	if p.closesRunning >= maxParallelCloses {
		return smerr.New(smerr.CodeNodeUnreachable, "",
			"ssh connection limit reached: too many connections are still closing")
	}
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
		p.closeLater(victim.conn)
		victim.conn = nil
	}
	return nil
}

// retireLocked stops handing out c and closes it once its leases drain, so
// commands already running on it are never cut short.
func (p *Pool) retireLocked(c *liveConn) {
	if c.active == 0 {
		p.closeLater(c)
		return
	}
	c.retired = true
	p.retiring[c] = struct{}{}
}

// Invalidate drops the pooled connections of (node, user), whatever their
// transport, so the next command authenticates afresh, for use after setup
// changes the account, its groups or its authorization. Commands in flight
// finish on the old connection; a dial already under way is discarded and
// repeated.
func (p *Pool) Invalidate(node domain.ID, user string) {
	p.mu.Lock()
	defer p.unlock()
	for key, pe := range p.peers {
		if key.node == node && key.user == user {
			p.invalidateLocked(pe)
		}
	}
}

// InvalidateNode is Invalidate for every login user of a node: the app calls
// it when the node's transport or tunnel hostname changes, so connections of
// the old transport retire as their leases drain.
func (p *Pool) InvalidateNode(node domain.ID) {
	p.mu.Lock()
	defer p.unlock()
	for key, pe := range p.peers {
		if key.node == node {
			p.invalidateLocked(pe)
		}
	}
}

func (p *Pool) invalidateLocked(pe *peer) {
	if pe.conn != nil {
		p.retireLocked(pe.conn)
		pe.conn = nil
	}
	pe.epoch++
	pe.failures, pe.lastErr, pe.nextDial = 0, nil, time.Time{}
}

func (p *Pool) countLocked() int {
	n := len(p.retiring)
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

// errSuperseded: Invalidate ran during the dial, so the connection predates it.
// Callers retry. errReplaced: another Target took over the (node, user) slot or
// the pool closed; callers fail instead of retrying, so two targets cannot
// replace each other forever.
var (
	errSuperseded = smerr.New(smerr.CodeNodeUnreachable, "", "ssh connection superseded while connecting")
	errReplaced   = smerr.New(smerr.CodeNodeUnreachable, "", "ssh connection replaced while connecting")
)

func (p *Pool) dialPeer(ctx context.Context, key connKey, pe *peer, startEpoch int, t Target, call *dialCall) {
	dialCtx, release := p.detached(ctx)
	defer release()
	conn, err := p.connect(dialCtx, t)

	p.mu.Lock()
	defer p.unlock()
	defer close(call.done)
	pe.dial = nil
	now := p.clock.Now()
	switch {
	case err != nil && pe.epoch != startEpoch:
		call.err, call.retry = errSuperseded, true
	case err != nil:
		pe.failures++
		pe.lastErr = err
		pe.nextDial = now.Add(backoffDelay(pe.failures))
		call.err = err
	case p.peers[key] == pe && pe.epoch != startEpoch && p.ctx.Err() == nil:
		p.closeLater(conn)
		call.err, call.retry = errSuperseded, true
	case p.peers[key] != pe || p.ctx.Err() != nil:
		p.closeLater(conn)
		call.err = errReplaced
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
	dialer, err := p.dialerFor(t)
	if err != nil {
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
	nc, err := dialer.DialContext(ctx, t)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	conn, chans, reqs, err := cryptossh.NewClientConn(nc, addr, cfg)
	stop()
	if err != nil {
		_ = nc.Close()
		return nil, classifyHandshake(ctx, err, mismatch, t.User, carrierNote(nc))
	}
	return &liveConn{
		client:   cryptossh.NewClient(conn, chans, reqs),
		sessions: make(chan struct{}, p.cfg.MaxSessionsPerConnection),
		closed:   make(chan struct{}),
	}, nil
}

// carrierNote is the sanitized reason a carrier gave for failing, read after
// the connection is closed.
func carrierNote(nc net.Conn) string {
	if d, ok := nc.(Diagnoser); ok {
		return d.Diagnostics()
	}
	return ""
}

func classifyHandshake(ctx context.Context, err error, mismatch *hostKeyMismatch, user, note string) error {
	text := err.Error()
	switch {
	case mismatch != nil:
		return smerr.Wrap(mismatch, smerr.CodeSSHHostKeyMismatch, "", "ssh host key does not match the pinned key")
	case strings.Contains(text, "no common algorithm for host key"):
		return smerr.Wrap(err, smerr.CodeSSHHostKeyMismatch, "", "server does not offer the pinned host key type")
	case ctx.Err() != nil:
		return smerr.Wrap(err, smerr.CodeNodeUnreachable, "", "ssh handshake timed out")
	case strings.Contains(text, "unable to authenticate"):
		return smerr.Wrap(err, smerr.CodeNodeUnreachable, "", "ssh authentication failed for user "+user+": the node does not accept the offered keys")
	}
	what := "ssh handshake"
	if note != "" {
		what += " (" + note + ")"
	}
	return unreachable(what, err)
}

func validateTarget(t Target) error {
	if err := validateEndpoint(t.Host, t.Port); err != nil {
		return err
	}
	if err := validateTransport(t); err != nil {
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
		defer p.unlock()
		delete(p.retiring, c)
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
	defer p.unlock()
	now := p.clock.Now()
	for _, pe := range p.peers {
		if c := pe.conn; c != nil && c.active == 0 && now.Sub(c.lastUsed) >= p.cfg.IdleConnectionTTL {
			p.closeLater(c)
			pe.conn = nil
		}
	}
}

func (p *Pool) release(c *liveConn) {
	p.mu.Lock()
	defer p.unlock()
	c.active--
	c.lastUsed = p.clock.Now()
	if c.retired && c.active == 0 {
		p.closeLater(c)
		delete(p.retiring, c)
	}
}
