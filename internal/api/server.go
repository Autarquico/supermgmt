// Package api serves /api/v1 (spec §23) on two transports with one set of
// handlers (ADR-0017): the daemon's Unix socket in local mode, where the
// listener admits only the daemon's own UID and every request is that user's
// identity (`local:<uid>`, credential local_socket, bearer tokens refused,
// ADR-0014), and HTTPS in server mode, where every request but the health
// probes and the login endpoints carries a bearer token that the Resolver
// turns into a Caller. A separate admin socket serves four routes (admin.go).
//
// Each route maps to exactly one catalog action or one exemption (routes.go,
// ADR-0012). For every request the dispatcher stamps the route's action on
// the context (app.WithAction) and, for every write whose route is a catalog
// action, asks the restore hold whether the write may happen (Hold.Guard):
// writes outside the shared commit path rely on that call. Mutations that
// are retryable carry an Idempotency-Key whose response bytes the application
// stores in the same transaction as the mutation; the credential-issuing
// routes are never keyed and refuse the header.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleConnTimeout   = 2 * time.Minute
	maxHeaderBytes    = 64 << 10
	maxBodyBytes      = 1 << 20
	maxAuthBodyBytes  = 16 << 10
	maxSecretBytes    = 256 << 10
	bearerScheme      = "Bearer"
)

// Residency is how the server reports the clients that keep a local daemon
// resident (ADR-0014): long-lived clients hold GET /presence open, and every
// other request counts as in flight while it runs.
type Residency interface {
	Present() (leave func())
	Begin() (end func())
}

type noResidency struct{}

func (noResidency) Present() func() { return func() {} }
func (noResidency) Begin() func()   { return func() {} }

// Services are the application services the routes call. The M2 services are
// optional: a route whose service is nil answers CAPABILITY_UNAVAILABLE, which
// is how enrollment behaves until its service exists.
type Services struct {
	Plans      *app.Plans
	Approvals  *app.Approvals
	Governance *app.Governance
	Services   *app.Services
	Queries    *app.Queries
	Inventory  *app.Inventory
	Sessions   *app.Sessions
	SSHKeys    *SSHKeys

	Auth        app.Auth
	Keys        app.Keys
	Backups     app.Backups
	Hold        app.Hold
	Enrollments app.Enrollments
}

func (s Services) complete() error {
	switch {
	case s.Plans == nil:
		return errors.New("api: plans service is required")
	case s.Approvals == nil:
		return errors.New("api: approvals service is required")
	case s.Governance == nil:
		return errors.New("api: governance service is required")
	case s.Services == nil:
		return errors.New("api: services service is required")
	case s.Queries == nil:
		return errors.New("api: queries service is required")
	case s.Inventory == nil:
		return errors.New("api: inventory service is required")
	case s.Sessions == nil:
		return errors.New("api: sessions service is required")
	case s.SSHKeys == nil:
		return errors.New("api: ssh key reader is required")
	}
	return nil
}

// Resolver turns the bearer token of a request into its Caller
// (auth.DBResolver). A failure is the typed UNAUTHENTICATED error.
type Resolver interface {
	Resolve(ctx context.Context, bearer string) (app.Caller, error)
}

// StreamOptions time the event stream (ADR-0017); zero values take the
// defaults, which are what production runs with.
type StreamOptions struct {
	Poll           time.Duration // how often new events are looked for; default 1s
	Revalidate     time.Duration // credential and policy check; default 30s
	Heartbeat      time.Duration // comment frame; default 15s
	WriteTimeout   time.Duration // per frame; default 10s
	MaxPerIdentity int           // open streams per identity; default 4
}

func (o StreamOptions) withDefaults() StreamOptions {
	o.Poll = orDefault(o.Poll, time.Second)
	o.Revalidate = orDefault(o.Revalidate, 30*time.Second)
	o.Heartbeat = orDefault(o.Heartbeat, 15*time.Second)
	o.WriteTimeout = orDefault(o.WriteTimeout, 10*time.Second)
	if o.MaxPerIdentity <= 0 {
		o.MaxPerIdentity = 4
	}
	return o
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}

// Options configure a Server. Services and IDs are required, and exactly one
// of Identity (the Unix socket transport) and Resolver (HTTPS).
type Options struct {
	Services Services
	IDs      domain.IDGenerator
	// Identity is the daemon-issued identity of the local OS user: the caller
	// of every request on the Unix socket, since the listener admits no other.
	Identity domain.ID
	// Resolver authenticates bearer tokens on HTTPS.
	Resolver Resolver
	// Proxy is set in `server.tls.mode: proxy`; nil means the TCP peer is the
	// client (direct TLS).
	Proxy *Proxy
	// DB is read by the event stream to start at the end of the log. Without
	// it the stream is CAPABILITY_UNAVAILABLE.
	DB *database.DB
	// Clock times the rate limits; default: the system clock.
	Clock domain.Clock
	// RequestTimeout bounds a request that is not a stream; 0 means no bound.
	RequestTimeout time.Duration
	Stream         StreamOptions
	Residency      Residency // default: none
	// Ready reports whether the daemon can serve; default: always.
	Ready func(context.Context) error
	Log   *slog.Logger // default: discard
}

type transport int

const (
	viaUnixSocket transport = iota
	viaHTTPS
)

// Server is the HTTP side of the daemon.
type Server struct {
	responder
	svc       Services
	ids       domain.IDGenerator
	transport transport
	caller    app.Caller // Unix socket: the local user
	resolver  Resolver
	proxy     *Proxy
	db        *database.DB
	stream    StreamOptions
	timeout   time.Duration
	residency Residency
	ready     func(context.Context) error

	authLimit  *limiter
	writeLimit *limiter
	openMu     sync.Mutex
	open       map[domain.ID]int // event streams per identity

	handler http.Handler
	routes  []route

	closing   chan struct{}
	closeOnce sync.Once
	http      *http.Server
}

// New validates o and builds the route table of its transport.
func New(o Options) (*Server, error) {
	if err := o.Services.complete(); err != nil {
		return nil, err
	}
	if o.IDs == nil {
		return nil, errors.New("api: id generator is required")
	}
	if (o.Identity == "") == (o.Resolver == nil) {
		return nil, errors.New("api: exactly one of the local caller identity and the bearer resolver is required")
	}
	if o.Clock == nil {
		o.Clock = domain.SystemClock{}
	}
	s := &Server{
		responder: responder{log: o.Log}, svc: o.Services, ids: o.IDs, resolver: o.Resolver, proxy: o.Proxy, db: o.DB,
		stream: o.Stream.withDefaults(), timeout: o.RequestTimeout, residency: o.Residency, ready: o.Ready,
		authLimit: newLimiter(authRate, o.Clock.Now), writeLimit: newLimiter(writeRate, o.Clock.Now),
		open: map[domain.ID]int{}, closing: make(chan struct{}),
	}
	if o.Resolver != nil {
		s.transport = viaHTTPS
	} else {
		s.caller = app.Caller{ID: o.Identity, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}, Source: "api"}
	}
	if s.residency == nil {
		s.residency = noResidency{}
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.routes = s.buildRoutes()
	s.handler = s.buildMux()
	// One http.Server for the Server's whole life: a Shutdown that arrives
	// before Serve has started still makes that Serve return and close its
	// listener, instead of leaving it accepting forever.
	s.http = &http.Server{
		Handler:           s.handler,
		ConnContext:       connContext,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleConnTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	return s, nil
}

// Handler is the full request pipeline. On the Unix socket it refuses requests
// whose connection was not admitted by RestrictToUID, so it is only useful
// behind Serve.
func (s *Server) Handler() http.Handler { return s.handler }

// Serve answers requests on l until Shutdown. On the Unix socket l must be
// restricted to the daemon's UID with RestrictToUID; for HTTPS it is the
// listener the TLS configuration wraps (or the proxy's plain one). It closes l
// when it returns, also when Shutdown came first.
func (s *Server) Serve(l net.Listener) error {
	if err := s.http.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve api: %w", err)
	}
	return nil
}

// Shutdown ends the presence and event streams, stops accepting and waits for
// the requests in flight until ctx ends.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() { close(s.closing) })
	return s.http.Shutdown(ctx)
}

func (s *Server) buildMux() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes {
		mux.Handle(rt.method+" "+rt.pattern, s.guard(rt))
	}
	mux.Handle("/", s.guard(route{auth: authNone, do: notFound}))
	return mux
}

func notFound(http.ResponseWriter, *http.Request) error {
	return smerr.New(smerr.CodeNotFound, "", "no such route")
}

// scope is what the dispatcher learned about a request before the handler
// runs: who calls and from where.
type scope struct {
	caller app.Caller
	client netip.Addr // HTTPS: the requester, after the proxy rules
}

type scopeKey struct{}

func scopeOf(ctx context.Context) scope {
	v, _ := ctx.Value(scopeKey{}).(scope)
	return v
}

// guard is what every request goes through: a correlation ID, the security
// headers, the transport's admission (peer check or bearer), the rate limits,
// the action stamp and the restore-hold guard, residency accounting and panic
// recovery.
func (s *Server) guard(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withCorrelation(r, s.ids.NewID())
		setCommonHeaders(w, r)
		defer s.recoverRequest(w, r)
		r, err := s.admit(r, rt)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !rt.longLived {
			defer s.residency.Begin()()
			var cancel context.CancelFunc
			r, cancel = s.bound(w, r)
			defer cancel()
		}
		r.Body = http.MaxBytesReader(w, r.Body, rt.bodyLimit())
		if err := rt.do(w, r); err != nil {
			s.fail(w, r, err)
		}
	})
}

func setCommonHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set(wire.HeaderCorrelationID, correlationOf(r).String())
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// bound gives a request that is not a stream its deadline. The server sets no
// ReadTimeout or WriteTimeout of its own because they would also end the
// event stream.
func (s *Server) bound(w http.ResponseWriter, r *http.Request) (*http.Request, context.CancelFunc) {
	if s.timeout <= 0 {
		return r, func() {}
	}
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(s.timeout) //nolint:forbidigo // network deadlines are wall-clock
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	return r.WithContext(ctx), func() {
		cancel()
		// A kept-alive connection must not carry this request's deadlines.
		_ = rc.SetReadDeadline(time.Time{})
		_ = rc.SetWriteDeadline(time.Time{})
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if s.transport == viaHTTPS && smerr.CodeOf(err) == smerr.CodeUnauthenticated {
		w.Header().Set("WWW-Authenticate", bearerScheme)
	}
	s.writeError(w, r, err)
}

// admit decides whether the request may reach its handler and returns it with
// the scope and the action stamped on the context.
func (s *Server) admit(r *http.Request, rt route) (*http.Request, error) {
	var (
		sc  scope
		err error
	)
	if s.transport == viaUnixSocket {
		sc, err = s.admitLocal(r)
	} else {
		sc, err = s.admitRemote(r, rt)
	}
	if err != nil {
		return r, err
	}
	ctx := context.WithValue(r.Context(), scopeKey{}, sc)
	if rt.action != "" {
		ctx = app.WithAction(ctx, rt.action)
	}
	r = r.WithContext(ctx)
	if rt.credential {
		if _, keyed := r.Header[wire.HeaderIdempotencyKey]; keyed {
			return r, invalid("%s is not accepted here: this route issues a credential once and cannot be replayed", wire.HeaderIdempotencyKey)
		}
	}
	return r, s.holdGuard(ctx, rt, sc.caller)
}

// holdGuard refuses the writes of catalog actions during a restore hold. The
// exempt routes (login, logout, one's own tokens) only create or end
// credentials and are on the hold's exception list.
func (s *Server) holdGuard(ctx context.Context, rt route, by app.Caller) error {
	if s.svc.Hold == nil || !rt.writes() || !rt.isAction() {
		return nil
	}
	return s.svc.Hold.Guard(ctx, rt.action, by)
}

// admitLocal refuses what cannot be this machine's user acting on the local
// socket.
func (s *Server) admitLocal(r *http.Request) (scope, error) {
	if _, ok := verifiedPeer(r.Context()); !ok {
		return scope{}, smerr.New(smerr.CodeUnauthenticated, "", "peer credentials were not verified")
	}
	if _, bearer := r.Header[wire.HeaderAuthorization]; bearer {
		return scope{}, smerr.New(smerr.CodeUnauthenticated, "", "the local socket authenticates by peer credentials; tokens are not accepted")
	}
	return scope{caller: s.caller}, nil
}

// admitRemote applies, in order, the proxy rules, the per-address limit of the
// login routes, the bearer token the route asks for and the per-identity limit
// of writes.
func (s *Server) admitRemote(r *http.Request, rt route) (scope, error) {
	client, err := s.proxy.clientOf(r)
	if err != nil {
		return scope{}, err
	}
	if rt.isAuth() {
		if ok, after := s.authLimit.allow(client.String()); !ok {
			return scope{}, &rateLimited{after: after}
		}
	}
	by, err := s.bearerCaller(r, rt.auth)
	if err != nil {
		return scope{}, err
	}
	if rt.writes() && by.ID != "" {
		if ok, after := s.writeLimit.allow(by.ID.String()); !ok {
			return scope{}, &rateLimited{after: after}
		}
	}
	return scope{caller: by, client: client}, nil
}

func (s *Server) bearerCaller(r *http.Request, mode authMode) (app.Caller, error) {
	values := r.Header.Values(wire.HeaderAuthorization)
	switch {
	case mode == authNone, mode == authOptional && len(values) == 0:
		return app.Caller{}, nil
	case len(values) != 1:
		return app.Caller{}, smerr.New(smerr.CodeUnauthenticated, "", "send exactly one Authorization: Bearer header")
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) || strings.TrimSpace(token) == "" {
		return app.Caller{}, smerr.New(smerr.CodeUnauthenticated, "", "the Authorization header must be Bearer <token>")
	}
	return s.resolver.Resolve(r.Context(), strings.TrimSpace(token))
}

func (s *Server) recoverRequest(w http.ResponseWriter, r *http.Request) {
	if recovered := recover(); recovered != nil {
		s.writeError(w, r, fmt.Errorf("panic serving %s %s: %v", r.Method, r.URL.Path, recovered))
	}
}
