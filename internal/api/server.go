// Package api serves /api/v1 (spec §23) on the daemon's Unix socket
// (ADR-0014). It authenticates nothing itself: the listener admits only the
// daemon's own UID, every accepted request is that user's identity
// (`local:<uid>`, credential local_socket), and authorization is the
// application services' job. Each route maps to exactly one catalog action or
// one exemption (routes.go); mutations carry an Idempotency-Key whose response
// bytes the application stores in the same transaction as the mutation.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleConnTimeout   = 2 * time.Minute
	maxBodyBytes      = 1 << 20
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

// Services are the application services the routes call.
type Services struct {
	Plans      *app.Plans
	Approvals  *app.Approvals
	Governance *app.Governance
	Services   *app.Services
	Queries    *app.Queries
	Inventory  *app.Inventory
	Sessions   *app.Sessions
	SSHKeys    *SSHKeys
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

// Options configure a Server. Services, IDs and Identity are required.
type Options struct {
	Services Services
	IDs      domain.IDGenerator
	// Identity is the daemon-issued identity of the local OS user: the caller
	// of every request, since the listener admits no other user.
	Identity  domain.ID
	Residency Residency // default: none
	// Ready reports whether the daemon can serve; default: always.
	Ready func(context.Context) error
	Log   *slog.Logger // default: discard
}

// Server is the HTTP side of the daemon.
type Server struct {
	svc       Services
	ids       domain.IDGenerator
	caller    app.Caller
	residency Residency
	ready     func(context.Context) error
	log       *slog.Logger

	handler http.Handler
	routes  []route

	closing   chan struct{}
	closeOnce sync.Once
	http      *http.Server
}

// New validates o and builds the route table.
func New(o Options) (*Server, error) {
	if err := o.Services.complete(); err != nil {
		return nil, err
	}
	if o.IDs == nil {
		return nil, errors.New("api: id generator is required")
	}
	if o.Identity == "" {
		return nil, errors.New("api: caller identity is required")
	}
	s := &Server{
		svc: o.Services, ids: o.IDs, residency: o.Residency, ready: o.Ready, log: o.Log,
		caller:  app.Caller{ID: o.Identity, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}, Source: "api"},
		closing: make(chan struct{}),
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
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	return s, nil
}

// Handler is the full request pipeline. It refuses requests whose connection
// was not admitted by RestrictToUID, so it is only useful behind Serve.
func (s *Server) Handler() http.Handler { return s.handler }

// Serve answers requests on l, which must be restricted to the daemon's UID
// with RestrictToUID, until Shutdown. It closes l when it returns, also when
// Shutdown came first.
func (s *Server) Serve(l net.Listener) error {
	if err := s.http.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve api: %w", err)
	}
	return nil
}

// Shutdown ends the presence streams, stops accepting and waits for the
// requests in flight until ctx ends.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() { close(s.closing) })
	return s.http.Shutdown(ctx)
}

func (s *Server) buildMux() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes {
		mux.Handle(rt.method+" "+rt.pattern, s.guard(rt))
	}
	mux.Handle("/", s.guard(route{do: notFound}))
	return mux
}

func notFound(http.ResponseWriter, *http.Request) error {
	return smerr.New(smerr.CodeNotFound, "", "no such route")
}

// guard is what every request goes through: a correlation ID, the peer check,
// the refusal of bearer credentials, residency accounting and panic recovery.
func (s *Server) guard(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withCorrelation(r, s.ids.NewID())
		w.Header().Set(wire.HeaderCorrelationID, correlationOf(r).String())
		defer s.recoverRequest(w, r)
		if err := s.admit(r); err != nil {
			s.writeError(w, r, err)
			return
		}
		if !rt.longLived {
			defer s.residency.Begin()()
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if err := rt.do(w, r); err != nil {
			s.writeError(w, r, err)
		}
	})
}

// admit refuses what cannot be this machine's user acting on the local socket.
func (s *Server) admit(r *http.Request) error {
	if _, ok := verifiedPeer(r.Context()); !ok {
		return smerr.New(smerr.CodeUnauthenticated, "", "peer credentials were not verified")
	}
	if _, bearer := r.Header[wire.HeaderAuthorization]; bearer {
		return smerr.New(smerr.CodeUnauthenticated, "", "the local socket authenticates by peer credentials; tokens are not accepted")
	}
	return nil
}

func (s *Server) recoverRequest(w http.ResponseWriter, r *http.Request) {
	if recovered := recover(); recovered != nil {
		s.writeError(w, r, fmt.Errorf("panic serving %s %s: %v", r.Method, r.URL.Path, recovered))
	}
}
