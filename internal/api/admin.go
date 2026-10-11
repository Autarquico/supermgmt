package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// AdminRoute is one route of the admin socket.
type AdminRoute struct {
	Method, Pattern, Action string
}

// The admin socket serves exactly these routes (spec §23.1, ADR-0012) and
// nothing else: in particular no key management and nothing under /api/v1.
// The table is closed: adding a route means editing it and its test.
var adminRoutes = []AdminRoute{
	{http.MethodPost, wire.AdminPathBootstrapCode, app.ActionAdminBootstrapCode},
	{http.MethodPost, wire.AdminPathGrant, app.ActionAdminGrant},
	{http.MethodPost, wire.AdminPathRestoreComplete, app.ActionRestoreComplete},
	{http.MethodGet, wire.AdminPathDoctor, ""},
}

const maxAdminBodyBytes = 16 << 10

// AdminOptions configure the AdminServer. All fields but Log are required.
type AdminOptions struct {
	Auth app.AdminSocket
	Hold app.Hold
	// Doctor answers the read-only doctor route.
	Doctor func(context.Context) (wire.AdminDoctor, error)
	IDs    domain.IDGenerator
	Log    *slog.Logger
}

// AdminServer is the server-mode admin socket (spec §23.1). It authenticates
// by the peer UID alone: the listener must be restricted with RestrictToUIDs
// to root and the service user. Callers are not identities; the operations are
// audited as the daemon's, with the peer UID.
type AdminServer struct {
	responder
	opts AdminOptions

	http *http.Server
}

// NewAdmin validates o.
func NewAdmin(o AdminOptions) (*AdminServer, error) {
	switch {
	case o.Auth == nil:
		return nil, errors.New("api: the admin socket needs the auth service")
	case o.Hold == nil:
		return nil, errors.New("api: the admin socket needs the restore hold")
	case o.Doctor == nil:
		return nil, errors.New("api: the admin socket needs the doctor")
	case o.IDs == nil:
		return nil, errors.New("api: id generator is required")
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	a := &AdminServer{responder: responder{log: o.Log}, opts: o}
	mux := http.NewServeMux()
	for _, rt := range adminRoutes {
		mux.Handle(rt.Method+" "+rt.Pattern, a.guard(rt))
	}
	mux.Handle("/", a.guard(AdminRoute{}))
	a.http = &http.Server{
		Handler:           mux,
		ConnContext:       connContext,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       idleConnTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(o.Log.Handler(), slog.LevelWarn),
	}
	return a, nil
}

// AdminRoutes lists the routes the admin socket serves.
func AdminRoutes() []AdminRoute { return append([]AdminRoute(nil), adminRoutes...) }

// Serve answers requests on l, which must be restricted by peer UID, until
// Shutdown.
func (a *AdminServer) Serve(l net.Listener) error {
	if err := a.http.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve admin socket: %w", err)
	}
	return nil
}

// Shutdown stops accepting and waits for the requests in flight.
func (a *AdminServer) Shutdown(ctx context.Context) error { return a.http.Shutdown(ctx) }

func (a *AdminServer) guard(rt AdminRoute) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withCorrelation(r, a.opts.IDs.NewID())
		setCommonHeaders(w, r)
		defer func() {
			if recovered := recover(); recovered != nil {
				a.writeError(w, r, fmt.Errorf("panic serving %s %s: %v", r.Method, r.URL.Path, recovered))
			}
		}()
		uid, ok := verifiedPeer(r.Context())
		if !ok {
			a.writeError(w, r, smerr.New(smerr.CodeUnauthenticated, "", "peer credentials were not verified"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
		if err := a.dispatch(w, r, rt, int(uid)); err != nil {
			a.writeError(w, r, err)
		}
	})
}

func (a *AdminServer) dispatch(w http.ResponseWriter, r *http.Request, rt AdminRoute, uid int) error {
	if rt.Pattern == "" {
		return notFound(w, r)
	}
	ctx := r.Context()
	if rt.Action != "" {
		ctx = app.WithAction(ctx, rt.Action)
		if err := a.opts.Hold.Guard(ctx, rt.Action, app.Caller{Source: "admin_socket"}); err != nil {
			return err
		}
	}
	switch rt.Pattern {
	case wire.AdminPathBootstrapCode:
		issued, err := a.opts.Auth.IssueBootstrapCode(ctx, uid)
		return a.answer(w, r, http.StatusOK, issued, err)
	case wire.AdminPathGrant:
		in, err := readInput(r)
		if err != nil {
			return err
		}
		req, err := decode[wire.GrantRequest](in)
		if err != nil {
			return err
		}
		return a.answer(w, r, http.StatusOK, struct{}{}, a.opts.Auth.Grant(ctx, uid, req))
	case wire.AdminPathRestoreComplete:
		return a.answer(w, r, http.StatusOK, wire.RestoreCompleted{RestoreHold: false}, a.opts.Hold.Complete(ctx, uid))
	default:
		report, err := a.opts.Doctor(ctx)
		return a.answer(w, r, http.StatusOK, report, err)
	}
}

func (a *AdminServer) answer(w http.ResponseWriter, r *http.Request, status int, data any, err error) error {
	if err != nil {
		return err
	}
	a.writeData(w, r, status, data)
	return nil
}
