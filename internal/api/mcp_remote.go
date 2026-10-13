package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/mcp"
)

// MCPRemoteConfig is everything the remote MCP endpoint needs (ADR-0033).
type MCPRemoteConfig struct {
	// Resolver authenticates an OAuth access token (auth.OAuthResolver).
	Resolver Resolver
	// MCP serves an admitted request; it finds the caller with MCPCaller.
	MCP http.Handler
	// Resource is mcp.oauth.resource, "<origin>/mcp" (validated at config
	// load); the metadata URL of every challenge derives from it.
	Resource       string
	Issuer         string
	RequiredScopes []string
	// Proxy applies the trusted-proxy rules to find the requester's address.
	Proxy *Proxy
	Clock domain.Clock
	IDs   domain.IDGenerator
	Log   *slog.Logger
}

type mcpCallerKey struct{}

// MCPCaller is the identity NewMCPRemote admitted for r. It is set only after
// the token was verified and the identity found.
func MCPCaller(r *http.Request) (app.Caller, bool) {
	by, ok := r.Context().Value(mcpCallerKey{}).(app.Caller)
	return by, ok
}

// NewMCPRemote serves /mcp and both Protected Resource Metadata paths. Every
// request first draws on the per-address bucket, so a flood of bad tokens
// cannot reach token verification; an admitted /mcp request then draws on the
// caller's own bucket (ADR-0033, "Rate limits on /mcp").
func NewMCPRemote(cfg MCPRemoteConfig) http.Handler {
	remote := &mcpRemote{
		cfg:          cfg,
		responder:    responder{log: cfg.Log},
		metadataURL:  strings.TrimSuffix(cfg.Resource, wire.MCPPath) + wire.WellKnownProtectedResourceMCP,
		addressLimit: newLimiter(authRate, cfg.Clock.Now),
		callerLimit:  newLimiter(writeRate, cfg.Clock.Now),
		metadata:     mcp.ProtectedResourceMetadata(cfg.Resource, cfg.Issuer, cfg.RequiredScopes),
	}
	mux := http.NewServeMux()
	mux.Handle(wire.MCPPath, remote.admitted(remote.serveMCP))
	mux.Handle(wire.WellKnownProtectedResource, remote.admitted(remote.serveMetadata))
	mux.Handle(wire.WellKnownProtectedResourceMCP, remote.admitted(remote.serveMetadata))
	return mux
}

type mcpRemote struct {
	responder
	cfg          MCPRemoteConfig
	metadataURL  string
	addressLimit *limiter
	callerLimit  *limiter
	metadata     http.Handler
}

// admitted wraps next with the correlation id and the per-address bucket.
func (m *mcpRemote) admitted(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withCorrelation(r, m.cfg.IDs.NewID())
		client, err := m.cfg.Proxy.clientOf(r)
		if err != nil {
			m.writeError(w, r, err)
			return
		}
		if ok, after := m.addressLimit.allow(client.String()); !ok {
			m.writeError(w, r, &rateLimited{after: after})
			return
		}
		next(w, r)
	}
}

func (m *mcpRemote) serveMetadata(w http.ResponseWriter, r *http.Request) {
	m.metadata.ServeHTTP(w, r)
}

func (m *mcpRemote) serveMCP(w http.ResponseWriter, r *http.Request) {
	by, err := m.authenticate(r)
	if err != nil {
		m.refuse(w, r, err)
		return
	}
	if ok, after := m.callerLimit.allow(by.ID.String()); !ok {
		m.writeError(w, r, &rateLimited{after: after})
		return
	}
	m.cfg.MCP.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), mcpCallerKey{}, by)))
}

func (m *mcpRemote) authenticate(r *http.Request) (app.Caller, error) {
	token, err := bearerToken(r)
	if err != nil {
		return app.Caller{}, err
	}
	return m.cfg.Resolver.Resolve(r.Context(), token)
}

// refuse answers an authentication failure. Every 401 and a missing scope
// carry the challenge that names the metadata document (RFC 6750, RFC 9728).
func (m *mcpRemote) refuse(w http.ResponseWriter, r *http.Request, err error) {
	var typed *smerr.Error
	if errors.As(err, &typed) {
		switch {
		case typed.Code == smerr.CodeUnauthenticated:
			w.Header().Set("WWW-Authenticate", m.unauthenticatedChallenge())
		case typed.Reason == smerr.ReasonScopeDenied:
			w.Header().Set("WWW-Authenticate", m.insufficientScopeChallenge())
		}
	}
	m.writeError(w, r, err)
}

func (m *mcpRemote) unauthenticatedChallenge() string {
	return `Bearer resource_metadata="` + m.metadataURL + `", scope="` + m.scope() + `"`
}

func (m *mcpRemote) insufficientScopeChallenge() string {
	return `Bearer error="insufficient_scope", scope="` + m.scope() + `", resource_metadata="` + m.metadataURL + `"`
}

func (m *mcpRemote) scope() string { return strings.Join(m.cfg.RequiredScopes, " ") }
