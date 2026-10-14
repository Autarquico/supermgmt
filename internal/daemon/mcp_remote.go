package daemon

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/mcp"
	"github.com/autarquico/supermgmt/internal/netguard"
)

// remoteProtocolVersions are the MCP versions served over HTTP (ADR-0031).
var remoteProtocolVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18"}

// mcpMount is what the HTTPS server mounts for remote MCP: the handler and
// the paths it owns.
type mcpMount struct {
	handler http.Handler
	paths   []string
}

// remoteMCP builds /mcp and the protected resource metadata. Without remote
// MCP it returns nil: local mode and servers that leave it off never mount
// them. It refuses to start on an OAuth section it cannot serve. The tools
// reach the API in process, through server, which exists only after this
// handler does.
func (b *builder) remoteMCP(ctx context.Context, server func() *api.Server, proxy *api.Proxy) (*mcpMount, error) {
	if !b.mcpRemoteOn() {
		if b.cfg.MCP.RemoteEnabled {
			b.o.Log.Warn("mcp.remote_enabled is set but mcp.enabled is false: /mcp is not served")
		}
		return nil, nil
	}
	resolver, err := b.oauthResolver(ctx)
	if err != nil {
		return nil, err
	}
	origin, err := publicOrigin(b.cfg.Server.PublicURL)
	if err != nil {
		return nil, err
	}
	o := b.cfg.MCP.OAuth
	tools := mcp.NewHTTPHandler(
		serversFor(mcp.NewServer, mcp.Options{WriteTools: b.cfg.MCP.WriteToolsEnabled, Version: b.o.SMVersion, Log: b.o.Log}, inProcessAPI(server)),
		mcp.HTTPOptions{AllowedOrigin: origin, ProtocolVersions: remoteProtocolVersions},
	)
	handler := api.NewMCPRemote(api.MCPRemoteConfig{
		Resolver: resolver, MCP: tools, Resource: o.Resource, Issuer: o.Issuer, RequiredScopes: o.RequiredScopes,
		Proxy: proxy, Clock: b.o.Clock, IDs: b.o.IDs, Log: b.o.Log,
	})
	return &mcpMount{handler: handler, paths: []string{wire.MCPPath, wire.WellKnownProtectedResource, wire.WellKnownProtectedResourceMCP}}, nil
}

// publicOrigin is scheme://host of server.public_url, the only Origin /mcp accepts.
func publicOrigin(publicURL string) (string, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("server.public_url %q is not an absolute URL", publicURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// oauthResolver verifies access tokens against the configured authorization
// server. Its JWKS and introspection calls are provider endpoints (spec
// §21.1): filtered by netguard, https only, no redirects.
func (b *builder) oauthResolver(ctx context.Context) (*auth.OAuthResolver, error) {
	o := b.cfg.MCP.OAuth
	cfg := auth.OAuthConfig{
		Issuer: o.Issuer, Resource: o.Resource, JWKSURL: o.JWKSURL, IntrospectionURL: o.IntrospectionURL,
		ClientID: o.IntrospectionClientID, RequiredScopes: o.RequiredScopes, Clock: b.o.Clock,
	}
	if o.IntrospectionURL != "" {
		ref, err := parseSecretRef(o.IntrospectionClientSecretRef)
		if err != nil {
			return nil, fmt.Errorf("mcp.oauth.introspection_client_secret_ref: %w", err)
		}
		if cfg.ClientSecret, err = b.kit.store.Get(ctx, ref); err != nil {
			return nil, fmt.Errorf("refusing to start remote MCP: read the introspection client secret %s: %w", ref, err)
		}
	}
	var err error
	if cfg.HTTP, err = b.oauthHTTPClient(); err != nil {
		return nil, err
	}
	resolver, err := auth.NewOAuthResolver(ctx, cfg, b.db)
	if err != nil {
		return nil, fmt.Errorf("refusing to start remote MCP: %w", err)
	}
	return resolver, nil
}

func (b *builder) oauthHTTPClient() (*http.Client, error) {
	if b.oauthHTTP != nil {
		return b.oauthHTTP, nil
	}
	proxy, err := outboundProxy(b.cfg.Outbound.Proxy)
	if err != nil {
		return nil, err
	}
	return netguard.NewClient(netguard.Allow{AllowAllPrivate: true}, proxy, idpTimeout, idpMaxBody), nil
}

// serversFor binds newServer to the API of the request's caller: one MCP
// server per request, whose tools call the API in process as that caller, so
// policy, audit and rate limits are the API's. A request without an admitted
// caller gets no server. The server type stays a parameter so this package
// never names the MCP SDK.
func serversFor[S any](newServer func(mcp.API, mcp.Options) S, o mcp.Options, apiOf func(*http.Request) (mcp.API, bool)) func(*http.Request) S {
	return func(r *http.Request) S {
		caller, ok := apiOf(r)
		if !ok {
			var none S
			return none
		}
		return newServer(caller, o)
	}
}

func inProcessAPI(server func() *api.Server) func(*http.Request) (mcp.API, bool) {
	return func(r *http.Request) (mcp.API, bool) {
		by, ok := api.MCPCaller(r)
		if !ok {
			return nil, false
		}
		return client.New(client.Options{Transport: server().InProcess(by)}), true
	}
}
