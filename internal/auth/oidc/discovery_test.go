package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func newClient(t *testing.T, p *idp, mutate ...func(*Config)) *Client {
	t.Helper()
	cl, err := tryNewClient(p, mutate...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cl
}

func tryNewClient(p *idp, mutate ...func(*Config)) (*Client, error) {
	cfg := p.config()
	for _, m := range mutate {
		m(&cfg)
	}
	return New(context.Background(), cfg)
}

func TestDiscoveryAcceptsEndpointsOnTheIssuerOrigin(t *testing.T) {
	p := newIdP(t, newClock())
	newClient(t, p)
}

func TestDiscoveryRefusals(t *testing.T) {
	tests := []struct {
		name    string
		doc     map[string]any
		mutate  func(*Config)
		mention string
	}{
		{"issuer differs", map[string]any{"issuer": "https://10.0.0.6"}, nil, "issuer"},
		{"issuer differs by a trailing slash", map[string]any{"issuer": issuerURL + "/"}, nil, "issuer"},
		{"issuer in config is http", nil, func(c *Config) { c.Issuer = "http://10.0.0.5" }, "https"},
		{"issuer carries userinfo", nil, func(c *Config) { c.Issuer = "https://u:p@10.0.0.5" }, "userinfo"},
		{"authorization endpoint on a foreign origin", map[string]any{"authorization_endpoint": foreignURL + "/auth"}, nil, "authorization_endpoint"},
		{"token endpoint on a foreign origin", map[string]any{"token_endpoint": foreignURL + "/token"}, nil, "token_endpoint"},
		{"jwks on a foreign origin", map[string]any{"jwks_uri": foreignURL + "/jwks"}, nil, "jwks_uri"},
		{"device endpoint on a foreign origin", map[string]any{"device_authorization_endpoint": foreignURL + "/device/code"}, nil, "device_authorization_endpoint"},
		{"same host, other port", map[string]any{"token_endpoint": "https://10.0.0.5:8443/token"}, nil, "token_endpoint"},
		{"token endpoint over http", map[string]any{"token_endpoint": "http://10.0.0.5/token"}, nil, "token_endpoint"},
		{"jwks over http even when listed", map[string]any{"jwks_uri": "http://10.0.0.6/jwks"}, func(c *Config) { c.AllowedEndpointOrigins = []string{"http://10.0.0.6"} }, "allowed_endpoint_origins"},
		{"authorization endpoint over http", map[string]any{"authorization_endpoint": "http://10.0.0.5/auth"}, nil, "authorization_endpoint"},
		{"endpoint with userinfo", map[string]any{"token_endpoint": "https://u:p@10.0.0.5/token"}, nil, "token_endpoint"},
		{"endpoint missing", map[string]any{"token_endpoint": ""}, nil, "token_endpoint"},
		{"jwks missing", map[string]any{"jwks_uri": ""}, nil, "jwks_uri"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newIdP(t, newClock())
			for k, v := range tt.doc {
				p.setDoc(k, v)
			}
			var mutate []func(*Config)
			if tt.mutate != nil {
				mutate = append(mutate, tt.mutate)
			}
			_, err := tryNewClient(p, mutate...)
			if err == nil || !strings.Contains(err.Error(), tt.mention) {
				t.Fatalf("New error = %v, want one mentioning %q", err, tt.mention)
			}
		})
	}
}

func TestDiscoveryAcceptsListedForeignOrigins(t *testing.T) {
	tests := []struct {
		name   string
		listed string
	}{
		{"exact", "https://10.0.0.6"},
		{"explicit default port", "https://10.0.0.6:443"},
		{"trailing slash", "https://10.0.0.6/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newIdP(t, newClock())
			p.setDoc("jwks_uri", foreignURL+"/jwks")
			p.setDoc("token_endpoint", foreignURL+"/token")
			newClient(t, p, func(c *Config) { c.AllowedEndpointOrigins = []string{tt.listed} })
		})
	}
}

func TestMalformedAllowedOriginIsAConfigurationError(t *testing.T) {
	p := newIdP(t, newClock())
	for _, bad := range []string{"http://10.0.0.6", "10.0.0.6", "https://"} {
		if _, err := tryNewClient(p, func(c *Config) { c.AllowedEndpointOrigins = []string{bad} }); err == nil {
			t.Errorf("allowed origin %q accepted", bad)
		}
	}
}

func TestDiscoveryDoesNotFollowRedirects(t *testing.T) {
	p := newIdP(t, newClock())
	_, err := tryNewClient(p, func(c *Config) { c.Issuer = issuerURL + "/moved" })
	if err == nil {
		t.Fatal("a redirected discovery document was accepted")
	}
	if got := p.hitCount("/.well-known/openid-configuration"); got != 0 {
		t.Fatalf("the redirect target was fetched %d times", got)
	}
}

func TestTokenEndpointRedirectIsNotFollowed(t *testing.T) {
	p := newIdP(t, newClock())
	p.setDoc("token_endpoint", issuerURL+"/moved/.well-known/openid-configuration")
	cl := newClient(t, p)
	_, err := codeLogin(t, cl, p)
	if err == nil {
		t.Fatal("exchange followed a redirect")
	}
	if got := p.hitCount("/.well-known/openid-configuration"); got != 1 { // the discovery fetch only
		t.Fatalf("the redirect target was fetched %d times", got)
	}
}

func TestListedMetadataOriginIsStillRefusedByTheNetworkFilter(t *testing.T) {
	p := newIdP(t, newClock())
	p.setDoc("token_endpoint", "https://169.254.169.254/token")
	cl := newClient(t, p, func(c *Config) { c.AllowedEndpointOrigins = []string{"https://169.254.169.254"} })

	_, err := codeLogin(t, cl, p)
	if err == nil || !strings.Contains(err.Error(), "netguard") {
		t.Fatalf("exchange with a metadata token endpoint = %v, want a netguard refusal", err)
	}
	var e *smerr.Error
	if !errors.As(err, &e) || e.Code != smerr.CodeProviderError {
		t.Fatalf("error = %v, want PROVIDER_ERROR", err)
	}
}

func TestUserinfoEndpointIsNeverCalled(t *testing.T) {
	p := newIdP(t, newClock())
	cl := newClient(t, p)
	if _, err := codeLogin(t, cl, p); err != nil {
		t.Fatal(err)
	}
	if got := p.hitCount("/userinfo"); got != 0 {
		t.Fatalf("userinfo was called %d times", got)
	}
}
