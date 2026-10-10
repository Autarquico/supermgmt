package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// validServer is the spec §8.2 example resolved for server mode.
func validServer(t *testing.T) Config {
	t.Helper()
	return resolved(t, serverDoc+"server:\n  public_url: https://mgmt.example.com\n")
}

func resolved(t *testing.T, doc string) Config {
	t.Helper()
	cfg := Defaults()
	if err := DecodeStrict(strings.NewReader(doc), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.applyModeDefaults(Paths{DataDir: "/home/u/data"})
	return cfg
}

func problemPaths(t *testing.T, err error) []string {
	t.Helper()
	var problems Problems
	if !errors.As(err, &problems) {
		t.Fatalf("want Problems, got %v", err)
	}
	paths := make([]string, len(problems))
	for i, p := range problems {
		paths[i] = p.Path
	}
	return paths
}

func contains(paths []string, path string) bool {
	for _, p := range paths {
		if p == path {
			return true
		}
	}
	return false
}

func TestValidateBaseConfigsAreValid(t *testing.T) {
	server := validServer(t)
	if err := server.Validate(); err != nil {
		t.Errorf("server base: %v", err)
	}
	local := resolved(t, localDoc)
	if err := local.Validate(); err != nil {
		t.Errorf("local base: %v", err)
	}
}

func TestValidateRules(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(c *Config)
		wantPath string // "" means the config must be valid
	}{
		{"version 1 ok", func(c *Config) {}, ""},
		{"version 2", func(c *Config) { c.Version = 2 }, "version"},
		{"version 0", func(c *Config) { c.Version = 0 }, "version"},
		{"unknown mode", func(c *Config) { c.Instance.Mode = "cluster" }, "instance.mode"},
		{"empty mode", func(c *Config) { c.Instance.Mode = "" }, "instance.mode"},

		{"direct TLS with cert and key", func(c *Config) {
			c.Server.TLS = TLS{Mode: TLSDirect, CertFile: "/c.pem", KeyFile: "/k.pem"}
			c.Server.Listen = "0.0.0.0:8443"
		}, ""},
		{"direct TLS without cert", func(c *Config) { c.Server.TLS = TLS{Mode: TLSDirect, KeyFile: "/k.pem"} }, "server.tls.cert_file"},
		{"direct TLS without key", func(c *Config) { c.Server.TLS = TLS{Mode: TLSDirect, CertFile: "/c.pem"} }, "server.tls.key_file"},
		{"unknown TLS mode", func(c *Config) { c.Server.TLS.Mode = "off" }, "server.tls.mode"},
		{"proxy without trusted proxies", func(c *Config) { c.Server.TrustedProxies = nil }, "server.trusted_proxies"},
		{"proxy with garbage trusted proxy", func(c *Config) { c.Server.TrustedProxies = []string{"proxy.local"} }, "server.trusted_proxies[0]"},
		{"proxy with single IP", func(c *Config) { c.Server.TrustedProxies = []string{"10.1.2.3"} }, ""},
		{"proxy on non-loopback is plain HTTP", func(c *Config) { c.Server.Listen = "0.0.0.0:8787" }, "server.listen"},
		{"proxy on LAN address", func(c *Config) { c.Server.Listen = "192.168.1.5:8787" }, "server.listen"},
		{"proxy listen without port", func(c *Config) { c.Server.Listen = "127.0.0.1" }, "server.listen"},
		{"proxy on localhost", func(c *Config) { c.Server.Listen = "localhost:8787" }, ""},
		{"proxy on IPv6 loopback", func(c *Config) { c.Server.Listen = "[::1]:8787" }, ""},
		{"proxy on unix socket", func(c *Config) { c.Server.Listen = "unix:/run/supermgmt/api.sock" }, ""},
		{"server rules do not apply in local mode", func(c *Config) {
			c.Instance.Mode = ModeLocal
			c.Server.TrustedProxies = nil
			c.Server.Listen = "0.0.0.0:1"
		}, ""},

		{"reconcile_grace at the floor", func(c *Config) { c.Jobs.ReconcileGrace = 43 * time.Second }, ""},
		{"reconcile_grace below the floor", func(c *Config) { c.Jobs.ReconcileGrace = 42 * time.Second }, "jobs.reconcile_grace"},
		{"reconcile_grace follows ssh timeouts", func(c *Config) { c.SSH.CommandTimeout = 60 * time.Second }, "jobs.reconcile_grace"},

		{"zero duration", func(c *Config) { c.Refresh.MetricsInterval = 0 }, "refresh.metrics_interval"},
		{"negative duration", func(c *Config) { c.Security.SessionTTL = -time.Hour }, "security.session_ttl"},
		{"zero workers", func(c *Config) { c.Jobs.Workers = 0 }, "jobs.workers"},
		{"zero max connections", func(c *Config) { c.SSH.MaxConnections = 0 }, "ssh.max_connections"},
		{"host key policy other than strict", func(c *Config) { c.SSH.HostKeyPolicy = "accept-new" }, "ssh.host_key_policy"},
		{"logs mode broker", func(c *Config) { c.SSH.LogsMode = "broker" }, ""},
		{"logs mode unknown", func(c *Config) { c.SSH.LogsMode = "syslog" }, "ssh.logs_mode"},
		{"private CIDR list ok", func(c *Config) { c.Health.AllowedPrivateCIDRs = []string{"10.0.0.0/8"} }, ""},
		{"private CIDR list garbage", func(c *Config) { c.Health.AllowedPrivateCIDRs = []string{"10.0.0.0"} }, "health.allowed_private_cidrs[0]"},

		{"oidc client secret as secret ref", func(c *Config) { c.Auth.OIDC.ClientSecretRef = "secret://oidc/client" }, ""},
		{"oidc client secret as file ref", func(c *Config) { c.Auth.OIDC.ClientSecretRef = "file:///etc/oidc" }, "auth.oidc.client_secret_ref"},
		{"oidc client secret inline", func(c *Config) { c.Auth.OIDC.ClientSecretRef = "hunter2" }, "auth.oidc.client_secret_ref"},

		{"remote MCP without oauth", func(c *Config) { c.MCP.RemoteEnabled = true }, "mcp.oauth.issuer"},
		{"remote MCP with jwks", func(c *Config) { c.MCP.RemoteEnabled = true; c.MCP.OAuth = completeOAuth() }, ""},
		{"remote MCP with introspection instead of jwks", func(c *Config) {
			c.MCP.RemoteEnabled = true
			c.MCP.OAuth = completeOAuth()
			c.MCP.OAuth.JWKSURL, c.MCP.OAuth.IntrospectionURL = "", "https://idp/introspect"
		}, ""},
		{"remote MCP missing key source", func(c *Config) {
			c.MCP.RemoteEnabled = true
			c.MCP.OAuth = completeOAuth()
			c.MCP.OAuth.JWKSURL = ""
		}, "mcp.oauth.jwks_url"},
		{"remote MCP missing scopes", func(c *Config) {
			c.MCP.RemoteEnabled = true
			c.MCP.OAuth = completeOAuth()
			c.MCP.OAuth.RequiredScopes = nil
		}, "mcp.oauth.required_scopes"},
		{"incomplete oauth is fine while remote is off", func(c *Config) { c.MCP.OAuth.Issuer = "" }, ""},

		{"environment ok", func(c *Config) { c.Environments = []Environment{env("production", "production", 1)} }, ""},
		{"environment quorum 5", func(c *Config) { c.Environments = []Environment{env("p", "production", 5)} }, ""},
		{"environment quorum 0", func(c *Config) { c.Environments = []Environment{env("p", "production", 0)} }, "environments[0].approvals_required"},
		{"environment quorum 6", func(c *Config) { c.Environments = []Environment{env("p", "production", 6)} }, "environments[0].approvals_required"},
		{"environment bad risk", func(c *Config) { c.Environments = []Environment{env("p", "critical", 1)} }, "environments[0].risk_level"},
		{"environment nameless", func(c *Config) { c.Environments = []Environment{env("", "staging", 1)} }, "environments[0].name"},
		{"environment duplicate", func(c *Config) {
			c.Environments = []Environment{env("p", "staging", 1), env("p", "production", 1)}
		}, "environments[1].name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validServer(t)
			tt.mutate(&c)
			err := c.Validate()
			if tt.wantPath == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want a problem at %s, got none", tt.wantPath)
			}
			if paths := problemPaths(t, err); !contains(paths, tt.wantPath) {
				t.Errorf("problem paths %v lack %s", paths, tt.wantPath)
			}
		})
	}
}

func completeOAuth() MCPOAuth {
	return MCPOAuth{
		Issuer: "https://idp", Resource: "https://mgmt.example.com/mcp",
		JWKSURL: "https://idp/jwks", RequiredScopes: []string{"supermgmt:mcp"},
	}
}

func env(name, risk string, approvals int) Environment {
	return Environment{Name: name, RiskLevel: risk, ApprovalsRequired: approvals}
}

func TestValidateCredentialRefs(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		ref  string
		ok   bool
	}{
		{"secret in server", ModeServer, "secret://ssh/default", true},
		{"secret in local", ModeLocal, "secret://ssh/default", true},
		{"secret without path", ModeLocal, "secret://", false},
		{"agent in local", ModeLocal, "ssh-agent://default", true},
		{"agent in server", ModeServer, "ssh-agent://default", false},
		{"agent with other name", ModeLocal, "ssh-agent://other", false},
		{"absolute file", ModeServer, "file:///etc/supermgmt/id_ed25519", true},
		{"relative file", ModeServer, "file://keys/id", false},
		{"unknown scheme", ModeLocal, "vault://kv/key", false},
		{"http scheme", ModeLocal, "https://example.com/token", false},
		{"bare string", ModeLocal, "hunter2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, field := range []string{"credential_ref", "admin_credential_ref"} {
				c := resolved(t, "version: 1\ninstance:\n  mode: "+string(tt.mode)+"\n")
				ssh := &SSHProvider{
					Type: "ssh", Name: "n", CredentialRef: DefaultSSHCredentialRef,
					Endpoint: SSHEndpoint{Host: "h", Port: 22, User: "u", AdminUser: "admin"},
				}
				if field == "credential_ref" {
					ssh.CredentialRef = tt.ref
				} else {
					ssh.AdminCredentialRef = tt.ref
				}
				c.Providers = []Provider{{SSH: ssh}}
				err := c.Validate()
				if tt.ok && err != nil {
					t.Errorf("%s: want valid, got %v", field, err)
				}
				if !tt.ok {
					if err == nil {
						t.Fatalf("%s: want a problem, got none", field)
					}
					if paths := problemPaths(t, err); !contains(paths, "providers[0]."+field) {
						t.Errorf("problem paths %v lack providers[0].%s", paths, field)
					}
				}
			}
		})
	}
}

func TestValidateProviders(t *testing.T) {
	good := func() Config {
		c := validServer(t)
		c.Providers = []Provider{
			{Proxmox: &ProxmoxProvider{Type: "proxmox", Name: "pve", Endpoint: "https://pve:8006", CredentialRef: "secret://providers/pve", VerifyTLS: true, SyncInterval: 30 * time.Second}},
			{SSH: &SSHProvider{Type: "ssh", Name: "n1", CredentialRef: "secret://ssh/default", Endpoint: SSHEndpoint{Host: "h", Port: 22, User: "u", AdminUser: "admin"}}},
		}
		return c
	}
	tests := []struct {
		name     string
		mutate   func(c *Config)
		wantPath string
	}{
		{"good providers", func(c *Config) {}, ""},
		{"proxmox token must be a secret ref", func(c *Config) { c.Providers[0].Proxmox.CredentialRef = "file:///tok" }, "providers[0].credential_ref"},
		{"proxmox without credential", func(c *Config) { c.Providers[0].Proxmox.CredentialRef = "" }, "providers[0].credential_ref"},
		{"proxmox without endpoint", func(c *Config) { c.Providers[0].Proxmox.Endpoint = "" }, "providers[0].endpoint"},
		{"proxmox zero sync interval", func(c *Config) { c.Providers[0].Proxmox.SyncInterval = 0 }, "providers[0].sync_interval"},
		{"ssh without host", func(c *Config) { c.Providers[1].SSH.Endpoint.Host = "" }, "providers[1].endpoint.host"},
		{"ssh without user", func(c *Config) { c.Providers[1].SSH.Endpoint.User = "" }, "providers[1].endpoint.user"},
		{"ssh without admin user", func(c *Config) { c.Providers[1].SSH.Endpoint.AdminUser = "" }, "providers[1].endpoint.admin_user"},
		{"ssh user outside the allowlist", func(c *Config) { c.Providers[1].SSH.Endpoint.User = "-oProxyCommand=x" }, "providers[1].endpoint.user"},
		{"ssh admin user outside the allowlist", func(c *Config) { c.Providers[1].SSH.Endpoint.AdminUser = "Alex Smith" }, "providers[1].endpoint.admin_user"},
		{"ssh port out of range", func(c *Config) { c.Providers[1].SSH.Endpoint.Port = 70000 }, "providers[1].endpoint.port"},
		{"nameless provider", func(c *Config) { c.Providers[1].SSH.Name = "" }, "providers[1].name"},
		{"duplicate provider name", func(c *Config) { c.Providers[1].SSH.Name = "pve" }, "providers[1].name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := good()
			tt.mutate(&c)
			err := c.Validate()
			if tt.wantPath == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want a problem at %s", tt.wantPath)
			}
			if paths := problemPaths(t, err); !contains(paths, tt.wantPath) {
				t.Errorf("problem paths %v lack %s", paths, tt.wantPath)
			}
		})
	}
}

func TestValidateReportsAllProblemsAtOnce(t *testing.T) {
	c := validServer(t)
	c.Version = 3
	c.Server.TrustedProxies = nil
	c.Jobs.Workers = 0
	c.Environments = []Environment{env("p", "x", 9)}
	paths := problemPaths(t, c.Validate())
	for _, want := range []string{"version", "server.trusted_proxies", "jobs.workers", "environments[0].risk_level", "environments[0].approvals_required"} {
		if !contains(paths, want) {
			t.Errorf("problem paths %v lack %s", paths, want)
		}
	}
}

func TestValidateNeverEchoesCredentialRefValues(t *testing.T) {
	for _, ref := range []string{"hunter2-plaintext", "pa ss://word", "Hunter2-Plain://x"} {
		c := validServer(t)
		c.Auth.OIDC.ClientSecretRef = ref
		c.Providers = []Provider{{SSH: &SSHProvider{
			Type: "ssh", Name: "n", CredentialRef: ref,
			Endpoint: SSHEndpoint{Host: "h", Port: 22, User: "u", AdminUser: "admin"},
		}}}

		err := c.Validate()

		if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "pa ss") || strings.Contains(err.Error(), "Plain") {
			t.Errorf("ref %q: error %v must reject without echoing the value", ref, err)
		}
	}
	c := validServer(t)
	c.Auth.OIDC.ClientSecretRef = "hunter2-plaintext"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "missing a scheme") {
		t.Errorf("err = %v, want a missing-scheme message", err)
	}
}
