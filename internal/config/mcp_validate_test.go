package config

import "testing"

// remoteMCP is a complete remote MCP configuration for the server base, whose
// public_url is https://mgmt.example.com.
func remoteMCP(c *Config) {
	c.MCP.RemoteEnabled = true
	c.MCP.OAuth = MCPOAuth{
		Issuer:         "https://idp.example.com",
		Resource:       "https://mgmt.example.com/mcp",
		JWKSURL:        "https://idp.example.com/jwks",
		RequiredScopes: []string{"supermgmt:mcp"},
	}
}

// wantMCPProblem validates c and checks that it is valid (wantPath "") or
// that one of its problems is at wantPath.
func wantMCPProblem(t *testing.T, c Config, wantPath string) {
	t.Helper()
	err := c.Validate()
	if wantPath == "" {
		if err != nil {
			t.Fatalf("want valid, got %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("want a problem at %s, got none", wantPath)
	}
	if paths := problemPaths(t, err); !contains(paths, wantPath) {
		t.Errorf("problem paths %v lack %s", paths, wantPath)
	}
}

func TestConfig_MCPResourceIdentity(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		resource  string
		wantPath  string
	}{
		{"origin followed by /mcp", "https://mgmt.example.com", "https://mgmt.example.com/mcp", ""},
		{"public_url with a root slash", "https://mgmt.example.com/", "https://mgmt.example.com/mcp", ""},
		{"origin with a port", "https://mgmt.example.com:8443", "https://mgmt.example.com:8443/mcp", ""},
		{"mismatched host", "https://mgmt.example.com", "https://other.example.com/mcp", "mcp.oauth.resource"},
		{"mismatched port", "https://mgmt.example.com", "https://mgmt.example.com:8443/mcp", "mcp.oauth.resource"},
		{"mismatched path", "https://mgmt.example.com", "https://mgmt.example.com/api/mcp", "mcp.oauth.resource"},
		{"bare origin as resource", "https://mgmt.example.com", "https://mgmt.example.com", "mcp.oauth.resource"},
		{"trailing slash", "https://mgmt.example.com", "https://mgmt.example.com/mcp/", "mcp.oauth.resource"},
		{"fragment", "https://mgmt.example.com", "https://mgmt.example.com/mcp#x", "mcp.oauth.resource"},
		{"empty fragment", "https://mgmt.example.com", "https://mgmt.example.com/mcp#", "mcp.oauth.resource"},
		{"query", "https://mgmt.example.com", "https://mgmt.example.com/mcp?a=1", "mcp.oauth.resource"},
		{"http resource", "https://mgmt.example.com", "http://mgmt.example.com/mcp", "mcp.oauth.resource"},
		{"http public_url", "http://mgmt.example.com", "http://mgmt.example.com/mcp", "server.public_url"},
		{"public_url with a path prefix", "https://mgmt.example.com/sm", "https://mgmt.example.com/sm/mcp", "server.public_url"},
		{"public_url with userinfo", "https://u:p@mgmt.example.com", "https://mgmt.example.com/mcp", "server.public_url"},
		{"public_url with a query", "https://mgmt.example.com?x=1", "https://mgmt.example.com/mcp", "server.public_url"},
		{"public_url with a fragment", "https://mgmt.example.com#x", "https://mgmt.example.com/mcp", "server.public_url"},
		{"public_url missing", "", "https://mgmt.example.com/mcp", "server.public_url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validServer(t)
			remoteMCP(&c)
			c.Server.PublicURL, c.MCP.OAuth.Resource = tt.publicURL, tt.resource
			wantMCPProblem(t, c, tt.wantPath)
		})
	}
}

func TestConfig_MCPRemoteRequirements(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(c *Config)
		wantPath string
	}{
		{"complete with jwks", func(*Config) {}, ""},
		{"complete with introspection", func(c *Config) {
			c.MCP.OAuth.JWKSURL = ""
			c.MCP.OAuth.IntrospectionURL = "https://idp.example.com/introspect"
			c.MCP.OAuth.IntrospectionClientID = "supermgmt"
			c.MCP.OAuth.IntrospectionClientSecretRef = "secret://mcp/introspection"
		}, ""},
		{"without oauth", func(c *Config) { c.MCP.OAuth = MCPOAuth{} }, "mcp.oauth.issuer"},
		{"without resource", func(c *Config) { c.MCP.OAuth.Resource = "" }, "mcp.oauth.resource"},
		{"without a token validation method", func(c *Config) { c.MCP.OAuth.JWKSURL = "" }, "mcp.oauth.jwks_url"},
		{"without scopes", func(c *Config) { c.MCP.OAuth.RequiredScopes = nil }, "mcp.oauth.required_scopes"},
		{"introspection without client id", func(c *Config) {
			c.MCP.OAuth.IntrospectionURL = "https://idp.example.com/introspect"
			c.MCP.OAuth.IntrospectionClientSecretRef = "secret://mcp/introspection"
		}, "mcp.oauth.introspection_client_id"},
		{"introspection without client secret", func(c *Config) {
			c.MCP.OAuth.IntrospectionURL = "https://idp.example.com/introspect"
			c.MCP.OAuth.IntrospectionClientID = "supermgmt"
		}, "mcp.oauth.introspection_client_secret_ref"},
		{"introspection secret inline", func(c *Config) {
			c.MCP.OAuth.IntrospectionURL = "https://idp.example.com/introspect"
			c.MCP.OAuth.IntrospectionClientID = "supermgmt"
			c.MCP.OAuth.IntrospectionClientSecretRef = "hunter2"
		}, "mcp.oauth.introspection_client_secret_ref"},
		{"introspection secret as file", func(c *Config) {
			c.MCP.OAuth.IntrospectionURL = "https://idp.example.com/introspect"
			c.MCP.OAuth.IntrospectionClientID = "supermgmt"
			c.MCP.OAuth.IntrospectionClientSecretRef = "file:///etc/supermgmt/introspection"
		}, "mcp.oauth.introspection_client_secret_ref"},
		{"issuer over http", func(c *Config) { c.MCP.OAuth.Issuer = "http://idp.example.com" }, "mcp.oauth.issuer"},
		{"jwks over http", func(c *Config) { c.MCP.OAuth.JWKSURL = "http://idp.example.com/jwks" }, "mcp.oauth.jwks_url"},
		{"introspection over http", func(c *Config) {
			c.MCP.OAuth.IntrospectionURL = "http://idp.example.com/introspect"
			c.MCP.OAuth.IntrospectionClientID = "supermgmt"
			c.MCP.OAuth.IntrospectionClientSecretRef = "secret://mcp/introspection"
		}, "mcp.oauth.introspection_url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validServer(t)
			remoteMCP(&c)
			tt.mutate(&c)
			wantMCPProblem(t, c, tt.wantPath)
		})
	}
}

func TestConfig_MCPRemoteNeedsServerMode(t *testing.T) {
	c := resolved(t, localDoc)
	remoteMCP(&c)
	wantMCPProblem(t, c, "mcp.remote_enabled")
}

func TestConfig_MCPOAuthMayStayIncompleteWhileRemoteIsOff(t *testing.T) {
	c := validServer(t)
	c.MCP.OAuth = MCPOAuth{Issuer: "http://not-checked", Resource: "anything"}
	wantMCPProblem(t, c, "")
}

func TestConfig_MCPIntrospectionSecretIsAlwaysASecretRef(t *testing.T) {
	c := resolved(t, localDoc)
	c.MCP.OAuth.IntrospectionClientSecretRef = "hunter2"
	wantMCPProblem(t, c, "mcp.oauth.introspection_client_secret_ref")
}

func TestConfig_MCPInteractiveExecIsRefused(t *testing.T) {
	for _, doc := range []string{localDoc, serverDoc} {
		c := resolved(t, doc)
		c.MCP.AllowInteractiveExec = true
		wantMCPProblem(t, c, "mcp.allow_interactive_exec")
	}
}
