package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	approvalsMin = 1
	approvalsMax = 5
	// reconcileMargin is the slack jobs.reconcile_grace must leave above one
	// SSH connect plus one SSH command (spec §8.2).
	reconcileMargin = 5 * time.Second
	// killAfter is the grace `timeout --kill-after` gives a mutating remote
	// command after its deadline (spec §20.4, ADR-0015). A remote process of
	// ours is gone once deadline + killAfter + connect_timeout has passed, and
	// quiescence waits for jobs.reconcile_grace after the deadline.
	killAfter = 10 * time.Second
)

// Validate reports every problem in c at once, each located by YAML path.
func (c *Config) Validate() error {
	v := &validator{cfg: c}
	v.version()
	v.instance()
	v.server()
	v.positiveDurations()
	v.positiveInts()
	v.ssh()
	v.jobs()
	v.cidrs("health.allowed_private_cidrs", c.Health.AllowedPrivateCIDRs)
	v.oidc()
	v.mcp()
	v.cloudflare()
	v.environments()
	v.providers()
	if len(v.problems) == 0 {
		return nil
	}
	return invalid("invalid configuration", v.problems)
}

type validator struct {
	cfg      *Config
	problems Problems
}

func (v *validator) add(path, format string, args ...any) {
	v.problems = append(v.problems, Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}

func (v *validator) version() {
	if v.cfg.Version != 1 {
		v.add("version", "must be 1, got %d", v.cfg.Version)
	}
}

func (v *validator) instance() {
	if m := v.cfg.Instance.Mode; m != ModeLocal && m != ModeServer {
		v.add("instance.mode", "must be local or server, got %q", m)
	}
}

func (v *validator) server() {
	if v.cfg.Instance.Mode != ModeServer {
		return
	}
	s := v.cfg.Server
	switch s.TLS.Mode {
	case TLSDirect:
		if s.TLS.CertFile == "" {
			v.add("server.tls.cert_file", "required when server.tls.mode is direct")
		}
		if s.TLS.KeyFile == "" {
			v.add("server.tls.key_file", "required when server.tls.mode is direct")
		}
	case TLSProxy:
		v.proxyTLS(s)
	default:
		v.add("server.tls.mode", "must be direct or proxy, got %q", s.TLS.Mode)
	}
}

// proxyTLS covers the proxy rules, including the refusal of plain HTTP on a
// non-loopback listener: behind a proxy the daemon speaks plain HTTP, so it
// may only bind loopback or a unix socket.
func (v *validator) proxyTLS(s Server) {
	if len(s.TrustedProxies) == 0 {
		v.add("server.trusted_proxies", "must be non-empty when server.tls.mode is proxy")
	}
	for i, p := range s.TrustedProxies {
		if !validIPOrCIDR(p) {
			v.add(fmt.Sprintf("server.trusted_proxies[%d]", i), "not an IP address or CIDR: %q", p)
		}
	}
	if !loopbackOrUnix(s.Listen) {
		v.add("server.listen", "plain HTTP behind a proxy must listen on loopback or a unix socket, got %q", s.Listen)
	}
}

// loopbackOrUnix accepts "unix:<path>", an absolute socket path, or a
// host:port whose host is localhost or a loopback IP.
func loopbackOrUnix(listen string) bool {
	if strings.HasPrefix(listen, "unix:") || strings.HasPrefix(listen, "/") {
		return true
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func validIPOrCIDR(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func (v *validator) cidrs(yamlPath string, values []string) {
	for i, s := range values {
		if _, err := netip.ParsePrefix(s); err != nil {
			v.add(fmt.Sprintf("%s[%d]", yamlPath, i), "not a CIDR: %q", s)
		}
	}
}

// positiveDurations requires every duration in the config to be > 0.
func (v *validator) positiveDurations() {
	walkLeaves(reflect.ValueOf(v.cfg).Elem(), "", func(yamlPath string, f reflect.Value) {
		if d, ok := f.Interface().(time.Duration); ok && d <= 0 {
			v.add(yamlPath, "must be a positive duration, got %s", d)
		}
	})
}

func (v *validator) positiveInts() {
	for _, f := range []struct {
		path  string
		value int
	}{
		{"ssh.max_dials_in_flight", v.cfg.SSH.MaxDialsInFlight},
		{"ssh.max_connections", v.cfg.SSH.MaxConnections},
		{"ssh.max_sessions_per_connection", v.cfg.SSH.MaxSessionsPerConnection},
		{"jobs.workers", v.cfg.Jobs.Workers},
	} {
		if f.value <= 0 {
			v.add(f.path, "must be positive, got %d", f.value)
		}
	}
}

func (v *validator) ssh() {
	s := v.cfg.SSH
	if s.HostKeyPolicy != "strict" {
		v.add("ssh.host_key_policy", "must be strict, got %q", s.HostKeyPolicy)
	}
	if s.LogsMode != "journal-group" && s.LogsMode != "broker" {
		v.add("ssh.logs_mode", "must be journal-group or broker, got %q", s.LogsMode)
	}
}

func (v *validator) jobs() {
	ssh := v.cfg.SSH
	floor := max(ssh.ConnectTimeout+ssh.CommandTimeout+reconcileMargin, killAfter+ssh.ConnectTimeout)
	if got := v.cfg.Jobs.ReconcileGrace; got < floor {
		v.add("jobs.reconcile_grace",
			"must be at least ssh.connect_timeout + ssh.command_timeout + 5s and at least the 10s kill-after + ssh.connect_timeout (%s), got %s", floor, got)
	}
}

func (v *validator) oidc() {
	o := v.cfg.Auth.OIDC
	if o.ClientSecretRef != "" {
		v.secretRefOnly("auth.oidc.client_secret_ref", o.ClientSecretRef)
	}
	for i, origin := range o.AllowedEndpointOrigins {
		if !httpsOrigin(origin) {
			v.add(fmt.Sprintf("auth.oidc.allowed_endpoint_origins[%d]", i), "must be an https origin (scheme and host, no path), got %q", origin)
		}
	}
	if !o.Enabled {
		return
	}
	if o.Issuer == "" || !httpsURL(o.Issuer) {
		v.add("auth.oidc.issuer", "must be an https URL when auth.oidc.enabled is true, got %q", o.Issuer)
	}
	if o.ClientID == "" {
		v.add("auth.oidc.client_id", "required when auth.oidc.enabled is true")
	}
	if o.ClientSecretRef == "" {
		v.add("auth.oidc.client_secret_ref", "required when auth.oidc.enabled is true")
	}
}

// httpsURL accepts an absolute https URL with a host and no userinfo.
func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// httpsOrigin accepts exactly scheme://host[:port], as browsers define an origin.
func httpsOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && httpsURL(raw) && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !strings.HasSuffix(raw, "/")
}

// mcpResourcePath is where remote MCP is served; its OAuth resource is
// server.public_url's origin followed by this path (ADR-0033).
const mcpResourcePath = "/mcp"

func (v *validator) mcp() {
	m := v.cfg.MCP
	if m.AllowInteractiveExec {
		v.add("mcp.allow_interactive_exec", "true is not supported in this version: no MCP tool runs commands")
	}
	if m.OAuth.IntrospectionClientSecretRef != "" {
		v.secretRefOnly("mcp.oauth.introspection_client_secret_ref", m.OAuth.IntrospectionClientSecretRef)
	}
	if !m.RemoteEnabled {
		return
	}
	if v.cfg.Instance.Mode != ModeServer {
		v.add("mcp.remote_enabled", "requires instance.mode server, got %q", v.cfg.Instance.Mode)
	}
	v.mcpOAuthComplete(m.OAuth)
	v.mcpOAuthEndpoints(m.OAuth)
	if m.OAuth.Resource != "" {
		v.mcpResource(v.cfg.Server.PublicURL, m.OAuth.Resource)
	}
}

func (v *validator) mcpOAuthComplete(o MCPOAuth) {
	need := func(yamlPath string, ok bool, what string) {
		if !ok {
			v.add(yamlPath, "%s (mcp.remote_enabled requires complete mcp.oauth)", what)
		}
	}
	need("mcp.oauth.issuer", o.Issuer != "", "required")
	need("mcp.oauth.resource", o.Resource != "", "required")
	need("mcp.oauth.jwks_url", o.JWKSURL != "" || o.IntrospectionURL != "", "jwks_url or introspection_url required")
	need("mcp.oauth.required_scopes", len(o.RequiredScopes) > 0, "must be non-empty")
	if o.IntrospectionURL != "" {
		need("mcp.oauth.introspection_client_id", o.IntrospectionClientID != "", "required with introspection_url")
		need("mcp.oauth.introspection_client_secret_ref", o.IntrospectionClientSecretRef != "", "required with introspection_url")
	}
}

// mcpOAuthEndpoints requires https for the issuer and for every endpoint
// SuperMgmt calls (§21.1 provider endpoints).
func (v *validator) mcpOAuthEndpoints(o MCPOAuth) {
	for _, f := range []struct{ path, value string }{
		{"mcp.oauth.issuer", o.Issuer},
		{"mcp.oauth.jwks_url", o.JWKSURL},
		{"mcp.oauth.introspection_url", o.IntrospectionURL},
	} {
		if f.value != "" && !httpsURL(f.value) {
			v.add(f.path, "must be an https URL, got %q", f.value)
		}
	}
}

// mcpResource enforces the resource identity of ADR-0033: server.public_url
// is a bare https origin (prefix-mounted proxies are not supported) and the
// resource is byte-equal to that origin followed by /mcp, so tokens are bound
// to the MCP endpoint and nothing else (RFC 8707 §2, RFC 9728 §3.3).
func (v *validator) mcpResource(publicURL, resource string) {
	origin, ok := bareHTTPSOrigin(publicURL)
	if !ok {
		v.add("server.public_url", "must be an https URL with no path, query, fragment or userinfo when mcp.remote_enabled is true, got %q", publicURL)
		return
	}
	if want := origin + mcpResourcePath; resource != want {
		v.add("mcp.oauth.resource", "must be exactly %q (server.public_url's origin followed by %s), got %q", want, mcpResourcePath, resource)
	}
}

// bareHTTPSOrigin returns scheme://host[:port] of an https URL whose path is
// empty or "/" and that has no query, fragment or userinfo.
func bareHTTPSOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || !httpsURL(raw) || strings.ContainsAny(raw, "?#") || (u.Path != "" && u.Path != "/") {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

func (v *validator) environments() {
	names := map[string]bool{}
	for i, e := range v.cfg.Environments {
		at := func(field string) string { return fmt.Sprintf("environments[%d].%s", i, field) }
		switch {
		case e.Name == "":
			v.add(at("name"), "required")
		case names[e.Name]:
			v.add(at("name"), "duplicate environment %q", e.Name)
		}
		names[e.Name] = true
		if _, err := domain.ParseEnvironmentRiskLevel(e.RiskLevel); err != nil {
			v.add(at("risk_level"), "must be development, staging or production, got %q", e.RiskLevel)
		}
		if e.ApprovalsRequired < approvalsMin || e.ApprovalsRequired > approvalsMax {
			v.add(at("approvals_required"), "must be between %d and %d, got %d", approvalsMin, approvalsMax, e.ApprovalsRequired)
		}
	}
}

func (v *validator) providers() {
	names := map[string]bool{}
	for i, p := range v.cfg.Providers {
		at := func(field string) string { return fmt.Sprintf("providers[%d].%s", i, field) }
		if p.Name() == "" {
			v.add(at("name"), "required")
		} else if names[p.Name()] {
			v.add(at("name"), "duplicate provider %q", p.Name())
		}
		names[p.Name()] = true
		switch {
		case p.GitHub != nil:
			v.githubProvider(*p.GitHub, at)
		case p.Proxmox != nil:
			v.proxmox(*p.Proxmox, at)
		case p.SSH != nil:
			v.sshProvider(*p.SSH, at)
		}
	}
}

// nodeNamePattern is a hostname-shaped node name (letters, digits, inner
// hyphens), the same shape the Proxmox client accepts in API paths.
var nodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

var hostLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// tlsServerName accepts an IP literal or a lowercase host name of one or more
// labels: a certificate behind a relay names localhost or the bare hostname.
func tlsServerName(name string) bool {
	if net.ParseIP(name) != nil {
		return true
	}
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// proxmox checks a Proxmox provider (spec §8.3, ADR-0024): exactly one of an
// https origin or a via_node, verified TLS (a private CA goes in ca_file), a
// secret:// token reference (optional with via_node, where node setup records
// it). Whether via_node names an existing node is resolved at sync time.
func (v *validator) proxmox(p ProxmoxProvider, at func(string) string) {
	switch {
	case p.Endpoint != "" && p.ViaNode != "":
		v.add(at("via_node"), "exactly one of endpoint and via_node may be set")
	case p.Endpoint == "" && p.ViaNode == "":
		v.add(at("endpoint"), "required unless via_node is set")
	case p.ViaNode != "" && !nodeNamePattern.MatchString(p.ViaNode):
		v.add(at("via_node"), "must be a node name (letters, digits and inner hyphens), got %q", p.ViaNode)
	case p.Endpoint != "" && !httpsOrigin(p.Endpoint):
		v.add(at("endpoint"), "must be an https URL with only a host and port, e.g. https://pve.lan:8006, got %q", p.Endpoint)
	}
	if p.TLSServerName != "" && !tlsServerName(p.TLSServerName) {
		v.add(at("tls_server_name"), "must be a lowercase host name or an IP address, got %q", p.TLSServerName)
	}
	if !p.VerifyTLS {
		v.add(at("verify_tls"), "must be true; trust a private CA with ca_file instead")
	}
	if p.CAFile != "" && !path.IsAbs(p.CAFile) {
		v.add(at("ca_file"), "must be an absolute path, got %q", p.CAFile)
	}
	if p.CredentialRef != "" {
		v.secretRefOnly(at("credential_ref"), p.CredentialRef)
	} else if p.ViaNode == "" {
		v.add(at("credential_ref"), "required")
	}
	if p.SyncInterval <= 0 {
		v.add(at("sync_interval"), "must be a positive duration, got %s", p.SyncInterval)
	}
}

func (v *validator) sshProvider(p SSHProvider, at func(string) string) {
	if p.Endpoint.Host == "" {
		v.add(at("endpoint.host"), "required")
	}
	v.sshUser(at("endpoint.user"), p.Endpoint.User)
	v.sshUser(at("endpoint.admin_user"), p.Endpoint.AdminUser)
	if p.Endpoint.Port < 1 || p.Endpoint.Port > 65535 {
		v.add(at("endpoint.port"), "must be between 1 and 65535, got %d", p.Endpoint.Port)
	}
	if p.CredentialRef == "" {
		v.add(at("credential_ref"), "required")
	} else if err := validateCredentialRef(p.CredentialRef, v.cfg.Instance.Mode); err != "" {
		v.add(at("credential_ref"), "%s", err)
	}
	if p.AdminCredentialRef != "" {
		if err := validateCredentialRef(p.AdminCredentialRef, v.cfg.Instance.Mode); err != "" {
			v.add(at("admin_credential_ref"), "%s", err)
		}
	}
}

// sshUserPattern is the login-name allowlist the command templates and the
// sudoers grammar rely on (ADR-0015).
var sshUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (v *validator) sshUser(yamlPath, user string) {
	switch {
	case user == "":
		v.add(yamlPath, "required")
	case !sshUserPattern.MatchString(user):
		v.add(yamlPath, "must match %s, got %q", sshUserPattern, user)
	}
}

// secretRefOnly requires a secret:// reference (tokens and client secrets
// always live in the secret store, spec §8.4).
func (v *validator) secretRefOnly(yamlPath, ref string) {
	if err := validateCredentialRef(ref, v.cfg.Instance.Mode); err != "" {
		v.add(yamlPath, "%s", err)
	} else if !strings.HasPrefix(ref, "secret://") {
		v.add(yamlPath, "must be a secret:// reference, got scheme %q", scheme(ref))
	}
}

var schemePattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,15}$`)

// scheme returns the "<scheme>://" prefix of ref, or "" when ref has none or
// its prefix does not look like a scheme, so a bare value (which may be a
// pasted secret) is never echoed.
func scheme(ref string) string {
	s, _, found := strings.Cut(ref, "://")
	if !found || !schemePattern.MatchString(s) {
		return ""
	}
	return s + "://"
}

// validateCredentialRef checks the closed scheme set of spec §8.4 and returns
// a problem description, or "" when ref is acceptable.
func validateCredentialRef(ref string, mode Mode) string {
	switch {
	case strings.HasPrefix(ref, "secret://"):
		if strings.TrimPrefix(ref, "secret://") == "" {
			return "secret:// reference needs a path"
		}
	case ref == "ssh-agent://default":
		if mode == ModeServer {
			return "ssh-agent:// is not allowed in server mode"
		}
	case strings.HasPrefix(ref, "file://"):
		if !path.IsAbs(strings.TrimPrefix(ref, "file://")) {
			return "file:// reference needs an absolute path"
		}
	default:
		const allowed = "(allowed: secret://<path>, ssh-agent://default, file://<abs-path>)"
		if sc := scheme(ref); sc != "" {
			return fmt.Sprintf("unsupported credential reference scheme %q %s", sc, allowed)
		}
		return "credential reference is missing a scheme " + allowed
	}
	return ""
}

// walkLeaves calls visit for every field of v that is not a struct, with its
// yaml path. Slices are not descended into.
func walkLeaves(v reflect.Value, prefix string, visit func(yamlPath string, f reflect.Value)) {
	t := v.Type()
	for i := range t.NumField() {
		key := yamlKey(t.Field(i))
		if key == "" {
			continue
		}
		f := v.Field(i)
		if f.Kind() == reflect.Struct {
			walkLeaves(f, joinPath(prefix, key), visit)
			continue
		}
		visit(joinPath(prefix, key), f)
	}
}

var (
	cloudflareAccountIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	identityProviderIDPattern  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// cloudflare validates the optional block; absent means the feature is off.
func (v *validator) cloudflare() {
	cf := v.cfg.Cloudflare
	if cf == nil {
		return
	}
	if !cloudflareAccountIDPattern.MatchString(cf.AccountID) {
		v.add("cloudflare.account_id", "must be 32 lowercase hexadecimal characters")
	}
	if err := domain.ValidateDNSName(cf.Zone); err != nil {
		v.add("cloudflare.zone", "must be a DNS name such as example.com: %v", err)
	}
	v.secretRefOnly("cloudflare.api_token_ref", cf.APITokenRef)
	v.secretRefOnly("cloudflare.access_token_ref", cf.AccessTokenRef)
	if len(cf.OwnerEmails) == 0 {
		v.add("cloudflare.owner_emails", "must be non-empty: Access admits only these identities")
	}
	for i, email := range cf.OwnerEmails {
		if !plausibleEmail(email) {
			v.add(fmt.Sprintf("cloudflare.owner_emails[%d]", i), "must be a single email address without wildcards, got %q", email)
		}
	}
	for i, id := range cf.AccessIdentityProviders {
		if !identityProviderIDPattern.MatchString(id) {
			v.add(fmt.Sprintf("cloudflare.access_identity_providers[%d]", i), "must be an identity provider ID (letters, digits, hyphens), got %q", id)
		}
	}
}

// plausibleEmail accepts a bare addr-spec whose domain is a DNS name: no
// display name, no comments, no wildcards, no whitespace.
func plausibleEmail(s string) bool {
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s || strings.ContainsAny(s, "*<>, \t") {
		return false
	}
	local, domainPart, ok := strings.Cut(s, "@")
	return ok && local != "" && domain.ValidateDNSName(strings.ToLower(domainPart)) == nil
}
