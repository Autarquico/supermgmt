package config

import (
	"fmt"
	"net"
	"net/netip"
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
	if ref := v.cfg.Auth.OIDC.ClientSecretRef; ref != "" {
		v.secretRefOnly("auth.oidc.client_secret_ref", ref)
	}
}

func (v *validator) mcp() {
	m := v.cfg.MCP
	if !m.RemoteEnabled {
		return
	}
	need := func(yamlPath string, ok bool, what string) {
		if !ok {
			v.add(yamlPath, "%s (mcp.remote_enabled requires complete mcp.oauth)", what)
		}
	}
	need("mcp.oauth.issuer", m.OAuth.Issuer != "", "required")
	need("mcp.oauth.resource", m.OAuth.Resource != "", "required")
	need("mcp.oauth.jwks_url", m.OAuth.JWKSURL != "" || m.OAuth.IntrospectionURL != "", "jwks_url or introspection_url required")
	need("mcp.oauth.required_scopes", len(m.OAuth.RequiredScopes) > 0, "must be non-empty")
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
		case p.Proxmox != nil:
			v.proxmox(*p.Proxmox, at)
		case p.SSH != nil:
			v.sshProvider(*p.SSH, at)
		}
	}
}

func (v *validator) proxmox(p ProxmoxProvider, at func(string) string) {
	if p.Endpoint == "" {
		v.add(at("endpoint"), "required")
	}
	if p.CredentialRef == "" {
		v.add(at("credential_ref"), "required")
	} else {
		v.secretRefOnly(at("credential_ref"), p.CredentialRef)
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
