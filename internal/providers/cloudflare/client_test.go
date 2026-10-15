package cloudflare

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

const (
	testTimeout = 2 * time.Second
	instanceID  = "11111111-1111-4111-8111-111111111111"
	nodeID      = "22222222-2222-4222-8222-222222222222"
)

func newClientFor(t *testing.T, f *cffake.Fake, token string) *Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.CAPEM()) {
		t.Fatal("fake CA")
	}
	c, err := New(f.Endpoint(), f.AccountID(), audit.Secret(token), WithHTTPTimeout(testTimeout),
		WithNetguardOptions(netguard.WithRootCAs(pool), netguard.WithTestDialer(f.Dial)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newEnv(t *testing.T, opts ...cffake.Option) (*cffake.Fake, *Client) {
	t.Helper()
	f := cffake.New(t, opts...)
	t.Cleanup(func() {
		if rejected := f.Rejected(); len(rejected) != 0 {
			t.Errorf("the client left the fake's contract: %v", rejected)
		}
	})
	return f, newClientFor(t, f, f.Token())
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestNew_RejectsBadInput(t *testing.T) {
	account := cffake.DefaultAccountID
	tests := []struct{ name, url, account, token string }{
		{"http", "http://api.cloudflare.com/client/v4", account, "t"},
		{"no host", "https://", account, "t"},
		{"userinfo", "https://u:p@api.cloudflare.com", account, "t"},
		{"query", "https://api.cloudflare.com?x=1", account, "t"},
		{"trailing slash", "https://api.cloudflare.com/client/v4/", account, "t"},
		{"empty token", "", account, ""},
		{"token with a space", "", account, "a b"},
		{"token with a newline", "", account, "a\nb"},
		{"bad account", "", "../x", "t"},
		{"empty account", "", "", "t"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.url, tc.account, audit.Secret(tc.token)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := New("", account, "t"); err != nil {
		t.Errorf("default base URL: %v", err)
	}
}

func TestNames_AreTheADRMarkers(t *testing.T) {
	if got, want := TunnelName("I", "N"), "sm-I-N"; got != want {
		t.Errorf("TunnelName = %q", got)
	}
	if got, want := AccessAppName("I", "N"), "supermgmt I N"; got != want {
		t.Errorf("AccessAppName = %q", got)
	}
	if got, want := ServicePolicyName("I"), "supermgmt service I"; got != want {
		t.Errorf("ServicePolicyName = %q", got)
	}
	if got, want := OwnersPolicyName("I"), "supermgmt owners I"; got != want {
		t.Errorf("OwnersPolicyName = %q", got)
	}
	if got, want := ServiceTokenName("I"), "supermgmt-I"; got != want {
		t.Errorf("ServiceTokenName = %q", got)
	}
	if got, want := DNSComment("I", "N"), "supermgmt:I:N"; got != want {
		t.Errorf("DNSComment = %q", got)
	}
	if got, want := TunnelTarget("abc"), "abc.cfargotunnel.com"; got != want {
		t.Errorf("TunnelTarget = %q", got)
	}
}

func TestTunnelHostname(t *testing.T) {
	if got, err := TunnelHostname("Web1", "Example.com"); err != nil || got != "ssh-web1.example.com" {
		t.Errorf("TunnelHostname = %q, %v", got, err)
	}
	for _, node := range []string{"", "a b", "a.b", "a_b", "-", "a;b", "a/b", "a%b", strings.Repeat("x", 70)} {
		if got, err := TunnelHostname(node, "example.com"); err == nil {
			t.Errorf("TunnelHostname(%q) = %q, want an error", node, got)
		}
	}
	if _, err := TunnelHostname("web1", ""); err == nil {
		t.Error("an empty zone must be refused")
	}
}

func TestTunnels_Lifecycle(t *testing.T) {
	f, c := newEnv(t)
	name := TunnelName(instanceID, nodeID)
	tun := must[Tunnel](t)(c.CreateTunnel(ctx(t), name))
	if tun.Name != name || tun.ConfigSrc != "cloudflare" || tun.CreatedAt.IsZero() || tun.Deleted() {
		t.Fatalf("created tunnel = %+v", tun)
	}
	found := must[[]Tunnel](t)(c.FindTunnels(ctx(t), name))
	if len(found) != 1 || found[0].ID != tun.ID {
		t.Fatalf("FindTunnels = %+v", found)
	}
	if got := must[[]Tunnel](t)(c.FindTunnels(ctx(t), name+"x")); len(got) != 0 {
		t.Errorf("a different name found %+v", got)
	}

	empty := must[TunnelConfig](t)(c.GetTunnelConfig(ctx(t), tun.ID))
	if empty.Version != 0 || len(empty.Ingress) != 0 {
		t.Errorf("unconfigured tunnel config = %+v", empty)
	}
	host := "ssh-web1.example.test"
	cfg := must[TunnelConfig](t)(c.PutTunnelIngress(ctx(t), tun.ID, SSHIngress(host)))
	if cfg.Version != 1 || len(cfg.Ingress) != 2 || cfg.Ingress[0] != (IngressRule{Hostname: host, Service: ServiceSSH}) || cfg.Ingress[1].Service != ServiceNotFound {
		t.Errorf("ssh ingress = %+v", cfg)
	}
	closed := must[TunnelConfig](t)(c.PutTunnelIngress(ctx(t), tun.ID, ClosedIngress()))
	if got := must[TunnelConfig](t)(c.GetTunnelConfig(ctx(t), tun.ID)); got.Version != 2 || len(got.Ingress) != 1 || got.Ingress[0].Hostname != "" || closed.Version != 2 {
		t.Errorf("closed ingress = %+v", got)
	}

	token := must[audit.Secret](t)(c.TunnelToken(ctx(t), tun.ID))
	if token.Reveal() == "" || strings.Contains(token.String(), token.Reveal()) {
		t.Errorf("token = %q (%v)", token.String(), token.Reveal() == "")
	}

	f.ConnectTunnel(tun.ID, 2)
	if got := must[Tunnel](t)(c.GetTunnel(ctx(t), tun.ID)); got.ActiveConnections != 2 || got.Status != "healthy" {
		t.Errorf("connected tunnel = %+v", got)
	}
	if err := c.DeleteTunnel(ctx(t), tun.ID); !isStatus(err, http.StatusBadRequest) {
		t.Fatalf("deleting a connected tunnel = %v, want 400", err)
	}
	if err := c.CleanupTunnelConnections(ctx(t), tun.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteTunnel(ctx(t), tun.ID); err != nil {
		t.Fatal(err)
	}
	if got := must[Tunnel](t)(c.GetTunnel(ctx(t), tun.ID)); !got.Deleted() {
		t.Errorf("deleted tunnel = %+v", got)
	}
	if got := must[[]Tunnel](t)(c.FindTunnels(ctx(t), name)); len(got) != 0 {
		t.Errorf("a deleted tunnel is still found: %+v", got)
	}
	if err := c.DeleteTunnel(ctx(t), tun.ID); !IsNotFound(err) {
		t.Errorf("deleting twice = %v, want not found", err)
	}
	if again := must[Tunnel](t)(c.CreateTunnel(ctx(t), name)); again.ID == tun.ID {
		t.Error("the name of a deleted tunnel is reusable")
	}
}

func isStatus(err error, status int) bool {
	var api *APIError
	return errors.As(err, &api) && api.Status == status
}

func TestTunnels_ForeignNameIsAConflict(t *testing.T) {
	f, c := newEnv(t)
	f.SeedTunnel(TunnelName(instanceID, nodeID))
	_, err := c.CreateTunnel(ctx(t), TunnelName(instanceID, nodeID))
	if !IsConflict(err) || IsAmbiguous(err) {
		t.Fatalf("CreateTunnel = %v, want a definite conflict", err)
	}
	var api *APIError
	if !errors.As(err, &api) || api.ErrorCode() != smerr.CodeConflict {
		t.Errorf("error code = %v", err)
	}
}

func TestIngress_IsValidatedBeforeSending(t *testing.T) {
	f, c := newEnv(t)
	tun := f.SeedTunnel("t")
	bad := map[string][]IngressRule{
		"none":              nil,
		"no catch-all":      {{Hostname: "ssh-a.example.test", Service: ServiceSSH}},
		"hostname in last":  {{Hostname: "ssh-a.example.test", Service: ServiceSSH}, {Hostname: "b.example.test", Service: ServiceNotFound}},
		"bad hostname":      {{Hostname: "a b", Service: ServiceSSH}, {Service: ServiceNotFound}},
		"empty service":     {{Hostname: "a.example.test"}, {Service: ServiceNotFound}},
		"hostless non-last": {{Service: ServiceSSH}, {Service: ServiceNotFound}},
	}
	for name, rules := range bad {
		if _, err := c.PutTunnelIngress(ctx(t), tun.ID, rules); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := c.PutTunnelIngress(ctx(t), "../x", ClosedIngress()); err == nil {
		t.Error("a path-like tunnel id was accepted")
	}
	for _, r := range f.Requests() {
		if strings.Contains(r.Path, "configurations") {
			t.Errorf("an invalid ingress reached the API: %s %s", r.Method, r.Path)
		}
	}
}

func TestDNS_Lifecycle(t *testing.T) {
	f, c := newEnv(t)
	zone := must[Zone](t)(c.ZoneByName(ctx(t), "Example.TEST"))
	if _, id := f.Zone(); zone.ID != id || zone.AccountID != f.AccountID() {
		t.Fatalf("zone = %+v", zone)
	}
	if _, err := c.ZoneByName(ctx(t), "other.test"); !IsNotFound(err) {
		t.Errorf("unknown zone = %v", err)
	}
	host := "ssh-web1.example.test"
	rec := must[DNSRecord](t)(c.CreateTunnelCNAME(ctx(t), zone.ID, host, "tun-1", DNSComment(instanceID, nodeID)))
	if rec.Type != "CNAME" || !rec.Proxied || rec.Content != TunnelTarget("tun-1") || rec.Comment != DNSComment(instanceID, nodeID) || rec.Name != host {
		t.Fatalf("record = %+v", rec)
	}
	if got := must[[]DNSRecord](t)(c.FindDNSRecords(ctx(t), zone.ID, host)); len(got) != 1 || got[0].ID != rec.ID {
		t.Fatalf("FindDNSRecords = %+v", got)
	}
	_, err := c.CreateTunnelCNAME(ctx(t), zone.ID, host, "tun-2", "someone else")
	if !IsConflict(err) || IsAmbiguous(err) {
		t.Fatalf("second record for the hostname = %v, want a definite conflict", err)
	}
	if err := c.DeleteDNSRecord(ctx(t), zone.ID, rec.ID); err != nil {
		t.Fatal(err)
	}
	if got := must[[]DNSRecord](t)(c.FindDNSRecords(ctx(t), zone.ID, host)); len(got) != 0 {
		t.Errorf("deleted record found: %+v", got)
	}
	if err := c.DeleteDNSRecord(ctx(t), zone.ID, rec.ID); !IsNotFound(err) {
		t.Errorf("deleting twice = %v", err)
	}
	if _, err := c.CreateTunnelCNAME(ctx(t), zone.ID, "evil.other.test", "t", ""); err == nil {
		t.Error("a record outside the zone was created")
	}
	if _, err := c.CreateTunnelCNAME(ctx(t), zone.ID, "a b.example.test", "t", ""); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("hostile hostname = %v", err)
	}
}

func TestAccess_PoliciesAppsAndTokens(t *testing.T) {
	f, c := newEnv(t)
	host := "ssh-web1.example.test"
	tok := must[NewServiceToken](t)(c.CreateServiceToken(ctx(t), ServiceTokenName(instanceID)))
	if tok.ClientSecret.Reveal() == "" || tok.ClientID == "" || tok.ExpiresAt.Sub(tok.CreatedAt) != 8760*time.Hour {
		t.Fatalf("service token = %+v", tok.ServiceToken)
	}
	listed := must[[]ServiceToken](t)(c.FindServiceTokens(ctx(t), ServiceTokenName(instanceID)))
	if len(listed) != 1 || listed[0].ID != tok.ID || listed[0].ClientID != tok.ClientID {
		t.Fatalf("FindServiceTokens = %+v", listed)
	}
	f.SeedServiceToken(ServiceTokenName(instanceID) + "-other")
	if got := must[[]ServiceToken](t)(c.FindServiceTokens(ctx(t), ServiceTokenName(instanceID))); len(got) != 1 {
		t.Errorf("a longer name matched: %+v", got)
	}

	svc := must[AccessPolicy](t)(c.CreateAccessPolicy(ctx(t), PolicySpec{
		Name: ServicePolicyName(instanceID), Kind: PolicyServiceAuth, ServiceTokenIDs: []string{tok.ID},
	}))
	if svc.Decision != "non_identity" || len(svc.ServiceTokenIDs) != 1 || svc.ServiceTokenIDs[0] != tok.ID || svc.UnknownRules != 0 {
		t.Fatalf("service policy = %+v", svc)
	}
	owners := must[AccessPolicy](t)(c.CreateAccessPolicy(ctx(t), PolicySpec{
		Name: OwnersPolicyName(instanceID), Kind: PolicyAllow, Emails: []string{"Owner@Example.com"},
	}))
	if owners.Decision != "allow" || len(owners.Emails) != 1 || owners.Emails[0] != "owner@example.com" {
		t.Fatalf("owners policy = %+v", owners)
	}

	app := must[AccessApp](t)(c.CreateAccessApp(ctx(t), AppSpec{
		Name: AccessAppName(instanceID, nodeID), Domain: host, PolicyIDs: []string{svc.ID, owners.ID}, AllowedIdPs: []string{"idp-1"},
	}))
	if app.Domain != host || app.Type != "self_hosted" || len(app.PolicyIDs) != 2 || app.PolicyIDs[0] != svc.ID || len(app.AllowedIdPs) != 1 {
		t.Fatalf("app = %+v", app)
	}
	if got := must[[]AccessApp](t)(c.FindAccessApps(ctx(t), AccessAppName(instanceID, nodeID))); len(got) != 1 || got[0].ID != app.ID {
		t.Fatalf("FindAccessApps = %+v", got)
	}
	if _, err := c.CreateAccessApp(ctx(t), AppSpec{Name: "dup", Domain: host, PolicyIDs: []string{svc.ID}}); !IsConflict(err) {
		t.Errorf("a second application on the domain = %v", err)
	}
	updated := must[AccessApp](t)(c.UpdateAccessApp(ctx(t), app.ID, AppSpec{
		Name: app.Name, Domain: host, PolicyIDs: []string{svc.ID, owners.ID}, AllowedIdPs: []string{"idp-1", "idp-2"},
	}))
	if updated.ID != app.ID || len(updated.AllowedIdPs) != 2 || !updated.CreatedAt.Equal(app.CreatedAt) {
		t.Errorf("updated app = %+v, want the same application with two identity providers", updated)
	}
	if _, err := c.UpdateAccessApp(ctx(t), "missing", AppSpec{Name: "n", Domain: host, PolicyIDs: []string{svc.ID}}); !IsNotFound(err) {
		t.Errorf("updating an unknown application = %v, want not found", err)
	}

	// Rotation: the service policy lists both tokens, then only the new one.
	next := must[NewServiceToken](t)(c.CreateServiceToken(ctx(t), ServiceTokenName(instanceID)))
	both := must[AccessPolicy](t)(c.UpdateAccessPolicy(ctx(t), svc.ID, PolicySpec{
		Name: svc.Name, Kind: PolicyServiceAuth, ServiceTokenIDs: []string{tok.ID, next.ID},
	}))
	if len(both.ServiceTokenIDs) != 2 {
		t.Fatalf("overlap policy = %+v", both)
	}
	only := must[AccessPolicy](t)(c.UpdateAccessPolicy(ctx(t), svc.ID, PolicySpec{
		Name: svc.Name, Kind: PolicyServiceAuth, ServiceTokenIDs: []string{next.ID},
	}))
	if len(only.ServiceTokenIDs) != 1 || only.ServiceTokenIDs[0] != next.ID {
		t.Fatalf("rotated policy = %+v", only)
	}
	if got := must[[]AccessPolicy](t)(c.FindAccessPolicies(ctx(t), ServicePolicyName(instanceID))); len(got) != 1 || got[0].ServiceTokenIDs[0] != next.ID {
		t.Fatalf("FindAccessPolicies = %+v", got)
	}
	if err := c.DeleteServiceToken(ctx(t), tok.ID); err != nil {
		t.Fatal(err)
	}

	// Removal order: the policy is held by the application until it is deleted.
	if err := c.DeleteAccessPolicy(ctx(t), svc.ID); !IsConflict(err) {
		t.Errorf("deleting an attached policy = %v", err)
	}
	if err := c.DeleteAccessApp(ctx(t), app.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{svc.ID, owners.ID} {
		if err := c.DeleteAccessPolicy(ctx(t), id); err != nil {
			t.Fatal(err)
		}
	}
	if snap := f.Snapshot(); len(snap.Apps)+len(snap.Policies) != 0 {
		t.Errorf("left behind: %+v", snap)
	}
}

func TestAccess_InputsAreValidated(t *testing.T) {
	_, c := newEnv(t)
	bad := []PolicySpec{
		{Name: "n", Kind: PolicyAllow},
		{Name: "n", Kind: PolicyAllow, Emails: []string{"*@example.com"}},
		{Name: "n", Kind: PolicyAllow, Emails: []string{"a@example.com", "b c@example.com"}},
		{Name: "n", Kind: PolicyAllow, Emails: []string{"a@@example.com"}},
		{Name: "n", Kind: PolicyAllow, Emails: []string{"a"}},
		{Name: "n", Kind: PolicyAllow, Emails: []string{"a@example.com"}, ServiceTokenIDs: []string{"x"}},
		{Name: "n", Kind: PolicyServiceAuth},
		{Name: "n", Kind: PolicyServiceAuth, ServiceTokenIDs: []string{"a/b"}},
		{Name: "n", Kind: "bypass", Emails: []string{"a@example.com"}},
		{Name: "", Kind: PolicyAllow, Emails: []string{"a@example.com"}},
	}
	for i, spec := range bad {
		if _, err := c.CreateAccessPolicy(ctx(t), spec); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("spec %d: err = %v", i, err)
		}
	}
	if _, err := c.CreateAccessApp(ctx(t), AppSpec{Name: "n", Domain: "a b.example.test", PolicyIDs: []string{"p"}}); err == nil {
		t.Error("hostile domain accepted")
	}
	if _, err := c.CreateAccessApp(ctx(t), AppSpec{Name: "n", Domain: "a.example.test"}); err == nil {
		t.Error("an application without a policy was accepted")
	}
	if err := c.DeleteAccessApp(ctx(t), ""); err == nil {
		t.Error("empty id accepted")
	}
}

func TestPagination_ReadsEveryPage(t *testing.T) {
	f, c := newEnv(t, cffake.WithPageSize(2))
	for range 5 {
		f.SeedPolicy("shared", "o@example.com")
		f.SeedServiceToken("shared")
	}
	f.SeedPolicy("other", "o@example.com")
	policies := must[[]AccessPolicy](t)(c.FindAccessPolicies(ctx(t), "shared"))
	tokens := must[[]ServiceToken](t)(c.FindServiceTokens(ctx(t), "shared"))
	if len(policies) != 5 || len(tokens) != 5 {
		t.Fatalf("policies = %d, tokens = %d, want 5 and 5", len(policies), len(tokens))
	}
	pages := 0
	for _, r := range f.Requests() {
		if strings.HasSuffix(r.Path, "/access/policies") {
			pages++
		}
	}
	if pages != 3 {
		t.Errorf("policy list took %d requests, want 3 pages of 2 (6 policies)", pages)
	}
}

func TestPagination_IsBounded(t *testing.T) {
	f, c := newEnv(t, cffake.WithPageSize(1))
	for range maxPages + 2 {
		f.SeedServiceToken("shared")
	}
	_, err := c.FindServiceTokens(ctx(t), "shared")
	if err == nil || !strings.Contains(err.Error(), "pages") {
		t.Fatalf("err = %v, want the page bound", err)
	}
}

func TestLists_AreExactWhateverTheServerFilterDoes(t *testing.T) {
	f, c := newEnv(t)
	f.SeedApp("supermgmt A B", "a.example.test")
	f.SeedApp("supermgmt A B extra", "b.example.test")
	if got := must[[]AccessApp](t)(c.FindAccessApps(ctx(t), "supermgmt A B")); len(got) != 1 || got[0].Domain != "a.example.test" {
		t.Errorf("FindAccessApps = %+v", got)
	}
}

func TestErrors_MapConsistently(t *testing.T) {
	f, c := newEnv(t)
	tun := f.SeedTunnel("t")
	tests := []struct {
		name      string
		fault     cffake.Fault
		op        cffake.Op
		call      func() error
		code      smerr.Code
		retryable bool
		ambiguous bool
	}{
		{"forbidden", cffake.Forbidden, cffake.OpTunnelGet, func() error { _, err := c.GetTunnel(ctx(t), tun.ID); return err }, smerr.CodeUnauthenticated, false, false},
		{"rate limited", cffake.RateLimited, cffake.OpTunnelDelete, func() error { return c.DeleteTunnel(ctx(t), tun.ID) }, smerr.CodeProviderError, true, false},
		{"server error", cffake.FailBefore, cffake.OpTunnelCreate, func() error { _, err := c.CreateTunnel(ctx(t), "x"); return err }, smerr.CodeProviderError, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.Inject(tc.op, tc.fault, 1)
			err := tc.call()
			var api *APIError
			if !errors.As(err, &api) {
				t.Fatalf("err = %v, want an APIError", err)
			}
			if api.ErrorCode() != tc.code || api.Retryable() != tc.retryable || IsAmbiguous(err) != tc.ambiguous {
				t.Errorf("code %v retryable %v ambiguous %v, want %v %v %v", api.ErrorCode(), api.Retryable(), IsAmbiguous(err), tc.code, tc.retryable, tc.ambiguous)
			}
			if tc.fault == cffake.RateLimited && api.RetryAfter != time.Second {
				t.Errorf("RetryAfter = %v", api.RetryAfter)
			}
		})
	}
	_, err := c.GetTunnel(ctx(t), "00000000-0000-4000-8000-00000000ffff")
	var missing *APIError
	if !IsNotFound(err) || !errors.As(err, &missing) || missing.ErrorCode() != smerr.CodeNotFound {
		t.Errorf("unknown tunnel = %v", err)
	}
	wrong := newClientFor(t, f, "not-the-token")
	_, err = wrong.GetTunnel(ctx(t), tun.ID)
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusUnauthorized || api.ErrorCode() != smerr.CodeUnauthenticated || IsAmbiguous(err) {
		t.Errorf("wrong token = %v", err)
	}
	other, err := New(f.Endpoint(), "ffffffffffffffffffffffffffffffff", audit.Secret(f.Token()),
		WithNetguardOptions(netguard.WithRootCAs(certPool(t, f)), netguard.WithTestDialer(f.Dial)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.FindTunnels(ctx(t), "x"); !isStatus(err, http.StatusForbidden) {
		t.Errorf("another account = %v, want 403", err)
	}
}

func certPool(t *testing.T, f *cffake.Fake) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.CAPEM())
	return pool
}

func TestErrors_NeverCarryTheTokenOrControlCharacters(t *testing.T) {
	f := cffake.New(t, cffake.WithEchoedCredentials())
	const secretToken = "tok-SECRET-0123456789"
	for _, token := range []string{f.Token(), secretToken} {
		c := newClientFor(t, f, token)
		_, err := c.CreateTunnel(ctx(t), "sm-"+instanceID)
		f.Inject(cffake.OpTunnelList, cffake.Forbidden, 1)
		_, err2 := c.FindTunnels(ctx(t), "x")
		for _, e := range []error{err, err2} {
			if e == nil && token == f.Token() {
				continue
			}
			if e == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(e.Error(), token) || strings.ContainsRune(e.Error(), 0x1b) {
				t.Errorf("error leaks: %q", e.Error())
			}
			if !strings.Contains(e.Error(), "[redacted]") && token != f.Token() {
				t.Errorf("error does not show the redaction: %q", e.Error())
			}
		}
	}
}

func TestTransportErrors_AreAmbiguousOnlyWhenSent(t *testing.T) {
	f := cffake.New(t)
	c, err := New("https://127.0.0.1/client/v4", cffake.DefaultAccountID, audit.Secret(f.Token()), WithHTTPTimeout(testTimeout))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateTunnel(ctx(t), "x")
	if err == nil || IsAmbiguous(err) || !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("blocked destination = %v, want a definite refusal", err)
	}
	if strings.Contains(err.Error(), f.Token()) {
		t.Error("token in error")
	}
}

func TestLostResponse_LookupByNameFindsTheObject(t *testing.T) {
	// A propagation delay of 2 means the first lookups right after the lost
	// answer may not see the object yet; a caller retries the lookup.
	f, c := newEnv(t, cffake.WithPropagationDelay(2))
	name := TunnelName(instanceID, nodeID)
	f.Inject(cffake.OpTunnelCreate, cffake.LostResponse, 1)
	_, err := c.CreateTunnel(ctx(t), name)
	if err == nil || !IsAmbiguous(err) {
		t.Fatalf("CreateTunnel = %v, want an ambiguous failure", err)
	}
	var found []Tunnel
	for range 5 {
		if found = must[[]Tunnel](t)(c.FindTunnels(ctx(t), name)); len(found) > 0 {
			break
		}
	}
	if len(found) != 1 || found[0].Name != name {
		t.Fatalf("lookup after the lost answer = %+v", found)
	}
	if n := len(f.Tunnels()); n != 1 {
		t.Errorf("%d tunnels exist", n)
	}
}

func TestLostResponse_ServiceTokenOrphanIsFoundAndDeleted(t *testing.T) {
	f, c := newEnv(t)
	name := ServiceTokenName(instanceID)
	f.Inject(cffake.OpServiceTokenNew, cffake.LostResponse, 1)
	if _, err := c.CreateServiceToken(ctx(t), name); !IsAmbiguous(err) {
		t.Fatalf("CreateServiceToken = %v, want ambiguous", err)
	}
	orphans := must[[]ServiceToken](t)(c.FindServiceTokens(ctx(t), name))
	if len(orphans) != 1 || orphans[0].ClientID == "" {
		t.Fatalf("orphans = %+v", orphans)
	}
	if err := c.DeleteServiceToken(ctx(t), orphans[0].ID); err != nil {
		t.Fatal(err)
	}
	fresh := must[NewServiceToken](t)(c.CreateServiceToken(ctx(t), name))
	if fresh.ID == orphans[0].ID || len(f.ServiceTokens()) != 1 {
		t.Errorf("fresh = %+v, tokens = %d", fresh.ServiceToken, len(f.ServiceTokens()))
	}
}

func TestFailBefore_AppliesNothing(t *testing.T) {
	f, c := newEnv(t)
	f.Inject(cffake.OpTunnelCreate, cffake.FailBefore, 1)
	if _, err := c.CreateTunnel(ctx(t), "x"); !IsAmbiguous(err) {
		t.Fatalf("err = %v, want ambiguous (a 5xx cannot be told from a lost answer)", err)
	}
	if n := len(f.Tunnels()); n != 0 {
		t.Errorf("%d tunnels exist after a failure before commit", n)
	}
}

func TestInvariant_DNSBeforeAccessIsCaught(t *testing.T) {
	f, c := newEnv(t)
	host := "ssh-web1.example.test"
	_, zoneID := f.Zone()
	must[DNSRecord](t)(c.CreateTunnelCNAME(ctx(t), zoneID, host, "tun-1", "m"))
	if got := f.RoutableWithoutAccess(); len(got) != 1 || got[0] != host {
		t.Fatalf("RoutableWithoutAccess = %v", got)
	}
	tok := must[NewServiceToken](t)(c.CreateServiceToken(ctx(t), "t"))
	pol := must[AccessPolicy](t)(c.CreateAccessPolicy(ctx(t), PolicySpec{Name: "p", Kind: PolicyServiceAuth, ServiceTokenIDs: []string{tok.ID}}))
	must[AccessApp](t)(c.CreateAccessApp(ctx(t), AppSpec{Name: "a", Domain: host, PolicyIDs: []string{pol.ID}}))
	if got := f.RoutableWithoutAccess(); len(got) != 0 {
		t.Errorf("protected hostname still reported: %v", got)
	}
	if got := f.EverRoutableWithoutAccess(); len(got) != 1 {
		t.Errorf("EverRoutableWithoutAccess = %v, want the early window recorded", got)
	}
}

// provision is a minimal idempotent setup in the order of ADR-0037: every step
// looks the object up by name before it creates.
func provision(c *Client, zoneID, host string) error {
	bg := context.Background()
	tunName := TunnelName(instanceID, nodeID)
	tuns, err := c.FindTunnels(bg, tunName)
	if err != nil {
		return err
	}
	var tun Tunnel
	if len(tuns) > 0 {
		tun = tuns[0]
	} else if tun, err = c.CreateTunnel(bg, tunName); err != nil {
		return err
	}
	if _, err := c.PutTunnelIngress(bg, tun.ID, SSHIngress(host)); err != nil {
		return err
	}
	toks, err := c.FindServiceTokens(bg, ServiceTokenName(instanceID))
	if err != nil {
		return err
	}
	var tokID string
	if len(toks) > 0 {
		tokID = toks[0].ID
	} else if nt, err := c.CreateServiceToken(bg, ServiceTokenName(instanceID)); err != nil {
		return err
	} else {
		tokID = nt.ID
	}
	var policyIDs []string
	for _, spec := range []PolicySpec{
		{Name: ServicePolicyName(instanceID), Kind: PolicyServiceAuth, ServiceTokenIDs: []string{tokID}},
		{Name: OwnersPolicyName(instanceID), Kind: PolicyAllow, Emails: []string{"o@example.com"}},
	} {
		got, err := c.FindAccessPolicies(bg, spec.Name)
		if err != nil {
			return err
		}
		if len(got) == 0 {
			p, err := c.CreateAccessPolicy(bg, spec)
			if err != nil {
				return err
			}
			got = []AccessPolicy{p}
		}
		policyIDs = append(policyIDs, got[0].ID)
	}
	apps, err := c.FindAccessApps(bg, AccessAppName(instanceID, nodeID))
	if err != nil {
		return err
	}
	if len(apps) == 0 {
		if _, err := c.CreateAccessApp(bg, AppSpec{Name: AccessAppName(instanceID, nodeID), Domain: host, PolicyIDs: policyIDs}); err != nil {
			return err
		}
	}
	records, err := c.FindDNSRecords(bg, zoneID, host)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		if _, err := c.CreateTunnelCNAME(bg, zoneID, host, tun.ID, DNSComment(instanceID, nodeID)); err != nil {
			return err
		}
	}
	return nil
}

func TestProvision_ConvergesAfterEveryInjectedFault(t *testing.T) {
	host := "ssh-web1.example.test"
	clean, cc := newEnv(t)
	_, zoneID := clean.Zone()
	if err := provision(cc, zoneID, host); err != nil {
		t.Fatal(err)
	}
	total := len(clean.Mutations())
	if total < 7 {
		t.Fatalf("a clean provisioning made %d mutations", total)
	}
	want := clean.Snapshot().Count()

	for _, fault := range []cffake.Fault{cffake.FailBefore, cffake.LostResponse} {
		for k := 1; k <= total; k++ {
			f, c := newEnv(t, cffake.WithPropagationDelay(1))
			f.Plan(func(m cffake.Mutation) cffake.Fault {
				if m.Seq == k {
					return fault
				}
				return cffake.NoFault
			})
			var err error
			for attempt := 0; attempt < 4; attempt++ {
				if err = provision(c, zoneID, host); err == nil {
					break
				}
				// A conflict right after an ambiguous attempt is the object the
				// lookup could not see yet; the next attempt looks again.
				if !IsAmbiguous(err) && !IsConflict(err) {
					t.Fatalf("fault %v at %d: definite failure %v", fault, k, err)
				}
			}
			if err != nil {
				t.Fatalf("fault %v at %d: did not converge: %v", fault, k, err)
			}
			if got := f.Snapshot(); got.Count() != want || len(got.Tunnels) != 1 || len(got.DNSRecords) != 1 || len(got.Apps) != 1 {
				t.Errorf("fault %v at %d: %+v, want %d objects once each", fault, k, got, want)
			}
			if bad := f.EverRoutableWithoutAccess(); len(bad) != 0 {
				t.Errorf("fault %v at %d: routable without Access: %v", fault, k, bad)
			}
		}
	}
}

func TestProbe_ReportsWhatWasProvable(t *testing.T) {
	f, c := newEnv(t)
	report := c.Probe(ctx(t), "example.test")
	for _, check := range report.Checks {
		if !check.OK() {
			t.Errorf("%s: %v", check.Name, check.Err)
		}
	}
	for _, name := range []string{CheckToken, CheckTunnels, CheckAccessApps, CheckAccessPolicy, CheckServiceTokens, CheckZone, CheckDNS} {
		if !report.Check(name).OK() {
			t.Errorf("check %s did not pass", name)
		}
	}
	if !report.Token.Active() {
		t.Errorf("token = %+v", report.Token)
	}
	for _, r := range f.Requests() {
		if r.Method != http.MethodGet {
			t.Errorf("probe sent %s %s", r.Method, r.Path)
		}
	}

	f.Inject(cffake.OpTunnelList, cffake.Forbidden, 1)
	f.Inject(cffake.OpDNSList, cffake.Forbidden, 1)
	report = c.Probe(ctx(t), "example.test")
	if report.Check(CheckTunnels).OK() || report.Check(CheckDNS).OK() || !report.Check(CheckAccessApps).OK() {
		t.Errorf("checks = %+v", report.Checks)
	}
	if got := c.Probe(ctx(t), "other.test").Check(CheckZone); got.OK() || report.Check("nope").OK() {
		t.Error("an unknown zone must fail its check")
	}
	if got := c.Probe(ctx(t), "other.test").Check(CheckDNS); got.OK() {
		t.Error("the DNS check must not run without a zone")
	}
}

func TestVerifyToken_FallsBackToTheUserEndpoint(t *testing.T) {
	_, c := newEnv(t, cffake.WithUserOwnedToken())
	info, err := c.VerifyToken(ctx(t))
	if err != nil || !info.Active() {
		t.Fatalf("VerifyToken = %+v, %v", info, err)
	}
	wrong := newClientFor(t, cffake.New(t), "nope")
	var api *APIError
	if _, err := wrong.VerifyToken(ctx(t)); !errors.As(err, &api) || api.ErrorCode() != smerr.CodeUnauthenticated {
		t.Errorf("wrong token = %v", err)
	}
}
