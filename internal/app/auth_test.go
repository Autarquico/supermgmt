package app

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/auth/oidc"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// countingMinter makes tokens "sm<k>_<n>" whose hash is "hash-" + token.
type countingMinter struct {
	mu sync.Mutex
	n  int
}

func (m *countingMinter) Mint(kind byte) (audit.Secret, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	token := fmt.Sprintf("sm%c_%d", kind, m.n)
	return audit.Secret(token), "hash-" + token, nil
}

func (m *countingMinter) Hash(token string) (byte, string, error) {
	if len(token) < 4 || token[:2] != "sm" || token[3] != '_' {
		return 0, "", smerr.New(smerr.CodeUnauthenticated, "", "malformed token")
	}
	return token[2], "hash-" + token, nil
}

// scriptedLogin is an oidc.Login whose answers the test sets.
type scriptedLogin struct {
	claims oidc.Claims
	poll   error
}

func (l *scriptedLogin) Start(context.Context, string, string) (string, string, error) {
	return "https://idp.example/auth", "state-1", nil
}

func (l *scriptedLogin) Exchange(context.Context, string, string, string) (oidc.Claims, error) {
	return l.claims, nil
}

func (l *scriptedLogin) DeviceStart(context.Context) (oidc.DeviceTxn, error) {
	return oidc.DeviceTxn{ID: "txn", UserCode: "ABCD", VerificationURI: "https://idp.example/device", Interval: 5 * time.Second}, nil
}

func (l *scriptedLogin) DevicePoll(context.Context, string) (oidc.Claims, error) {
	return l.claims, l.poll
}

var ada = oidc.Claims{Issuer: "https://idp.example", Subject: "ada", Email: "ada@example.com", EmailVerified: true, Name: "Ada"}

func newAuth(t *testing.T, f *fixture, login oidc.Login) *AuthService {
	t.Helper()
	a, err := NewAuthService(f.cfg, AuthOptions{Tokens: &countingMinter{}, OIDC: login})
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	return a
}

func (f *fixture) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.Reader().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (f *fixture) noAdmin() {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM role_bindings`)
		return err
	})
}

func (f *fixture) tokenRequest(scopes ...string) wire.CreateTokenRequest {
	return wire.CreateTokenRequest{Name: "ci", Scopes: scopes, ExpiresAt: f.clock.Now().Add(24 * time.Hour)}
}

func TestCreatedTokenIsShownOnceAndStoredOnlyAsAHash(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)

	issued, err := a.CreateToken(context.Background(), f.caller(f.admin), f.tokenRequest())
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if !strings.HasPrefix(issued.Value, "smt_") {
		t.Fatalf("token = %q, want an API token", issued.Value)
	}
	stored, err := database.GetAPIToken(context.Background(), f.db.Reader(), issued.Token.ID)
	if err != nil || stored.TokenHash == issued.Value {
		t.Fatalf("stored = %+v, %v; want the hash only", stored, err)
	}
	listed, err := a.ListTokens(context.Background(), f.caller(f.admin))
	if err != nil || len(listed) != 1 || listed[0].ID != issued.Token.ID {
		t.Fatalf("ListTokens = %+v, %v", listed, err)
	}
	for _, e := range f.events("token.created") {
		if strings.Contains(fmt.Sprint(e.Data), issued.Value) {
			t.Fatalf("audit event leaks the token: %v", e.Data)
		}
	}
}

func TestIssuingCredentialsRefusesAnIdempotencyKeyAndStoresNoAnswer(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	keyed := f.caller(f.admin)
	keyed.Idempotency = &Idempotency{Key: "k", Method: "POST", Path: "/tokens", RequestHash: "h"}

	_, err := a.CreateToken(context.Background(), keyed, f.tokenRequest())
	wantError(t, err, smerr.CodeInvalidArgument, "")
	if _, err := a.CreateToken(context.Background(), f.caller(f.admin), f.tokenRequest()); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if n := f.count(`SELECT COUNT(*) FROM api_tokens`); n != 1 {
		t.Errorf("api_tokens = %d, want only the unkeyed one", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM idempotency_records`); n != 0 {
		t.Errorf("idempotency_records = %d, want none", n)
	}
}

func TestTokenScopesOnlyNarrow(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	scoped := f.caller(f.admin)
	scoped.Credential.Scopes = []string{"token.create", "node.read", "service.*"}
	tests := []struct {
		name      string
		requested []string
		want      []string
		reason    smerr.Reason
	}{
		{"covered exactly", []string{"node.read"}, []string{"node.read"}, ""},
		{"covered by a wildcard", []string{"service.restart"}, []string{"service.restart"}, ""},
		{"nothing requested inherits", nil, []string{"token.create", "node.read", "service.*"}, ""},
		{"wider action", []string{"node.reboot"}, nil, smerr.ReasonScopeDenied},
		{"wider wildcard", []string{"node.*"}, nil, smerr.ReasonScopeDenied},
		{"everything", []string{"*"}, nil, smerr.ReasonScopeDenied},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := f.tokenRequest(tt.requested...)
			req.Name = fmt.Sprintf("t%d", i)

			issued, err := a.CreateToken(context.Background(), scoped, req)

			if tt.reason != "" {
				wantError(t, err, smerr.CodePolicyDenied, tt.reason)
				return
			}
			if err != nil || fmt.Sprint(issued.Token.Scopes) != fmt.Sprint(tt.want) {
				t.Fatalf("scopes = %v, %v; want %v", issued.Token.Scopes, err, tt.want)
			}
		})
	}
}

func TestTokenRequestsAreValidatedAtTheBorder(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	now := f.clock.Now()
	tests := map[string]wire.CreateTokenRequest{
		"no name":         {ExpiresAt: now.Add(time.Hour)},
		"no expiry":       {Name: "x"},
		"past expiry":     {Name: "x", ExpiresAt: now.Add(-time.Hour)},
		"over a year":     {Name: "x", ExpiresAt: now.Add(366 * 24 * time.Hour)},
		"unknown scope":   {Name: "x", ExpiresAt: now.Add(time.Hour), Scopes: []string{"nope.nothing"}},
		"control in name": {Name: "a\x1b[31mb", ExpiresAt: now.Add(time.Hour)},
	}
	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := a.CreateToken(context.Background(), f.caller(f.admin), req)

			wantError(t, err, smerr.CodeInvalidArgument, "")
		})
	}
}

func TestCreatingATokenNeedsThePolicyToAllowIt(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)

	_, err := a.CreateToken(context.Background(), f.caller(f.dave), f.tokenRequest())

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	if len(f.events("policy.deny")) == 0 {
		t.Error("the denial was not audited")
	}
}

func TestRevokingATokenIsAuditedOnceAndGuardedForOthersTokens(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	issued, err := a.CreateToken(context.Background(), f.caller(f.admin), f.tokenRequest())
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	wantError(t, a.RevokeToken(context.Background(), f.caller(f.bob), issued.Token.ID), smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
	for i := 0; i < 2; i++ {
		if err := a.RevokeToken(context.Background(), f.caller(f.admin), issued.Token.ID); err != nil {
			t.Fatalf("revoke #%d: %v", i+1, err)
		}
	}

	stored, _ := database.GetAPIToken(context.Background(), f.db.Reader(), issued.Token.ID)
	if stored.RevokedAt == nil {
		t.Error("token not revoked")
	}
	if n := len(f.events("token.revoked")); n != 1 {
		t.Errorf("token.revoked events = %d, want 1", n)
	}
	defer func() {
		if n := len(f.events("token.revoked")); n != 2 {
			t.Errorf("token.revoked events after a foreign revoke = %d, want 2", n)
		}
	}()
	other, _ := a.CreateToken(context.Background(), f.caller(f.admin), withName(f.tokenRequest(), "second"))
	if err := a.Grant(context.Background(), 0, wire.GrantRequest{IdentityID: f.carol, Role: "admin"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := a.RevokeToken(context.Background(), f.caller(f.carol), other.Token.ID); err != nil {
		t.Errorf("admin revoking a foreign token: %v", err)
	}
}

func withName(r wire.CreateTokenRequest, name string) wire.CreateTokenRequest {
	r.Name = name
	return r
}

func TestBootstrapWithoutOIDCCreatesTheAdminOnceAndInvalidatesOlderCodes(t *testing.T) {
	f := newFixture(t)
	f.noAdmin()
	a := newAuth(t, f, nil)
	ctx := context.Background()
	first, err := a.IssueBootstrapCode(ctx, 0)
	if err != nil {
		t.Fatalf("IssueBootstrapCode: %v", err)
	}
	second, err := a.IssueBootstrapCode(ctx, 0)
	if err != nil {
		t.Fatalf("IssueBootstrapCode: %v", err)
	}

	_, err = a.Bootstrap(ctx, nil, wire.BootstrapRequest{Code: first.Code, DisplayName: "Root"})
	wantError(t, err, smerr.CodeUnauthenticated, "")
	_, err = a.Bootstrap(ctx, nil, wire.BootstrapRequest{Code: second.Code})
	wantError(t, err, smerr.CodeInvalidArgument, "")
	done, err := a.Bootstrap(ctx, nil, wire.BootstrapRequest{Code: second.Code, DisplayName: "Root"})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if done.Session == nil || done.APIToken == nil || !strings.HasPrefix(done.Session.Token, "sms_") || !strings.HasPrefix(done.APIToken.Value, "smt_") {
		t.Fatalf("Bootstrapped = %+v, want a session and a first API token", done)
	}
	if n := f.count(`SELECT COUNT(*) FROM role_bindings WHERE identity_id = ?`, done.IdentityID); n != 1 {
		t.Errorf("admin bindings = %d, want 1", n)
	}
	_, err = a.Bootstrap(ctx, nil, wire.BootstrapRequest{Code: second.Code, DisplayName: "Again"})
	wantError(t, err, smerr.CodeUnauthenticated, "")
	_, err = a.IssueBootstrapCode(ctx, 0)
	wantError(t, err, smerr.CodeConflict, "")
	if n := f.count(`SELECT COUNT(*) FROM idempotency_records`); n != 0 {
		t.Errorf("idempotency_records = %d, want none", n)
	}
}

func TestBootstrapRefusesACodeOfAnotherKind(t *testing.T) {
	f := newFixture(t)
	f.noAdmin()
	a := newAuth(t, f, nil)

	_, err := a.Bootstrap(context.Background(), nil, wire.BootstrapRequest{Code: "smt_1", DisplayName: "x"})

	wantError(t, err, smerr.CodeUnauthenticated, "")
}

func TestAFailedExchangeKeepsTheCode(t *testing.T) {
	f := newFixture(t)
	f.noAdmin()
	a := newAuth(t, f, nil)
	code, _ := a.IssueBootstrapCode(context.Background(), 0)

	_, err := a.Bootstrap(context.Background(), nil, wire.BootstrapRequest{Code: code.Code})
	wantError(t, err, smerr.CodeInvalidArgument, "")

	if _, err := a.Bootstrap(context.Background(), nil, wire.BootstrapRequest{Code: code.Code, DisplayName: "Root"}); err != nil {
		t.Fatalf("code was spent by the failed attempt: %v", err)
	}
}

func TestBootstrapWithOIDCBindsTheLoggedInIdentityToAdmin(t *testing.T) {
	f := newFixture(t)
	f.noAdmin()
	login := &scriptedLogin{claims: ada}
	a := newAuth(t, f, login)
	ctx := context.Background()
	code, _ := a.IssueBootstrapCode(ctx, 0)

	_, err := a.Bootstrap(ctx, nil, wire.BootstrapRequest{Code: code.Code})
	wantError(t, err, smerr.CodeUnauthenticated, "")
	session, err := a.OIDCExchange(ctx, wire.OIDCExchangeRequest{Code: "c", State: "s", CodeVerifier: "v", Client: "sm"})
	if err != nil {
		t.Fatalf("OIDCExchange: %v", err)
	}
	by := Caller{ID: session.IdentityID, Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: session.SessionID.String()}}
	done, err := a.Bootstrap(ctx, &by, wire.BootstrapRequest{Code: code.Code})

	if err != nil || done.IdentityID != session.IdentityID || done.Session != nil || done.APIToken != nil {
		t.Fatalf("Bootstrap = %+v, %v; want the logged-in identity bound, no new credentials", done, err)
	}
	roles, _ := database.ListRolesForIdentity(ctx, f.db.Reader(), session.IdentityID)
	if len(roles) != 1 || roles[0].Name != "admin" {
		t.Errorf("roles = %v, want admin", roles)
	}
}

func TestOIDCLoginCreatesAnIdentityWithoutRolesAndReusesIt(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, &scriptedLogin{claims: ada})
	ctx := context.Background()
	req := wire.OIDCExchangeRequest{Code: "c", State: "s", CodeVerifier: "v"}

	first, err := a.OIDCExchange(ctx, req)
	if err != nil {
		t.Fatalf("OIDCExchange: %v", err)
	}
	second, err := a.OIDCExchange(ctx, req)
	if err != nil {
		t.Fatalf("OIDCExchange: %v", err)
	}

	if first.IdentityID != second.IdentityID || first.Token == second.Token {
		t.Errorf("identities %s/%s, tokens equal=%v; want one identity, two sessions", first.IdentityID, second.IdentityID, first.Token == second.Token)
	}
	if roles, _ := database.ListRolesForIdentity(ctx, f.db.Reader(), first.IdentityID); len(roles) != 0 {
		t.Errorf("roles = %v, want none", roles)
	}
	if n := f.count(`SELECT COUNT(*) FROM idempotency_records`); n != 0 {
		t.Errorf("idempotency_records = %d, want none", n)
	}
}

func TestADisabledIdentityCannotLogIn(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, &scriptedLogin{claims: ada})
	session, _ := a.OIDCExchange(context.Background(), wire.OIDCExchangeRequest{Code: "c", State: "s", CodeVerifier: "v"})
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identities SET disabled_at = 1 WHERE id = ?`, session.IdentityID)
		return err
	})

	_, err := a.OIDCExchange(context.Background(), wire.OIDCExchangeRequest{Code: "c", State: "s", CodeVerifier: "v"})

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
}

func TestDeviceLoginReportsPendingThenCompletes(t *testing.T) {
	f := newFixture(t)
	login := &scriptedLogin{claims: ada, poll: oidc.Pending{SlowDown: true}}
	a := newAuth(t, f, login)
	ctx := context.Background()

	started, err := a.DeviceStart(ctx)
	if err != nil || started.TransactionID != "txn" || started.IntervalSeconds != 5 {
		t.Fatalf("DeviceStart = %+v, %v", started, err)
	}
	slow, _ := a.DevicePoll(ctx, wire.DevicePollRequest{TransactionID: "txn"})
	login.poll = oidc.Pending{}
	pending, _ := a.DevicePoll(ctx, wire.DevicePollRequest{TransactionID: "txn"})
	login.poll = nil
	done, err := a.DevicePoll(ctx, wire.DevicePollRequest{TransactionID: "txn", Client: "sm"})

	if slow.Status != wire.DeviceSlowDown || pending.Status != wire.DevicePending {
		t.Errorf("statuses = %s, %s", slow.Status, pending.Status)
	}
	if err != nil || done.Status != wire.DeviceComplete || done.Session == nil {
		t.Fatalf("final poll = %+v, %v", done, err)
	}
}

func TestOIDCEndpointsAreUnavailableWithoutOIDC(t *testing.T) {
	a := newAuth(t, newFixture(t), nil)

	_, err := a.OIDCStart(context.Background(), wire.OIDCStartRequest{RedirectURI: "r", CodeChallenge: "c"})

	wantError(t, err, smerr.CodeNotFound, "")
}

func TestLogoutRevokesTheSessionOnly(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, &scriptedLogin{claims: ada})
	ctx := context.Background()
	session, _ := a.OIDCExchange(ctx, wire.OIDCExchangeRequest{Code: "c", State: "s", CodeVerifier: "v"})
	by := Caller{ID: session.IdentityID, Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: session.SessionID.String()}}

	wantError(t, a.Logout(ctx, f.caller(f.admin)), smerr.CodeInvalidArgument, "")
	if err := a.Logout(ctx, by); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	row, _ := database.GetAuthSession(ctx, f.db.Reader(), session.SessionID)
	if row.RevokedAt == nil {
		t.Error("session not revoked")
	}
	if n := len(f.events("session.revoked")); n != 1 {
		t.Errorf("session.revoked events = %d, want 1", n)
	}
}

func TestGrantBindsARoleAndIsQuietWhenAlreadyGranted(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := a.Grant(ctx, 0, wire.GrantRequest{IdentityID: f.dave, Role: "admin"}); err != nil {
			t.Fatalf("Grant #%d: %v", i+1, err)
		}
	}

	roles, _ := database.ListRolesForIdentity(ctx, f.db.Reader(), f.dave)
	if len(roles) != 1 {
		t.Errorf("roles = %v, want admin once", roles)
	}
	if n := len(f.events("role_binding.created")); n != 1 {
		t.Errorf("role_binding.created events = %d, want 1", n)
	}
	wantError(t, a.Grant(ctx, 0, wire.GrantRequest{IdentityID: f.dave, Role: "nope"}), smerr.CodeNotFound, "")
	wantError(t, a.Grant(ctx, 0, wire.GrantRequest{IdentityID: "01970000-0000-7000-8000-00000000dead", Role: "admin"}), smerr.CodeNotFound, "")
}

func TestScopeCovers(t *testing.T) {
	tests := []struct {
		parent, child string
		want          bool
	}{
		{"*", "node.read", true},
		{"*", "*", true},
		{"node.read", "node.read", true},
		{"node.*", "node.read", true},
		{"node.*", "node.*", true},
		{"node.read", "node.*", false},
		{"node.*", "service.read", false},
		{"node.*", "*", false},
		{"node.*", "node.read.deep", false},
		{"node", "node.read", false},
	}
	for _, tt := range tests {
		if got := scopeCovers(tt.parent, tt.child); got != tt.want {
			t.Errorf("scopeCovers(%q, %q) = %v, want %v", tt.parent, tt.child, got, tt.want)
		}
	}
}
