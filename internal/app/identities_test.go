package app

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

// operatorsManageIdentities lets operators hold identity.write by a custom
// rule, which must still not make them administrators of identities.
func operatorsManageIdentities(c *Config) {
	text := string(policy.DefaultYAML()) + `  - name: test-operators-manage-identities
    subjects: ["role:operator"]
    allow: ["identity.write"]
`
	p, err := policy.Parse([]byte(text))
	if err != nil {
		panic(err)
	}
	c.Policy = p
}

// apiToken stores an API token of identity that expires in ttl.
func (f *fixture) apiToken(identity domain.ID, name string, ttl time.Duration) database.APIToken {
	f.t.Helper()
	row := database.APIToken{
		ID: f.ids.NewID(), IdentityID: identity, Name: name, TokenHash: "hash-" + name + "-" + identity.String(),
		CreatedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(ttl),
	}
	f.inTx(func(ctx context.Context, tx *database.Tx) error { return database.CreateAPIToken(ctx, tx, row) })
	return row
}

func (f *fixture) session(identity domain.ID) database.AuthSession {
	f.t.Helper()
	row := database.AuthSession{
		ID: f.ids.NewID(), IdentityID: identity, TokenHash: "hash-session-" + identity.String(), Client: "sm/test",
		Origin: database.OriginOIDC, CreatedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(time.Hour),
	}
	f.inTx(func(ctx context.Context, tx *database.Tx) error { return database.CreateAuthSession(ctx, tx, row) })
	return row
}

// secondAdmin is an enabled admin besides f.admin.
func (f *fixture) secondAdmin() domain.ID {
	f.t.Helper()
	var id domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		id = f.identity(ctx, tx, "root-2", domain.ActorHuman, f.role(ctx, tx, "admin"))
		return nil
	})
	return id
}

func (f *fixture) rolesOf(id domain.ID) []string {
	f.t.Helper()
	roles, err := database.ListRolesForIdentity(context.Background(), f.db.Reader(), id)
	if err != nil {
		f.t.Fatalf("ListRolesForIdentity: %v", err)
	}
	return roleNames(roles)
}

func (f *fixture) tokenRow(id domain.ID) database.APIToken {
	f.t.Helper()
	row, err := database.GetAPIToken(context.Background(), f.db.Reader(), id)
	if err != nil {
		f.t.Fatalf("GetAPIToken: %v", err)
	}
	return row
}

func TestAnAdminListsEveryIdentityWithItsRolesAndWhetherItIsDisabled(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()
	if _, err := a.DisableIdentity(ctx, f.caller(f.admin), f.alice); err != nil {
		t.Fatalf("DisableIdentity: %v", err)
	}

	page, err := a.ListIdentities(ctx, f.caller(f.admin), wire.PageQuery{})
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	byID := map[domain.ID]wire.Identity{}
	for _, i := range page.Items {
		byID[i.ID] = i
	}
	if len(page.Items) != 5 {
		t.Errorf("listed %d identities, want the five of the fixture", len(page.Items))
	}
	if got := byID[f.admin]; !slices.Equal(got.Roles, []string{"admin"}) || got.DisabledAt != nil {
		t.Errorf("admin = %+v, want the admin role and enabled", got)
	}
	if got := byID[f.alice]; got.DisabledAt == nil || len(got.Roles) != 0 {
		t.Errorf("disabled alice = %+v, want disabled and without roles", got)
	}
	if got := byID[f.dave]; got.Roles == nil || len(got.Roles) != 0 {
		t.Errorf("dave roles = %#v, want an empty list", got.Roles)
	}
}

func TestIdentitiesArePagedByACursor(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()

	first, err := a.ListIdentities(ctx, f.caller(f.admin), wire.PageQuery{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %+v, %v; want two items and a cursor", first, err)
	}
	rest, err := a.ListIdentities(ctx, f.caller(f.admin), wire.PageQuery{Limit: 10, Cursor: first.NextCursor})
	if err != nil || len(rest.Items) != 3 || rest.NextCursor != "" {
		t.Fatalf("second page = %+v, %v; want the other three and no cursor", rest, err)
	}
	if rest.Items[0].ID == first.Items[0].ID || rest.Items[0].ID == first.Items[1].ID {
		t.Errorf("the second page repeats the first: %+v", rest.Items[0])
	}
}

func TestAnAdminListsTheTokensOfAnotherIdentityRevokedOnesIncluded(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()
	live := f.apiToken(f.alice, "ci", time.Hour)
	revoked := f.apiToken(f.alice, "old", time.Hour)
	f.apiToken(f.bob, "bobs", time.Hour)
	if err := a.RevokeToken(ctx, f.caller(f.admin), revoked.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	tokens, err := a.ListIdentityTokens(ctx, f.caller(f.admin), f.alice)
	if err != nil {
		t.Fatalf("ListIdentityTokens: %v", err)
	}
	if len(tokens) != 2 || tokens[0].ID != live.ID || tokens[1].ID != revoked.ID {
		t.Fatalf("tokens = %+v, want alice's two", tokens)
	}
	for _, tok := range tokens {
		if tok.IdentityID != f.alice {
			t.Errorf("token %s belongs to %s, want alice", tok.ID, tok.IdentityID)
		}
	}
	if tokens[0].RevokedAt != nil || tokens[1].RevokedAt == nil {
		t.Errorf("revoked_at = %v and %v, want none and set", tokens[0].RevokedAt, tokens[1].RevokedAt)
	}
}

func TestOnlyAnAdminMayListIdentitiesTheirTokensOrDisableAndEnableThem(t *testing.T) {
	f := newFixture(t, operatorsManageIdentities)
	a := newAuth(t, f, nil)
	ctx := context.Background()
	var viewer domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		viewer = f.identity(ctx, tx, "vera", domain.ActorHuman, f.role(ctx, tx, "viewer"))
		return nil
	})
	f.apiToken(f.bob, "bobs", time.Hour)
	callers := map[string]domain.ID{
		"a viewer": viewer, "an operator": f.alice, "an identity without roles": f.dave,
		"an operator granted identity.write by a custom rule": f.alice,
	}

	for who, id := range callers {
		by := f.caller(id)
		if _, err := a.ListIdentities(ctx, by, wire.PageQuery{}); smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s listing identities: %v, want POLICY_DENIED", who, err)
		}
		if _, err := a.ListIdentityTokens(ctx, by, f.bob); smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s listing another's tokens: %v, want POLICY_DENIED", who, err)
		}
		if _, err := a.DisableIdentity(ctx, by, f.bob); smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s disabling: %v, want POLICY_DENIED", who, err)
		}
		if _, err := a.EnableIdentity(ctx, by, f.bob); smerr.CodeOf(err) != smerr.CodePolicyDenied {
			t.Errorf("%s enabling: %v, want POLICY_DENIED", who, err)
		}
	}

	if got := f.rolesOf(f.bob); !slices.Equal(got, []string{"operator"}) {
		t.Errorf("bob roles = %v, want them untouched", got)
	}
	if denied := f.events("policy.deny"); len(denied) == 0 {
		t.Error("a refused disable left no policy decision in the audit trail")
	}
}

func TestDisablingAnIdentityRevokesItsCredentialsAndRemovesItsRolesInOneStep(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()
	live := f.apiToken(f.alice, "ci", 24*time.Hour)
	short := f.apiToken(f.alice, "short", time.Hour)
	f.clock.Advance(2 * time.Hour) // short has lapsed; its row is still there
	session := f.session(f.alice)
	bobs := f.apiToken(f.bob, "bobs", 24*time.Hour)

	disabled, err := a.DisableIdentity(ctx, f.caller(f.admin), f.alice)
	if err != nil {
		t.Fatalf("DisableIdentity: %v", err)
	}
	if disabled.ID != f.alice || disabled.DisabledAt == nil {
		t.Errorf("answer = %+v, want alice, disabled", disabled)
	}
	for _, tok := range []database.APIToken{live, short} {
		if f.tokenRow(tok.ID).RevokedAt == nil {
			t.Errorf("token %q was not revoked", tok.Name)
		}
	}
	if got, _ := database.GetAuthSession(ctx, f.db.Reader(), session.ID); got.RevokedAt == nil {
		t.Error("the session was not revoked")
	}
	if f.tokenRow(bobs.ID).RevokedAt != nil {
		t.Error("another identity's token was revoked")
	}
	if got := f.rolesOf(f.alice); len(got) != 0 {
		t.Errorf("alice roles = %v, want none", got)
	}
	identity, _ := database.GetIdentity(ctx, f.db.Reader(), f.alice)
	if identity.DisabledAt == nil {
		t.Error("disabled_at is not set")
	}
	events := f.events("identity.disabled")
	if len(events) != 1 || events[0].ActorID != f.admin || events[0].ResourceID != f.alice {
		t.Fatalf("identity.disabled events = %+v, want one by the admin about alice", events)
	}
	if fmt.Sprint(events[0].Data["revoked"]) != "3" {
		t.Errorf("event data = %+v, want 3 credentials revoked", events[0].Data)
	}
}

func TestADisabledIdentityCanNoLongerActEvenWithAnUnrevokedCredential(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()
	if _, err := a.DisableIdentity(ctx, f.caller(f.admin), f.alice); err != nil {
		t.Fatalf("DisableIdentity: %v", err)
	}

	_, err := a.ListTokens(ctx, f.caller(f.alice))

	wantError(t, err, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
}

func TestDisablingADisabledIdentitySucceedsAndAuditsOnce(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()
	for range 2 {
		if _, err := a.DisableIdentity(ctx, f.caller(f.admin), f.alice); err != nil {
			t.Fatalf("DisableIdentity: %v", err)
		}
	}

	if got := len(f.events("identity.disabled")); got != 1 {
		t.Errorf("identity.disabled events = %d, want 1", got)
	}
}

func TestTheLastEnabledAdminCannotBeDisabledNotEvenByItself(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	token := f.apiToken(f.admin, "ci", time.Hour)

	_, err := a.DisableIdentity(context.Background(), f.caller(f.admin), f.admin)

	wantError(t, err, smerr.CodeConflict, "")
	if f.tokenRow(token.ID).RevokedAt != nil {
		t.Error("a refused disable revoked the admin's token")
	}
	if got := f.rolesOf(f.admin); !slices.Equal(got, []string{"admin"}) {
		t.Errorf("admin roles = %v, want them kept", got)
	}
	if got := len(f.events("identity.disabled")); got != 0 {
		t.Errorf("identity.disabled events = %d, want none", got)
	}
}

func TestAnAdminMayDisableAnotherAdminWhileOneRemains(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	second := f.secondAdmin()

	_, err := a.DisableIdentity(context.Background(), f.caller(f.admin), second)
	if err != nil {
		t.Fatalf("DisableIdentity: %v", err)
	}
	if n := f.count(`SELECT COUNT(*) FROM identities i JOIN role_bindings b ON b.identity_id = i.id JOIN roles r ON r.id = b.role_id
		WHERE r.name = 'admin' AND i.disabled_at IS NULL`); n != 1 {
		t.Errorf("enabled admins = %d, want 1", n)
	}
}

func TestTwoAdminsDisablingEachOtherAtOnceLeaveExactlyOneEnabled(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	second := f.secondAdmin()
	pairs := [][2]domain.ID{{f.admin, second}, {second, f.admin}}
	errs := make([]error, len(pairs))

	var wg sync.WaitGroup
	for i, p := range pairs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = a.DisableIdentity(context.Background(), f.caller(p[0]), p[1])
		}()
	}
	wg.Wait()

	if succeeded := countNil(errs); succeeded != 1 {
		t.Fatalf("results = %v, want exactly one disable to succeed", errs)
	}
	if n := f.count(`SELECT COUNT(*) FROM identities i JOIN role_bindings b ON b.identity_id = i.id JOIN roles r ON r.id = b.role_id
		WHERE r.name = 'admin' AND i.disabled_at IS NULL`); n != 1 {
		t.Errorf("enabled admins = %d, want 1", n)
	}
}

func countNil(errs []error) int {
	n := 0
	for _, err := range errs {
		if err == nil {
			n++
		}
	}
	return n
}

func TestTheSystemAndMCPIdentitiesAreNotDisabledHere(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	var system, agent domain.ID
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		system = f.identity(ctx, tx, "daemon", domain.ActorSystem, "")
		agent = f.identity(ctx, tx, "claude", domain.ActorMCP, "")
		return nil
	})

	for name, id := range map[string]domain.ID{"system": system, "mcp": agent} {
		_, err := a.DisableIdentity(context.Background(), f.caller(f.admin), id)
		wantError(t, err, smerr.CodeInvalidArgument, "")
		_, err = a.EnableIdentity(context.Background(), f.caller(f.admin), id)
		wantError(t, err, smerr.CodeInvalidArgument, "")
		if got, _ := database.GetIdentity(context.Background(), f.db.Reader(), id); got.DisabledAt != nil {
			t.Errorf("%s identity was disabled", name)
		}
	}
}

func TestDisablingAnUnknownIdentityIsNotFound(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)

	_, err := a.DisableIdentity(context.Background(), f.caller(f.admin), "no-such-identity")

	wantError(t, err, smerr.CodeNotFound, "")
}

func TestEnablingAnIdentityRestoresNeitherItsRolesNorItsCredentials(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()
	old := f.apiToken(f.alice, "ci", 24*time.Hour)
	if _, err := a.DisableIdentity(ctx, f.caller(f.admin), f.alice); err != nil {
		t.Fatalf("DisableIdentity: %v", err)
	}

	enabled, err := a.EnableIdentity(ctx, f.caller(f.admin), f.alice)
	if err != nil {
		t.Fatalf("EnableIdentity: %v", err)
	}
	if enabled.DisabledAt != nil {
		t.Errorf("answer = %+v, want enabled", enabled)
	}
	if f.tokenRow(old.ID).RevokedAt == nil {
		t.Error("enabling brought a revoked token back")
	}
	if got := f.rolesOf(f.alice); len(got) != 0 {
		t.Errorf("alice roles = %v, want none until they are granted again", got)
	}
	if got := len(f.events("identity.enabled")); got != 1 {
		t.Errorf("identity.enabled events = %d, want 1", got)
	}
	if _, err := a.EnableIdentity(ctx, f.caller(f.admin), f.alice); err != nil || len(f.events("identity.enabled")) != 1 {
		t.Errorf("enabling an enabled identity: %v, %d events; want success and still one event", err, len(f.events("identity.enabled")))
	}
}

func TestADisableEnableRegrantCycleLeavesTheOldCredentialsRevoked(t *testing.T) {
	f := newFixture(t)
	a := newAuth(t, f, nil)
	ctx := context.Background()
	old := f.apiToken(f.alice, "ci", 24*time.Hour)
	if _, err := a.DisableIdentity(ctx, f.caller(f.admin), f.alice); err != nil {
		t.Fatalf("DisableIdentity: %v", err)
	}
	if _, err := a.EnableIdentity(ctx, f.caller(f.admin), f.alice); err != nil {
		t.Fatalf("EnableIdentity: %v", err)
	}

	if err := a.Grant(ctx, 0, wire.GrantRequest{IdentityID: f.alice, Role: "operator"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	if got := f.rolesOf(f.alice); !slices.Equal(got, []string{"operator"}) {
		t.Errorf("alice roles = %v, want operator after the grant", got)
	}
	if f.tokenRow(old.ID).RevokedAt == nil {
		t.Error("the grant revived a token from before the disable")
	}
}

func TestADisabledAdminDoesNotKeepBootstrapClosed(t *testing.T) {
	f := newFixture(t)
	f.noAdmin()
	a := newAuth(t, f, nil)
	ctx := context.Background()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		id := f.identity(ctx, tx, "gone", domain.ActorHuman, f.role(ctx, tx, "admin"))
		at := f.clock.Now()
		return database.SetIdentityDisabled(ctx, tx, id, &at)
	})
	code, err := a.IssueBootstrapCode(ctx, 0, false)
	if err != nil {
		t.Fatalf("IssueBootstrapCode: %v", err)
	}

	if _, err := a.Bootstrap(ctx, nil, wire.BootstrapRequest{Code: code.Code, DisplayName: "Fresh"}); err != nil {
		t.Errorf("Bootstrap with only a disabled admin bound: %v, want it to open", err)
	}
}
