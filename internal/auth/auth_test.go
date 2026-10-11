package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// world is a migrated database, the real credential store wired into the app
// services and the job engine, one admin and one node that can be probed.
type world struct {
	t        *testing.T
	dir      string
	db       *database.DB
	clock    *domaintest.FakeClock
	ids      *domaintest.SequentialIDs
	cfg      app.Config
	auth     *app.AuthService
	plans    *app.Plans
	store    *jobs.Store
	resolver auth.DBResolver
	admin    domain.ID
	node     domain.Node
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	w := &world{t: t, dir: t.TempDir(), clock: domaintest.NewFakeClock(epoch), ids: domaintest.NewSequentialIDs()}
	var err error
	w.db, err = database.Open(ctx, filepath.Join(w.dir, "sm.db"), database.Options{Clock: w.clock})
	must(t, err, "Open")
	t.Cleanup(func() { _ = w.db.Close() })
	must(t, w.db.Migrate(ctx), "Migrate")
	pol, err := policy.Default()
	must(t, err, "policy.Default")
	w.cfg = app.Config{DB: w.db, Clock: w.clock, IDs: w.ids, Policy: pol, Credentials: auth.CredentialStatus{DB: w.db, Clock: w.clock}}
	w.seed()
	w.auth, err = app.NewAuthService(w.cfg, app.AuthOptions{Tokens: auth.Minter{}})
	must(t, err, "NewAuthService")
	reval, err := app.NewRevalidator(w.cfg)
	must(t, err, "NewRevalidator")
	w.store, err = jobs.NewStore(jobs.Config{DB: w.db, Clock: w.clock, IDs: w.ids, Revalidator: reval, LockPlanner: app.LockPlanner{}})
	must(t, err, "jobs.NewStore")
	w.plans, err = app.NewPlans(w.cfg, w.store)
	must(t, err, "NewPlans")
	w.resolver = auth.DBResolver{DB: w.db, Clock: w.clock}
	return w
}

func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func (w *world) seed() {
	w.t.Helper()
	err := w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		now := w.clock.Now()
		provider, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: w.ids.NewID(), Type: "ssh", Name: "ssh-hosts", Origin: domain.ProviderAPI, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		public, _, _ := ed25519.GenerateKey(rand.Reader)
		key, _ := cryptossh.NewPublicKey(public)
		w.node, err = database.CreateNode(ctx, tx, domain.Node{
			ID: w.ids.NewID(), ProviderID: provider.ID, NativeID: "web-1", Name: "web-1", Kind: "ssh",
			ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
			Endpoint: domain.NodeEndpoint{
				Host: "10.0.0.5", Port: 22, User: "supermgmt", AdminUser: "admin", AdminCredentialRef: "ssh-agent://default",
				HostPublicKey: strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key))),
			},
			CredentialRef: "secret://ssh/default", CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		err = database.SetNodeCapability(ctx, tx, w.node.ID, database.NodeCapability{Capability: "node.read", Available: true, CheckedAt: now})
		if err != nil {
			return err
		}
		w.admin = w.ids.NewID()
		err = database.CreateIdentity(ctx, tx, database.Identity{ID: w.admin, ActorType: domain.ActorHuman, Subject: "root", CreatedAt: now})
		if err != nil {
			return err
		}
		role, err := database.GetRoleByName(ctx, tx, "admin")
		if err != nil {
			return err
		}
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: w.ids.NewID(), IdentityID: w.admin, RoleID: role.ID, CreatedAt: now})
	})
	must(w.t, err, "seed")
}

// viaSocket is the admin as the local socket sees them.
func (w *world) viaSocket() app.Caller {
	return app.Caller{ID: w.admin, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}}
}

func (w *world) issue(scopes ...string) wire.TokenIssued {
	w.t.Helper()
	req := wire.CreateTokenRequest{Name: "token-" + w.ids.NewID().String(), Scopes: scopes, ExpiresAt: w.clock.Now().Add(time.Hour)}
	issued, err := w.auth.CreateToken(context.Background(), w.viaSocket(), req)
	must(w.t, err, "CreateToken")
	return issued
}

func (w *world) resolve(token string) (app.Caller, error) {
	return w.resolver.Resolve(context.Background(), token)
}

func (w *world) wantCode(err error, code smerr.Code, reason smerr.Reason) {
	w.t.Helper()
	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Code != code || typed.Reason != reason {
		w.t.Fatalf("err = %v, want %s/%s", err, code, reason)
	}
}

func (w *world) submitProbe(by app.Caller) jobs.Job {
	w.t.Helper()
	created, err := w.plans.Create(context.Background(), by, app.PlanRequest{
		Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: w.node.ID},
	})
	must(w.t, err, "Create plan")
	sub, err := w.plans.Submit(context.Background(), by, created.Record.ID, created.Record.PlanHash)
	must(w.t, err, "Submit")
	return sub.Job
}

func (w *world) claimFails(id domain.ID, code smerr.Code, reason smerr.Reason) {
	w.t.Helper()
	if _, ok, err := w.store.Claim(context.Background(), "worker"); ok || err != nil {
		w.t.Fatalf("Claim = %v, %v; want the job to fail", ok, err)
	}
	job, err := w.store.Get(context.Background(), w.db.Reader(), id)
	must(w.t, err, "Get job")
	if job.State != domain.JobFailed || job.Error == nil || job.Error.Code != code || job.Error.Reason != reason {
		w.t.Fatalf("job = %s %+v, want failed %s/%s", job.State, job.Error, code, reason)
	}
}

func TestMintedTokensHaveTheirKindAndHashToWhatIsStored(t *testing.T) {
	for _, kind := range []auth.Kind{auth.KindSession, auth.KindAPIToken, auth.KindBootstrap, auth.KindJoin} {
		secret, hash, err := auth.Mint(kind)
		if err != nil {
			t.Fatalf("Mint(%c): %v", kind, err)
		}
		token := secret.Reveal()
		gotKind, gotHash, err := auth.Hash(token)

		if err != nil || gotKind != kind || gotHash != hash {
			t.Errorf("Hash(%q) = %c, %q, %v; want %c, %q", token, gotKind, gotHash, err, kind, hash)
		}
		if !strings.HasPrefix(token, "sm"+string(rune(kind))+"_") || len(token) != len("sms_")+43 {
			t.Errorf("token %q has the wrong shape", token)
		}
		if hash == token {
			t.Errorf("hash is the token")
		}
	}
}

func TestMintedTokensAreDistinctAndTheKindIsChecked(t *testing.T) {
	a, _, _ := auth.Mint(auth.KindSession)
	b, _, _ := auth.Mint(auth.KindSession)
	if a == b {
		t.Error("two tokens are equal")
	}
	if _, _, err := auth.Mint(auth.Kind('x')); err == nil {
		t.Error("an unknown kind was minted")
	}
}

func TestHashRejectsMalformedTokensWithoutALookup(t *testing.T) {
	good, _, _ := auth.Mint(auth.KindAPIToken)
	body := strings.TrimPrefix(good.Reveal(), "smt_")
	for name, token := range map[string]string{
		"empty":         "",
		"no prefix":     body,
		"unknown kind":  "smx_" + body,
		"no separator":  "smt-" + body,
		"short body":    "smt_" + body[:20],
		"long body":     "smt_" + body + "A",
		"not base64url": "smt_" + strings.Repeat("!", 43),
		"padded":        "smt_" + body + "=",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := auth.Hash(token)

			if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
				t.Fatalf("err = %v, want UNAUTHENTICATED", err)
			}
		})
	}
}

func TestMinterAgreesWithTheKindBytesOfTheAppServices(t *testing.T) {
	for kind, want := range map[byte]auth.Kind{app.SessionTokenKind: auth.KindSession, app.APITokenKind: auth.KindAPIToken, app.BootstrapCodeKind: auth.KindBootstrap} {
		if auth.Kind(kind) != want {
			t.Errorf("app kind %c != auth kind %c", kind, want)
		}
	}
}

func TestARevokedTokenFailsTheNextRequest(t *testing.T) {
	w := newWorld(t)
	issued := w.issue()
	if _, err := w.resolve(issued.Value); err != nil {
		t.Fatalf("Resolve before revoke: %v", err)
	}

	must(t, w.auth.RevokeToken(context.Background(), w.viaSocket(), issued.Token.ID), "RevokeToken")

	_, err := w.resolve(issued.Value)
	w.wantCode(err, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestAJobSubmittedBeforeARevocationFailsAtClaim(t *testing.T) {
	w := newWorld(t)
	issued := w.issue()
	by, err := w.resolve(issued.Value)
	must(t, err, "Resolve")
	job := w.submitProbe(by)

	must(t, w.auth.RevokeToken(context.Background(), w.viaSocket(), issued.Token.ID), "RevokeToken")

	w.claimFails(job.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestAnExpiredAPITokenFailsTheClaimButAnExpiredSessionDoesNot(t *testing.T) {
	w := newWorld(t)
	issued := w.issue()
	apiCaller, err := w.resolve(issued.Value)
	must(t, err, "Resolve")
	apiJob := w.submitProbe(apiCaller)
	sessionCaller := w.sessionFor(w.admin, "session-hash")
	sessionJob := w.submitProbe(sessionCaller)

	w.clock.Advance(2 * time.Hour)

	for i := 0; i < 2; i++ {
		if _, _, err := w.store.Claim(context.Background(), "worker"); err != nil {
			t.Fatalf("Claim: %v", err)
		}
	}

	failed, err := w.store.Get(context.Background(), w.db.Reader(), apiJob.ID)
	must(t, err, "Get api job")
	if failed.State != domain.JobFailed || failed.Error == nil || failed.Error.Reason != smerr.ReasonCredentialExpired {
		t.Errorf("api job = %s %+v, want failed CREDENTIAL_EXPIRED", failed.State, failed.Error)
	}
	ran, err := w.store.Get(context.Background(), w.db.Reader(), sessionJob.ID)
	must(t, err, "Get session job")
	if ran.State != domain.JobRunning {
		t.Errorf("session job = %s, want running", ran.State)
	}
}

func TestARevokedSessionFailsTheClaimEvenAfterItExpired(t *testing.T) {
	w := newWorld(t)
	caller := w.sessionFor(w.admin, "session-hash")
	job := w.submitProbe(caller)

	must(t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.RevokeAuthSession(ctx, tx, domain.ID(caller.Credential.ID), w.clock.Now())
		return err
	}), "revoke")
	w.clock.Advance(2 * time.Hour)

	w.claimFails(job.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

// sessionFor stores a session that lives one hour and returns its caller.
func (w *world) sessionFor(identity domain.ID, hash string) app.Caller {
	w.t.Helper()
	s := database.AuthSession{
		ID: w.ids.NewID(), IdentityID: identity, TokenHash: hash, Origin: database.OriginOIDC,
		CreatedAt: w.clock.Now(), ExpiresAt: w.clock.Now().Add(time.Hour),
	}
	must(w.t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.CreateAuthSession(ctx, tx, s)
	}), "CreateAuthSession")
	return app.Caller{ID: identity, Credential: domain.CredentialContext{Kind: domain.CredentialSession, ID: s.ID.String()}}
}

func TestStatusDistinguishesActiveExpiredAndRevoked(t *testing.T) {
	w := newWorld(t)
	live := w.issue()
	dead := w.issue()
	must(t, w.auth.RevokeToken(context.Background(), w.viaSocket(), dead.Token.ID), "RevokeToken")
	status := auth.CredentialStatus{DB: w.db, Clock: w.clock}
	of := func(id domain.ID) app.CredentialState {
		state, err := status.Status(context.Background(), domain.CredentialContext{Kind: domain.CredentialAPIToken, ID: id.String()})
		must(t, err, "Status")
		return state
	}

	if got := of(live.Token.ID); got != app.CredentialActive {
		t.Errorf("live = %s", got)
	}
	if got := of(dead.Token.ID); got != app.CredentialRevoked {
		t.Errorf("revoked = %s", got)
	}
	w.clock.Advance(2 * time.Hour)
	if got := of(live.Token.ID); got != app.CredentialExpired {
		t.Errorf("expired = %s", got)
	}
	if got := of(dead.Token.ID); got != app.CredentialRevoked {
		t.Errorf("revoked and expired = %s, want revoked to win", got)
	}
	if got := of("01970000-0000-7000-8000-00000000dead"); got != app.CredentialRevoked {
		t.Errorf("unknown = %s, want fail closed", got)
	}
}

func TestStatusKeepsTheLocalSocketActiveAndRefusesOtherKinds(t *testing.T) {
	status := auth.CredentialStatus{DB: newWorld(t).db}

	state, err := status.Status(context.Background(), domain.CredentialContext{Kind: domain.CredentialLocalSocket})
	if err != nil || state != app.CredentialActive {
		t.Fatalf("local socket = %s, %v", state, err)
	}
	for _, kind := range []domain.CredentialKind{domain.CredentialMCPToken, domain.CredentialOAuthAccessToken, domain.CredentialGitHubOIDC} {
		_, err := status.Status(context.Background(), domain.CredentialContext{Kind: kind})
		if smerr.CodeOf(err) != smerr.CodeUnauthenticated {
			t.Errorf("%s: err = %v, want UNAUTHENTICATED", kind, err)
		}
	}
}

func TestResolveDistinguishesExpiredFromRevokedAndUnknown(t *testing.T) {
	w := newWorld(t)
	issued := w.issue()
	unknown, _, _ := auth.Mint(auth.KindAPIToken)
	wrongKind, _, _ := auth.Mint(auth.KindBootstrap)

	_, err := w.resolve(unknown.Reveal())
	w.wantCode(err, smerr.CodeUnauthenticated, "")
	_, err = w.resolve(wrongKind.Reveal())
	w.wantCode(err, smerr.CodeUnauthenticated, "")
	_, err = w.resolve("garbage")
	w.wantCode(err, smerr.CodeUnauthenticated, "")
	w.clock.Advance(2 * time.Hour)
	_, err = w.resolve(issued.Value)
	w.wantCode(err, smerr.CodeUnauthenticated, smerr.ReasonCredentialExpired)
}

func TestResolveRefusesADisabledIdentity(t *testing.T) {
	w := newWorld(t)
	issued := w.issue()
	must(t, w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identities SET disabled_at = 1 WHERE id = ?`, w.admin)
		return err
	}), "disable")

	_, err := w.resolve(issued.Value)

	w.wantCode(err, smerr.CodeUnauthenticated, "")
}

func TestScopesNeverWidenFromCreationToUse(t *testing.T) {
	w := newWorld(t)
	scoped := w.issue("token.create", "node.read")
	by, err := w.resolve(scoped.Value)
	must(t, err, "Resolve")

	if fmt.Sprint(by.Credential.Scopes) != "[token.create node.read]" {
		t.Fatalf("scopes = %v", by.Credential.Scopes)
	}
	_, err = w.auth.CreateToken(context.Background(), by, wire.CreateTokenRequest{Name: "wider", Scopes: []string{"node.reboot"}, ExpiresAt: w.clock.Now().Add(time.Hour)})
	w.wantCode(err, smerr.CodePolicyDenied, smerr.ReasonScopeDenied)
	child, err := w.auth.CreateToken(context.Background(), by, wire.CreateTokenRequest{Name: "same", ExpiresAt: w.clock.Now().Add(time.Hour)})
	must(t, err, "CreateToken inheriting")
	if fmt.Sprint(child.Token.Scopes) != "[token.create node.read]" {
		t.Errorf("child scopes = %v, want the creator's", child.Token.Scopes)
	}
	// An action outside the scopes is denied by policy even for an admin.
	actor := domain.Actor{ID: w.admin, Type: domain.ActorHuman, Roles: []string{"admin"}, Credential: by.Credential}
	res := w.cfg.Policy.Evaluate(policy.Request{Actor: actor, Action: "node.reboot", Targets: []policy.Target{{Ref: domain.ResourceRef{Type: domain.ResourceNode, ID: w.node.ID}}}})
	if res.Decision == policy.DecisionAllow {
		t.Error("a scoped credential was allowed an action outside its scopes")
	}
}

func TestIssuingCredentialsLeavesNoIdempotencyRecord(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.issue()
	w.issue()

	var n int
	must(t, w.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM idempotency_records`).Scan(&n), "count")
	if n != 0 {
		t.Errorf("idempotency_records = %d, want none", n)
	}
}

func TestNoPlaintextCredentialReachesTheDatabaseOrTheWAL(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	token := w.issue()
	bootstrapDB := newWorld(t)
	must(t, deleteBindings(bootstrapDB), "clear bindings")
	code, err := bootstrapDB.auth.IssueBootstrapCode(ctx, 0)
	must(t, err, "IssueBootstrapCode")
	done, err := bootstrapDB.auth.Bootstrap(ctx, nil, wire.BootstrapRequest{Code: code.Code, DisplayName: "Root"})
	must(t, err, "Bootstrap")

	for _, c := range []struct {
		w       *world
		secrets []string
	}{
		{w, []string{token.Value}},
		{bootstrapDB, []string{code.Code, done.Session.Token, done.APIToken.Value}},
	} {
		dump := c.w.dumpEverything()
		for _, secret := range c.secrets {
			body := secret[len("smt_"):]
			if strings.Contains(dump, secret) || strings.Contains(dump, body) {
				t.Errorf("a plaintext credential (%.8s...) is stored", secret)
			}
		}
		if !strings.Contains(dump, "token_hash") && !strings.Contains(dump, "sessions") {
			t.Error("the dump does not contain the schema; the scan proves nothing")
		}
	}
}

func deleteBindings(w *world) error {
	return w.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM role_bindings`)
		return err
	})
}

// dumpEverything is the text of every table plus the raw bytes of the database
// and its write-ahead log.
func (w *world) dumpEverything() string {
	w.t.Helper()
	var out strings.Builder
	ctx := context.Background()
	tables, err := w.db.Reader().QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	must(w.t, err, "list tables")
	var names []string
	for tables.Next() {
		var name string
		must(w.t, tables.Scan(&name), "scan")
		names = append(names, name)
	}
	must(w.t, tables.Err(), "tables")
	tables.Close()
	for _, name := range names {
		rows, err := w.db.Reader().QueryContext(ctx, `SELECT * FROM "`+name+`"`)
		must(w.t, err, "select "+name)
		columns, _ := rows.Columns()
		out.WriteString(name + " " + strings.Join(columns, " ") + "\n")
		for rows.Next() {
			values := make([]any, len(columns))
			holders := make([]any, len(columns))
			for i := range values {
				holders[i] = &values[i]
			}
			must(w.t, rows.Scan(holders...), "scan row")
			for _, v := range values {
				if b, ok := v.([]byte); ok {
					v = string(b)
				}
				fmt.Fprintf(&out, "%v|", v)
			}
			out.WriteByte('\n')
		}
		must(w.t, rows.Err(), "rows")
		rows.Close()
	}
	for _, suffix := range []string{"", "-wal"} {
		raw, err := os.ReadFile(filepath.Join(w.dir, "sm.db"+suffix))
		if err == nil {
			out.Write(raw)
		}
	}
	return out.String()
}

func TestOIDCReplayStoreAcceptsAJTIOnce(t *testing.T) {
	w := newWorld(t)
	store := auth.OIDCReplay{DB: w.db}
	ctx := context.Background()
	exp := w.clock.Now().Add(time.Hour)

	first, err := store.Remember(ctx, "https://idp", "jti-1", exp)
	again, err2 := store.Remember(ctx, "https://idp", "jti-1", exp)
	other, err3 := store.Remember(ctx, "https://other", "jti-1", exp)

	if err != nil || err2 != nil || err3 != nil || !first || again || !other {
		t.Fatalf("fresh = %v, %v, %v (errors %v %v %v); want true, false, true", first, again, other, err, err2, err3)
	}
}
