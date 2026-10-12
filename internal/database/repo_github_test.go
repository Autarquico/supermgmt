package database

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func githubArtifactOf(f *fixture, app App, digest string) Artifact {
	run, attempt := int64(42), int64(2)
	return Artifact{
		ID: f.ids.NewID(), AppID: app.ID, ImmutableRef: "ghcr.io/acme/web@" + digest, Digest: digest,
		CommitSHA: "abc123", SourceRunID: &run, SourceRunAttempt: &attempt,
		ProvenanceJSON: []byte(`{"slsa":"v1"}`), ProvenanceMethod: "attestation", CreatedAt: testEpoch,
	}
}

func TestArtifactRoundTripAndLookup(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		app := must(CreateApp(ctx, q, appsAppOf(f, "web")))

		created := must(CreateArtifact(ctx, q, githubArtifactOf(f, app, "sha256:aa")))
		if created.Type != "oci_image" {
			t.Errorf("type = %q, want the oci_image default", created.Type)
		}
		got := must(GetArtifact(ctx, q, created.ID))
		if got.Digest != "sha256:aa" || *got.SourceRunID != 42 || *got.SourceRunAttempt != 2 ||
			string(got.ProvenanceJSON) != `{"slsa":"v1"}` || !got.CreatedAt.Equal(testEpoch) {
			t.Fatalf("round trip: %+v", got)
		}

		noRun := githubArtifactOf(f, app, "sha256:bb")
		noRun.SourceRunID, noRun.SourceRunAttempt, noRun.ProvenanceMethod = nil, nil, "oidc_claims"
		stored := must(GetArtifact(ctx, q, must(CreateArtifact(ctx, q, noRun)).ID))
		if stored.SourceRunID != nil || stored.SourceRunAttempt != nil {
			t.Errorf("run fields = %v %v, want nil", stored.SourceRunID, stored.SourceRunAttempt)
		}

		found := must(FindArtifact(ctx, q, app.ID, "sha256:aa", "abc123"))
		if found.ID != created.ID {
			t.Errorf("find = %v, want %v", found.ID, created.ID)
		}
		_, err := FindArtifact(ctx, q, app.ID, "sha256:aa", "other-commit")
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = GetArtifact(ctx, q, f.ids.NewID())
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestFindArtifactReturnsTheNewestMatch(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		app := must(CreateApp(ctx, q, appsAppOf(f, "web")))
		older := githubArtifactOf(f, app, "sha256:aa")
		newer := githubArtifactOf(f, app, "sha256:aa")
		newer.CreatedAt = testEpoch.Add(time.Hour)
		must(CreateArtifact(ctx, q, newer))
		must(CreateArtifact(ctx, q, older))

		if got := must(FindArtifact(ctx, q, app.ID, "sha256:aa", "abc123")); got.ID != newer.ID {
			t.Errorf("find = %v, want the newer %v", got.ID, newer.ID)
		}
	})
}

func TestArtifactsAreImmutable(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		app := must(CreateApp(ctx, q, appsAppOf(f, "web")))
		a := must(CreateArtifact(ctx, q, githubArtifactOf(f, app, "sha256:aa")))
		if _, err := q.ExecContext(ctx, `UPDATE artifacts SET commit_sha = 'x' WHERE id = ?`, a.ID); err == nil {
			t.Error("artifact update succeeded, want the immutability trigger to abort it")
		}
	})
}

func TestArtifactChecks(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		app := must(CreateApp(ctx, q, appsAppOf(f, "web")))
		a := must(CreateArtifact(ctx, q, githubArtifactOf(f, app, "sha256:aa")))
		run, attempt := int64(42), int64(2)
		done := testEpoch.Add(time.Minute)

		noErr(t, PutArtifactCheck(ctx, q, ArtifactCheck{
			ArtifactID: a.ID, CheckName: "test", AppID: 15368, WorkflowPath: ".github/workflows/ci.yml",
			RunID: &run, RunAttempt: &attempt, Conclusion: "success", CompletedAt: &done,
		}))
		noErr(t, PutArtifactCheck(ctx, q, ArtifactCheck{ArtifactID: a.ID, CheckName: "lint", AppID: 15368, Conclusion: "success"}))
		wantError(t, PutArtifactCheck(ctx, q, ArtifactCheck{ArtifactID: a.ID, CheckName: "lint", AppID: 1, Conclusion: "failure"}),
			smerr.CodeConflict, "")

		checks := must(ListArtifactChecks(ctx, q, a.ID))
		if len(checks) != 2 || checks[0].CheckName != "lint" || checks[1].CheckName != "test" {
			t.Fatalf("checks = %+v, want lint then test", checks)
		}
		lint, test := checks[0], checks[1]
		if lint.RunID != nil || lint.CompletedAt != nil {
			t.Errorf("lint optional fields = %v %v, want nil", lint.RunID, lint.CompletedAt)
		}
		if *test.RunID != 42 || *test.RunAttempt != 2 || test.AppID != 15368 || !test.CompletedAt.Equal(done) ||
			test.WorkflowPath != ".github/workflows/ci.yml" {
			t.Errorf("test check = %+v", test)
		}
		if other := must(ListArtifactChecks(ctx, q, f.ids.NewID())); len(other) != 0 {
			t.Errorf("checks of another artifact = %+v, want none", other)
		}
	})
}

func githubCredentialOf(identity domain.ID, jti string) GithubOIDCCredential {
	return GithubOIDCCredential{
		ID:         GithubOIDCCredentialID("https://token.actions.githubusercontent.com", jti),
		IdentityID: identity, RepositoryID: 100, ClaimsJSON: []byte(`{"sha":"abc123"}`),
		IssuedAt: testEpoch, ExpiresAt: testEpoch.Add(10 * time.Minute), CreatedAt: testEpoch,
	}
}

func TestGithubOIDCCredentialIDIsAStableHashOfIssuerAndJTI(t *testing.T) {
	a := GithubOIDCCredentialID("iss", "jti-1")
	if a != GithubOIDCCredentialID("iss", "jti-1") {
		t.Error("id is not deterministic")
	}
	if len(a) != 64 {
		t.Errorf("id length = %d, want 64 hex characters", len(a))
	}
	if a == GithubOIDCCredentialID("iss", "jti-2") || a == GithubOIDCCredentialID("iss2", "jti-1") {
		t.Error("distinct issuer/jti pairs share an id")
	}
}

func TestGithubOIDCCredentialRoundTripAndReplay(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		identity := f.identity(ctx, q, domain.ActorAutomation, "repository_id:100:workflow:deploy.yml")
		c := githubCredentialOf(identity.ID, "jti-1")

		noErr(t, InsertGithubOIDCCredential(ctx, q, c))
		got := must(GetGithubOIDCCredential(ctx, q, c.ID))
		if got.IdentityID != identity.ID || got.RepositoryID != 100 || string(got.ClaimsJSON) != `{"sha":"abc123"}` ||
			!got.IssuedAt.Equal(testEpoch) || !got.ExpiresAt.Equal(c.ExpiresAt) || got.RevokedAt != nil {
			t.Fatalf("round trip: %+v", got)
		}
		wantError(t, InsertGithubOIDCCredential(ctx, q, c), smerr.CodeConflict, "")

		_, err := GetGithubOIDCCredential(ctx, q, "missing")
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestRevokeGithubOIDCCredentialsByIdentity(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		deploy := f.identity(ctx, q, domain.ActorAutomation, "repository_id:100:workflow:deploy.yml")
		other := f.identity(ctx, q, domain.ActorAutomation, "repository_id:200:workflow:deploy.yml")
		first, second, unrelated := githubCredentialOf(deploy.ID, "j1"), githubCredentialOf(deploy.ID, "j2"), githubCredentialOf(other.ID, "j3")
		for _, c := range []GithubOIDCCredential{first, second, unrelated} {
			noErr(t, InsertGithubOIDCCredential(ctx, q, c))
		}

		early := testEpoch.Add(time.Minute)
		if n := must(RevokeGithubOIDCCredentialsByIdentity(ctx, q, deploy.ID, early)); n != 2 {
			t.Fatalf("revoked = %d, want 2", n)
		}
		later := testEpoch.Add(time.Hour)
		if n := must(RevokeGithubOIDCCredentialsByIdentity(ctx, q, deploy.ID, later)); n != 0 {
			t.Fatalf("second revoke = %d, want 0", n)
		}

		for _, c := range []GithubOIDCCredential{first, second} {
			got := must(GetGithubOIDCCredential(ctx, q, c.ID))
			if got.RevokedAt == nil || !got.RevokedAt.Equal(early) {
				t.Errorf("revoked_at = %v, want the first revocation time %v", got.RevokedAt, early)
			}
		}
		if got := must(GetGithubOIDCCredential(ctx, q, unrelated.ID)); got.RevokedAt != nil {
			t.Errorf("another identity's credential was revoked at %v", got.RevokedAt)
		}
	})
}

func TestWebhookDeliveriesAreDeduplicatedPerProvider(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		delivery := WebhookDelivery{
			ID: f.ids.NewID(), Provider: "gh-main", DeliveryID: "d-1", ReceivedAt: testEpoch,
			SignatureValid: true, EventType: "check_run",
		}
		if fresh := must(RecordWebhookDelivery(ctx, q, delivery)); !fresh {
			t.Fatal("first delivery reported as a redelivery")
		}
		redelivery := delivery
		redelivery.ID = f.ids.NewID()
		if fresh := must(RecordWebhookDelivery(ctx, q, redelivery)); fresh {
			t.Fatal("redelivery reported as new")
		}
		otherProvider := redelivery
		otherProvider.ID, otherProvider.Provider = f.ids.NewID(), "gh-other"
		if fresh := must(RecordWebhookDelivery(ctx, q, otherProvider)); !fresh {
			t.Fatal("same delivery id under another provider reported as a redelivery")
		}

		if n := githubScalar[int](ctx, t, q, `SELECT count(*) FROM webhook_deliveries`); n != 2 {
			t.Errorf("rows = %d, want 2", n)
		}
	})
}

func TestMarkWebhookDeliveryProcessed(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		must(RecordWebhookDelivery(ctx, q, WebhookDelivery{
			ID: f.ids.NewID(), Provider: "gh-main", DeliveryID: "d-1", ReceivedAt: testEpoch, SignatureValid: true,
		}))
		at := testEpoch.Add(time.Second)

		noErr(t, MarkWebhookDeliveryProcessed(ctx, q, "gh-main", "d-1", at, "nudged"))
		if got := githubScalar[string](ctx, t, q, `SELECT result FROM webhook_deliveries WHERE delivery_id = 'd-1'`); got != "nudged" {
			t.Errorf("result = %q, want nudged", got)
		}
		if got := githubScalar[int64](ctx, t, q, `SELECT processed_at FROM webhook_deliveries WHERE delivery_id = 'd-1'`); got != millis(at) {
			t.Errorf("processed_at = %d, want %d", got, millis(at))
		}
		wantError(t, MarkWebhookDeliveryProcessed(ctx, q, "gh-main", "unknown", at, "x"), smerr.CodeNotFound, "")
	})
}

func githubScalar[T any](ctx context.Context, t *testing.T, q Querier, query string) T {
	t.Helper()
	var v T
	if err := q.QueryRowContext(ctx, query).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}
