package database

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

func TestSweepAuthKeepsCredentialsOfUnfinishedJobs(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		alice := f.identity(ctx, q, domain.ActorHuman, "alice")
		jobFor := func(kind string, id domain.ID, state string) {
			row := override(baselines()["jobs"], "id", f.ids.NewID().String())
			row = override(row, "actor_id", alice.ID.String())
			row = override(row, "credential_kind", kind)
			row = override(row, "credential_id", id.String())
			row = override(row, "state", state)
			noErr(t, insertRow(ctx, q.(*Tx), "jobs", row))
		}
		held := f.authSession(alice.ID, "s-held", time.Minute)
		finished := f.authSession(alice.ID, "s-finished", time.Minute)
		heldToken := f.token(alice.ID, "held", "t-held", time.Minute)
		finishedToken := f.token(alice.ID, "finished", "t-finished", time.Minute)
		for _, s := range []AuthSession{held, finished} {
			noErr(t, CreateAuthSession(ctx, q, s))
		}
		for _, tok := range []APIToken{heldToken, finishedToken} {
			noErr(t, CreateAPIToken(ctx, q, tok))
		}
		jobFor("session", held.ID, "queued")
		jobFor("session", finished.ID, "succeeded")
		jobFor("api_token", heldToken.ID, "interrupted")
		jobFor("api_token", finishedToken.ID, "failed")

		got := must(SweepAuth(ctx, q, testEpoch.Add(time.Minute)))

		if got.Sessions != 1 || got.APITokens != 1 {
			t.Fatalf("swept %+v, want only the credentials of finished jobs", got)
		}
		noErr(t, nilIfNil(GetAuthSession(ctx, q, held.ID)))
		noErr(t, nilIfNil(GetAPIToken(ctx, q, heldToken.ID)))
	})
}
