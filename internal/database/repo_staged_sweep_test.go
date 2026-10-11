package database

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestSweepOrphanStagedSecretsKeepsOnlyWhatAnUnfinishedJobStillNeeds(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		kek := f.ids.NewID()
		actor := f.identity(ctx, q, domain.ActorHuman, "alice").ID
		stagedFor := func(state string) domain.ID {
			staged := must(StageSecret(ctx, q, secret(f, "demo", kek, state)))
			row := override(baselines()["jobs"], "id", f.ids.NewID().String())
			row = override(row, "actor_id", actor.String())
			row = override(row, "state", state)
			row = override(row, "payload_json", `{"operation":"import_secret","staged_id":"`+staged.ID.String()+`"}`)
			noErr(t, insertRow(ctx, q.(*Tx), "jobs", row))
			return staged.ID
		}
		waiting, running, succeeded, cancelled := stagedFor("awaiting_approval"), stagedFor("running"), stagedFor("succeeded"), stagedFor("cancelled")
		unreferenced := must(StageSecret(ctx, q, secret(f, "demo", kek, "unreferenced"))).ID
		current := must(PutSecretVersion(ctx, q, secret(f, "demo", kek, "current"))).ID
		recent := secret(f, "demo", kek, "recent")
		recent.CreatedAt = testEpoch.Add(time.Hour)
		young := must(StageSecret(ctx, q, recent)).ID

		swept, err := SweepOrphanStagedSecrets(ctx, q, testEpoch)

		noErr(t, err)
		if swept != 3 {
			t.Errorf("swept %d, want the unreferenced one and the two whose jobs ended", swept)
		}
		for name, id := range map[string]domain.ID{"awaiting approval": waiting, "running": running, "current": current, "too young": young} {
			if _, err := GetSecretByID(ctx, q, id); err != nil {
				t.Errorf("the %s version was swept: %v", name, err)
			}
		}
		for name, id := range map[string]domain.ID{"unreferenced": unreferenced, "succeeded job": succeeded, "cancelled job": cancelled} {
			if _, err := GetSecretByID(ctx, q, id); smerr.CodeOf(err) != smerr.CodeNotFound {
				t.Errorf("the %s version survived: %v", name, err)
			}
		}
	})
}
