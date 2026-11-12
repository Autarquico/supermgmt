package database

import (
	"context"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestStagedSecretsAreInvisibleUntilActivatedAndTakeTheNextVersion(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		kek := f.ids.NewID()
		first := must(StageSecret(ctx, q, secret(f, "demo", kek, "a")))
		second := must(StageSecret(ctx, q, secret(f, "demo", kek, "b")))
		if first.Version >= 0 || second.Version >= first.Version {
			t.Fatalf("staged versions = %d, %d; want distinct negatives", first.Version, second.Version)
		}
		if _, err := GetSecret(ctx, q, "demo", 0); err == nil {
			t.Fatal("a staged version is readable as the latest")
		}
		if _, err := GetSecret(ctx, q, "demo", first.Version); err == nil {
			t.Fatal("a staged version is readable by its version")
		}
		current := must(PutSecretVersion(ctx, q, secret(f, "demo", kek, "current")))
		if current.Version != 1 {
			t.Fatalf("version after staged ones = %d, want 1", current.Version)
		}

		activated := must(ActivateStagedSecret(ctx, q, second.ID))

		if activated.Version != 2 || string(activated.Ciphertext) != "b" {
			t.Fatalf("activated = %+v, want version 2", activated)
		}
		if latest := must(GetSecret(ctx, q, "demo", 0)); latest.ID != second.ID {
			t.Errorf("latest = %+v", latest)
		}
		again := must(ActivateStagedSecret(ctx, q, second.ID))
		if again.Version != 2 {
			t.Errorf("a second activation moved the version to %d", again.Version)
		}
		if ids := must(ReferencedKEKIDs(ctx, q)); len(ids) != 1 || ids[0] != kek {
			t.Errorf("referenced = %v; the remaining staged ciphertext still references its key", ids)
		}
	})
}

func TestDeletingAStagedSecretLeavesCurrentOnesAndIsIdempotent(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		kek := f.ids.NewID()
		current := must(PutSecretVersion(ctx, q, secret(f, "demo", kek, "kept")))
		staged := must(StageSecret(ctx, q, secret(f, "demo", kek, "gone")))

		noErr(t, DeleteStagedSecret(ctx, q, staged.ID))
		noErr(t, DeleteStagedSecret(ctx, q, staged.ID))
		noErr(t, DeleteStagedSecret(ctx, q, current.ID))

		if _, err := GetSecretByID(ctx, q, staged.ID); err == nil {
			t.Error("the staged version survived its deletion")
		}
		if got := must(GetSecretByID(ctx, q, current.ID)); string(got.Ciphertext) != "kept" {
			t.Errorf("current = %+v", got)
		}
		_, err := ActivateStagedSecret(ctx, q, staged.ID)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestSecretSummariesDescribeTheLatestVersionAndSkipStagedOnes(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		kek := f.ids.NewID()
		must(PutSecretVersion(ctx, q, secret(f, "zeta", kek, "v1")))
		latest := secret(f, "zeta", kek, "v2")
		latest.Metadata = map[string]any{"source": "import"}
		must(PutSecretVersion(ctx, q, latest))
		must(PutSecretVersion(ctx, q, secret(f, "alpha", kek, "v1")))
		must(StageSecret(ctx, q, secret(f, "alpha", kek, "staged")))
		must(StageSecret(ctx, q, secret(f, "only-staged", kek, "staged")))

		got := must(ListSecretSummaries(ctx, q))

		if len(got) != 2 || got[0].Name != "alpha" || got[0].Version != 1 || got[1].Name != "zeta" || got[1].Version != 2 {
			t.Fatalf("summaries = %+v; want alpha v1 and zeta v2, sorted", got)
		}
		if got[1].Metadata["source"] != "import" {
			t.Errorf("zeta metadata = %v; want the latest version's", got[1].Metadata)
		}
	})
}
