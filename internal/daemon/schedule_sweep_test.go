package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

func TestTheSweeperDeletesOrphanStagedSecretsAfterTheirGraceOnly(t *testing.T) {
	ctx := context.Background()
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	stage := func(age time.Duration) domain.ID {
		t.Helper()
		var id domain.ID
		err := db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
			staged, err := database.StageSecret(ctx, tx, database.SecretRecord{
				ID: domain.UUIDv7Generator{}.NewID(), Name: "demo", EnvelopeVersion: 1, KEKID: domain.UUIDv7Generator{}.NewID(),
				WrappedDEK: []byte{1}, Ciphertext: []byte{2}, CreatedAt: clock.Now().Add(-age),
			})
			id = staged.ID
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	orphan, fresh := stage(2*stagedGrace), stage(time.Minute)
	sweep := &authSweep{db: db, now: clock.Now, report: func(err error) { t.Error(err) }}

	sweep.once(ctx)

	if _, err := database.GetSecretByID(ctx, db.Reader(), fresh); err != nil {
		t.Errorf("a version staged a minute ago was swept: %v", err)
	}
	if _, err := database.GetSecretByID(ctx, db.Reader(), orphan); err == nil {
		t.Error("an orphan staged version older than the grace survived the sweep")
	}
}
