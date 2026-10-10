package database

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestConfigSnapshotGenerationsIncrease(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		_, err := GetConfigSnapshot(ctx, q)
		wantError(t, err, smerr.CodeNotFound, "")

		first := must(PutConfigSnapshot(ctx, q, []byte("a: 1\n"), []byte("p: 1\n"), testEpoch))
		second := must(PutConfigSnapshot(ctx, q, []byte("a: 2\x00\xff"), nil, testEpoch.Add(time.Minute)))
		if first.Generation != 1 || second.Generation != 2 {
			t.Fatalf("generations = %d, %d; want 1, 2", first.Generation, second.Generation)
		}
		got := must(GetConfigSnapshot(ctx, q))
		if got.Generation != 2 || !bytes.Equal(got.Config, []byte("a: 2\x00\xff")) || len(got.Policy) != 0 {
			t.Fatalf("stored = %+v", got)
		}
	})
}

func TestConfigSnapshotRollsBackWithItsTransaction(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		must(PutConfigSnapshot(ctx, q, []byte("kept"), nil, testEpoch))
	})
	_ = f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		must(PutConfigSnapshot(ctx, tx, []byte("discarded"), nil, testEpoch))
		return context.Canceled
	})
	got := must(GetConfigSnapshot(context.Background(), f.db.Reader()))
	if string(got.Config) != "kept" || got.Generation != 1 {
		t.Fatalf("snapshot = %+v, want the committed one", got)
	}
}

func TestRestoreHoldDefaultsToOffAndFailsClosedWhenUnreadable(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		if held := must(GetRestoreHold(ctx, q)); held {
			t.Fatal("hold is on without a row")
		}
		noErr(t, SetRestoreHold(ctx, q, true, testEpoch))
		if held := must(GetRestoreHold(ctx, q)); !held {
			t.Fatal("hold is off after SetRestoreHold(true)")
		}
		noErr(t, SetRestoreHold(ctx, q, false, testEpoch))
		if held := must(GetRestoreHold(ctx, q)); held {
			t.Fatal("hold is on after SetRestoreHold(false)")
		}

		noErr(t, PutSetting(ctx, q, Setting{Key: SettingRestoreHold, Value: json.RawMessage(`"yes"`), UpdatedAt: testEpoch}))
		if _, err := GetRestoreHold(ctx, q); err == nil {
			t.Fatal("a non-boolean hold value was accepted")
		}
	})
}
