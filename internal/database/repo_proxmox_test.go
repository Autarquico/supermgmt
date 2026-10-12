package database

import (
	"context"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestUpdateProviderSpecBumpsTheRevisionOnlyFromTheExpectedOne(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		p := f.provider(ctx, q, "pve")
		p.Endpoint, p.CredentialRef, p.Config = "https://pve.lan:8006", "secret://providers/pve/token", map[string]any{"ca_file": "/ca.pem"}
		p.UpdatedAt = testEpoch.Add(time.Hour)

		got := must(UpdateProviderSpec(ctx, q, p, p.SpecRevision))

		if got.SpecRevision != p.SpecRevision+1 || got.Endpoint != p.Endpoint || got.CredentialRef != p.CredentialRef ||
			got.Config["ca_file"] != "/ca.pem" || !got.UpdatedAt.Equal(p.UpdatedAt) {
			t.Fatalf("updated = %+v", got)
		}
		_, err := UpdateProviderSpec(ctx, q, p, p.SpecRevision) // stale
		wantError(t, err, smerr.CodeConflict, "")
		p.ID = f.ids.NewID()
		_, err = UpdateProviderSpec(ctx, q, p, 1)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestSetProviderStatusKeepsTheLastSyncUnlessGivenOneAndNeverTouchesTheRevision(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		p := f.provider(ctx, q, "pve")
		at := testEpoch.Add(time.Minute)

		noErr(t, SetProviderStatus(ctx, q, p.ID, "ok", &at))
		noErr(t, SetProviderStatus(ctx, q, p.ID, "error", nil))

		got := must(GetProvider(ctx, q, p.ID))
		if got.Status != "error" || got.LastSyncAt == nil || !got.LastSyncAt.Equal(at) || got.SpecRevision != p.SpecRevision {
			t.Errorf("provider = %+v, want status error, last sync %v, revision %d", got, at, p.SpecRevision)
		}
		wantError(t, SetProviderStatus(ctx, q, f.ids.NewID(), "ok", nil), smerr.CodeNotFound, "")
	})
}

func TestMarkProviderRemovedSetsTheStatusAndInvalidatesPlansOfTheProvider(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		p := f.provider(ctx, q, "pve")

		noErr(t, MarkProviderRemoved(ctx, q, p.ID, "removed"))

		got := must(GetProvider(ctx, q, p.ID))
		if got.Status != "removed" || got.SpecRevision != p.SpecRevision+1 {
			t.Errorf("provider = %+v, want status removed and revision %d", got, p.SpecRevision+1)
		}
		wantError(t, MarkProviderRemoved(ctx, q, f.ids.NewID(), "removed"), smerr.CodeNotFound, "")
	})
}

func TestSetNodeMetadataReplacesTheObservedMetadataWithoutBumpingTheRevision(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "pve"), "qemu/100")

		noErr(t, SetNodeMetadata(ctx, q, n.ID, map[string]any{"pve_node": "pve2", "vmid": 100}))

		got := must(GetNode(ctx, q, n.ID))
		if got.Metadata["pve_node"] != "pve2" || got.Metadata["vmid"] != float64(100) || got.SpecRevision != n.SpecRevision {
			t.Errorf("node = %+v", got)
		}
		wantError(t, SetNodeMetadata(ctx, q, f.ids.NewID(), nil), smerr.CodeNotFound, "")
	})
}
