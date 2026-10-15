package database

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestEndpointJSONBeforeTheTunnelFieldsReadsAsDirect(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "ssh-a"), "web-1")
		old := `{"host":"10.0.0.1","port":22,"user":"sm","admin_user":"","admin_credential_ref":"","host_public_key":"ssh-ed25519 AAAA"}`
		if _, err := q.ExecContext(ctx, `UPDATE nodes SET endpoint_json = ? WHERE id = ?`, old, n.ID); err != nil {
			t.Fatal(err)
		}
		got := must(GetNode(ctx, q, n.ID))
		if got.Endpoint.Transport != "" || got.Endpoint.Transport.Effective() != domain.TransportDirect || got.Endpoint.TunnelHostname != "" {
			t.Fatalf("endpoint = %+v, want direct", got.Endpoint)
		}
	})
}

func TestADirectEndpointStoresNoTunnelKeys(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "ssh-a"), "web-1")
		var keys map[string]any
		var raw string
		if err := q.QueryRowContext(ctx, `SELECT endpoint_json FROM nodes WHERE id = ?`, n.ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"transport", "tunnel_hostname"} {
			if _, ok := keys[key]; ok {
				t.Errorf("endpoint_json = %s, want no %s key", raw, key)
			}
		}
	})
}

func TestTunnelFieldsRoundTripAndAreValidated(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "ssh-a"), "web-1")
		n.Endpoint.Transport, n.Endpoint.TunnelHostname = domain.TransportCloudflare, "ssh-web-1.example.com"
		stored := must(UpdateNodeSpec(ctx, q, n, n.SpecRevision))
		got := must(GetNode(ctx, q, stored.ID))
		if got.Endpoint != n.Endpoint {
			t.Fatalf("endpoint = %+v, want %+v", got.Endpoint, n.Endpoint)
		}

		bad := got
		bad.Endpoint.TunnelHostname = "a;b.example.com"
		_, err := UpdateNodeSpec(ctx, q, bad, got.SpecRevision)
		wantError(t, err, smerr.CodeInvalidArgument, "")

		bad = got
		bad.Endpoint.Transport = "wireguard"
		_, err = UpdateNodeSpec(ctx, q, bad, got.SpecRevision)
		wantError(t, err, smerr.CodeInvalidArgument, "")
	})
}

func TestAStoredUnknownTransportIsRejectedOnRead(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "ssh-a"), "web-1")
		if _, err := q.ExecContext(ctx, `UPDATE nodes SET endpoint_json = ? WHERE id = ?`,
			`{"host":"h","port":22,"transport":"wireguard"}`, n.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := GetNode(ctx, q, n.ID); err == nil {
			t.Fatal("GetNode accepted an unknown transport")
		}
	})
}
