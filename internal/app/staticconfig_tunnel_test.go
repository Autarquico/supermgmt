package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

func TestReconcileNeverWritesTheTunnelFields(t *testing.T) {
	f := newFixture(t)
	r := f.reconciler(t)
	ctx := context.Background()
	mustf(t, r.Reconcile(ctx, fileEnvs(), []config.Provider{fileNode("edge-1", "10.1.0.1")}), "first")
	node, _ := f.nodeNamed("edge-1")
	node.Endpoint.Transport, node.Endpoint.TunnelHostname = domain.TransportCloudflare, "ssh-edge-1.example.com"
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := database.UpdateNodeSpec(ctx, tx, node, node.SpecRevision)
		return err
	})
	tunnelled, _ := f.nodeNamed("edge-1")
	updates := len(f.events("node.update"))

	mustf(t, r.Reconcile(ctx, fileEnvs(), []config.Provider{fileNode("edge-1", "10.1.0.1")}), "same file")
	after, _ := f.nodeNamed("edge-1")
	if after.SpecRevision != tunnelled.SpecRevision || len(f.events("node.update")) != updates {
		t.Errorf("an unchanged file must not touch a tunnelled node: revision %d -> %d", tunnelled.SpecRevision, after.SpecRevision)
	}

	mustf(t, r.Reconcile(ctx, fileEnvs(), []config.Provider{fileNode("edge-1", "10.1.0.2")}), "moved host")
	moved, _ := f.nodeNamed("edge-1")
	if moved.Endpoint.Host != "10.1.0.2" || moved.Endpoint.Transport != domain.TransportCloudflare ||
		moved.Endpoint.TunnelHostname != "ssh-edge-1.example.com" {
		t.Errorf("endpoint = %+v, want the new host with the tunnel fields kept", moved.Endpoint)
	}
}
