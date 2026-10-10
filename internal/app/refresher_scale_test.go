package app

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// manyNodes inserts n managed SSH nodes.
func (p *probing) manyNodes(n int) {
	p.t.Helper()
	p.inTx(func(ctx context.Context, tx *database.Tx) error {
		for k := range n {
			name := fmt.Sprintf("bulk-%03d", k)
			provider, err := database.CreateProvider(ctx, tx, domain.Provider{
				ID: p.ids.NewID(), Type: "ssh", Name: name, Origin: domain.ProviderAPI, CreatedAt: p.clock.Now(), UpdatedAt: p.clock.Now(),
			})
			if err != nil {
				return err
			}
			_, err = database.CreateNode(ctx, tx, domain.Node{
				ID: p.ids.NewID(), ProviderID: provider.ID, NativeID: name, Name: name, Kind: "ssh",
				ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
				Endpoint: domain.NodeEndpoint{
					Host: "10.9.0.1", Port: 22, User: "supermgmt", AdminUser: "admin",
					AdminCredentialRef: "ssh-agent://default", HostPublicKey: testHostKey,
				},
				CreatedAt: p.clock.Now(), UpdatedAt: p.clock.Now(),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func TestARefreshOfFiveHundredNodesKeepsTheProbesInFlightBounded(t *testing.T) {
	p := newProbing(t)
	const nodes, workers = 500, 16
	p.manyNodes(nodes)
	var running, peak, total atomic.Int32
	p.dialer.as("admin").on("probe", func(templates.Command) (transport.Result, error) {
		n := running.Add(1)
		for {
			if old := peak.Load(); n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		total.Add(1)
		running.Add(-1)
		return transport.Result{Stdout: []byte(linuxProbe)}, nil
	})
	r := p.refresher(t, func(o *RefresherOptions) { o.Workers = workers })

	for total.Load() < nodes+1 { // the bulk nodes and the fixture's own
		mustf(t, r.Pass(context.Background()), "pass")
		r.Wait()
	}

	if peak.Load() > workers {
		t.Errorf("peak probes in flight = %d, want at most %d", peak.Load(), workers)
	}
}

func TestListingNeverWaitsForAHungProbe(t *testing.T) {
	p := newProbing(t)
	slow, release, started := hung(t)
	p.dialer.route(p.node.ID, slow)
	r := p.refresher(t)
	mustf(t, r.Pass(context.Background()), "pass")
	eventually(t, "the hung probe to start", func() bool { return started.Load() == 1 })

	page, err := p.inv.ListNodes(context.Background(), p.caller(p.alice), wire.NodeQuery{})

	if err != nil || len(page.Items) != 1 {
		t.Errorf("ListNodes while a probe hangs = %d items, %v", len(page.Items), err)
	}
	release()
	r.Wait()
}
