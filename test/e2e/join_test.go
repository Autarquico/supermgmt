//go:build e2e && fixtures

package e2e_test

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/e2e/harness"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// TestM2_JoinEnrollsFixtureNode
//
// Criterion J (spec §13, ADR-0022; PLAN §9 row "Join"): an administrator issues a join token over
// `sm enrollments create`, the node
// runs the signed scripts/join.sh, and the server ends up with a managed node it reaches over SSH as
// the dedicated `supermgmt` account, using the instance key that join authorized.
func TestM2_JoinEnrollsFixtureNode(t *testing.T) {
	ctx := context.Background()
	w := newReleaseWorld(t)
	srv := harness.StartServer(t, w.net, w.ca, harness.ServerOptions{Mode: harness.Direct, Aliases: []string{"sm.test"}})
	admin := harness.NewClient(t)
	admin.AddProfile(ctx, "ops", srv.URL, srv.CAFile)
	session := srv.BootstrapAdmin(ctx, admin, "operator")

	created := admin.Must(ctx, "", "enrollments", "create", "--tag", "fixture", "--max-nodes", "1", "--expires-in", "1h")
	joinToken := strings.TrimSpace(created.Stdout)

	if err := fixture.Build(ctx); err != nil {
		t.Fatal(err)
	}
	fx, err := fixture.Start(ctx, fixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fx.Stop(context.WithoutCancel(ctx)) })
	node := harness.Adopt(t, fx.Name)
	node.Connect(w.net)
	node.MustExec(ctx, "sh", "-c", "apt-get update -qq && apt-get install -y -qq --no-install-recommends curl")
	node.TrustCA(ctx, w.ca.CertPEM)
	node.WriteFile(ctx, "/root/join-token", []byte(joinToken), "0600")

	join := node.Env(ctx, "", map[string]string{
		"SUPERMGMT_RELEASE_BASE_URL": w.mirror.BaseURL("good"), "SUPERMGMT_VERSION": w.release.Version,
	}, "bash", "-c", `set -o pipefail; curl -fsSL `+w.mirror.BaseURL("good")+`/join.sh | bash -s -- --server https://sm.test:8443 --token-file /root/join-token --hostname fixture-1`)
	if join.Code != 0 {
		t.Fatalf("join.sh exited %d\n%s", join.Code, join.Output())
	}

	t.Run("the node holds the instance key under the dedicated account", func(t *testing.T) {
		key, err := srv.Typed(session).SSHKey(ctx)
		if err != nil {
			t.Fatal(err)
		}
		home := strings.Split(node.MustExec(ctx, "getent", "passwd", "supermgmt"), ":")[5]
		authorized := node.MustExec(ctx, "cat", home+"/.ssh/authorized_keys")
		keyBody := strings.Fields(key.AuthorizedKey)[1]
		if !strings.Contains(authorized, keyBody) || !strings.Contains(authorized, "restrict") {
			t.Fatalf("authorized_keys of supermgmt does not carry the instance key as a restricted key:\n%s", authorized)
		}
	})

	t.Run("the server lists it as a managed node and reaches it as supermgmt", func(t *testing.T) {
		var nodes wire.Page[wire.Node]
		admin.JSON(ctx, "", &nodes, "nodes", "list")
		var joined *wire.Node
		for i := range nodes.Items {
			if nodes.Items[i].Name == "fixture-1" {
				joined = &nodes.Items[i]
			}
		}
		if joined == nil {
			t.Fatalf("fixture-1 is not in the node list: %+v", nodes.Items)
		}
		if joined.ManagementState != domain.ManagementManaged {
			t.Fatalf("management state = %s, want managed", joined.ManagementState)
		}
		var probe wire.Submission
		admin.JSON(ctx, "", &probe, "nodes", "probe", joined.Name)
		harness.WaitJob(ctx, t, srv.Typed(session), jobOf(t, probe), domain.JobSucceeded)
		reached, err := srv.Typed(session).GetNode(ctx, joined.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		if reached.Reachability != domain.ReachabilityReachable {
			t.Fatalf("reachability = %s, want reachable (connection: %+v)", reached.Reachability, reached.Connection)
		}
	})

	t.Run("a join token works once", func(t *testing.T) {
		again := node.Env(ctx, "", map[string]string{
			"SUPERMGMT_RELEASE_BASE_URL": w.mirror.BaseURL("good"), "SUPERMGMT_VERSION": w.release.Version,
		}, "bash", "-c", `set -o pipefail; curl -fsSL `+w.mirror.BaseURL("good")+`/join.sh | bash -s -- --server https://sm.test:8443 --token-file /root/join-token --hostname fixture-2`)
		if again.Code == 0 {
			t.Fatalf("a second node joined with a spent token\n%s", again.Output())
		}
	})
}
