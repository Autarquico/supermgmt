package app

import (
	"context"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

// addContainer records a Docker container service on the fixture node.
func (n *nodeFixture) addContainer(name string, metadata map[string]any) domain.Service {
	n.t.Helper()
	var svc domain.Service
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		rt, err := database.UpsertRuntime(ctx, tx, domain.Runtime{ID: n.ids.NewID(), NodeID: n.node.ID, Type: "docker", NativeID: "docker"})
		if err != nil {
			return err
		}
		svc, err = database.UpsertService(ctx, tx, domain.Service{
			ID: n.ids.NewID(), RuntimeID: rt.ID, NodeID: n.node.ID, NativeID: "abc123", Name: name,
			Kind: string(domain.ServiceDockerContainer), Status: "running", Metadata: metadata,
		})
		return err
	})
	return svc
}

func TestContainersAreActionableOnlyWithDockerAccess(t *testing.T) {
	n := newNodeFixture(t)
	container := n.addContainer("web", nil)
	ctx, by := context.Background(), n.caller(n.alice)

	n.grantSetup("nginx.service") // docker_access is false
	without, err := n.inv.GetService(ctx, by, container.ID)
	mustf(t, err, "GetService")
	meta := setupMetaFor("nginx.service")
	meta.DockerAccess = true
	capability, err := setupCapability(meta, n.clock.Now())
	mustf(t, err, "setupCapability")
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, n.node.ID, capability)
	})
	with, err := n.inv.GetService(ctx, by, container.ID)
	mustf(t, err, "GetService")

	if len(without.Actions) != 0 || !slices.Equal(with.Actions, domain.AllServiceVerbs()) || with.RuntimeType != domain.RuntimeDocker {
		t.Errorf("without docker_access %v, with %v (%s)", without.Actions, with.Actions, with.RuntimeType)
	}
}

func TestAContainerActionIsRefusedWithoutDockerAccess(t *testing.T) {
	n := newNodeFixture(t)
	container := n.addContainer("web", nil)
	n.grantSetup("nginx.service")

	_, err := n.svcs.Act(context.Background(), n.caller(n.alice), container.ID, domain.VerbRestart)

	wantError(t, err, smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible)
}

func TestAGoneServiceAdvertisesNoActions(t *testing.T) {
	svc := domain.Service{Kind: string(domain.ServiceSystemdUnit), NativeID: "nginx.service", Status: database.StatusGone}
	meta := setupMetaFor("nginx.service")

	if got := actionsFor(svc, &meta); len(got) != 0 {
		t.Errorf("actions = %v", got)
	}
}

func TestContainersAreLockedByTheirComposeProjectOrThemselves(t *testing.T) {
	n := newNodeFixture(t)
	plain := n.addContainer("web", nil)

	lock, err := serviceLock(plain, domain.LockExclusive)
	mustf(t, err, "serviceLock")
	composed := plain
	composed.Metadata = map[string]any{"compose_project": "shop"}
	composeLock, err := serviceLock(composed, domain.LockExclusive)
	mustf(t, err, "serviceLock")
	_, unknownKind := serviceLock(domain.Service{Kind: "pod", NativeID: "x"}, domain.LockExclusive)

	if lock.Key != "container:"+n.node.ID.String()+":abc123" || composeLock.Key != "compose_project:"+n.node.ID.String()+":shop" {
		t.Errorf("locks = %q and %q", lock.Key, composeLock.Key)
	}
	wantError(t, unknownKind, smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible)
}

func TestListProvidersShowsOnlyWhatTheCallerMayRead(t *testing.T) {
	n := newNodeFixture(t)

	visible, err := n.inv.ListProviders(context.Background(), n.caller(n.alice))
	hidden, errHidden := n.inv.ListProviders(context.Background(), n.caller(n.dave))

	if err != nil || len(visible) != 1 || visible[0].Name != "ssh-hosts" || visible[0].Origin != domain.ProviderAPI {
		t.Errorf("visible = %+v, %v", visible, err)
	}
	if errHidden != nil || len(hidden) != 0 {
		t.Errorf("hidden = %+v, %v", hidden, errHidden)
	}
}

func TestLogsOfABrokerNodeGoThroughTheBroker(t *testing.T) {
	n := newNodeFixture(t)
	meta := setupMetaFor("nginx.service")
	meta.LogsMode = runtimes.LogsBroker
	capability, err := setupCapability(meta, n.clock.Now())
	mustf(t, err, "setupCapability")
	n.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, n.node.ID, capability)
	})
	n.dialer.as("supermgmt").reply("systemd.logs_broker", "from the broker\n")

	chunk, err := n.inv.ServiceLogs(context.Background(), n.caller(n.alice), n.service.ID, 10)

	if err != nil || len(chunk.Lines) != 1 || chunk.Lines[0] != "from the broker" {
		t.Errorf("logs = %+v, %v", chunk, err)
	}
}

func TestDirectActionsDoNotGoThroughPOSTPlans(t *testing.T) {
	n := newNodeFixture(t)

	_, err := n.plans.Create(context.Background(), n.caller(n.admin), PlanRequest{
		Action: "node.add", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: n.node.ID},
	})

	if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("error = %v; direct actions are applied or wrapped by their own endpoints", err)
	}
}
