package app

import (
	"context"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// heldLocks reads the locks a claimed job holds, as "<key>=<mode>".
func (w *deployWorld) heldLocks(job domain.ID) map[string]domain.LockMode {
	w.t.Helper()
	rows, err := w.db.Reader().QueryContext(context.Background(),
		`SELECT resource_type, resource_id, mode FROM resource_locks WHERE job_id = ?`, job)
	mustf(w.t, err, "query locks")
	defer rows.Close()
	held := map[string]domain.LockMode{}
	for rows.Next() {
		var kind, id, mode string
		mustf(w.t, rows.Scan(&kind, &id, &mode), "scan lock")
		held[kind+":"+id] = domain.LockMode(mode)
	}
	mustf(w.t, rows.Err(), "locks")
	return held
}

func TestDeploymentLocks_ClaimTakesTargetProjectAndPortsExclusivelyAndInputsShared(t *testing.T) {
	w := newDeployWorld(t)
	dep := w.queued()

	claimed, ok := w.claim()
	if !ok {
		t.Fatal("a finalized deployment cannot be claimed through the real store")
	}

	held := w.heldLocks(claimed.Job.ID)
	exclusive := []string{
		"app_target:" + w.target.ID.String(),
		"compose_project:" + w.node.ID.String() + ":sm-web-dev",
		"port:" + w.node.ID.String() + ":127.0.0.1:8080",
	}
	for _, key := range exclusive {
		if held[key] != domain.LockExclusive {
			t.Errorf("lock %s = %q, want exclusive (held: %v)", key, held[key], held)
		}
	}
	for _, in := range w.planOf(dep.ID).Inputs {
		key := in.Type + ":" + in.ID
		if held[key] != domain.LockShared {
			t.Errorf("input lock %s = %q, want shared", key, held[key])
		}
	}
	for key, mode := range held {
		if mode == domain.LockExclusive && !slices.Contains(exclusive, key) {
			t.Errorf("unexpected exclusive lock %s", key)
		}
	}
}

func TestDeploymentLocks_AnotherDeploymentOfTheSameTargetWaitsForTheFirst(t *testing.T) {
	w := newDeployWorld(t)
	w.queued()
	second := w.queued(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit })
	first, ok := w.claim()
	if !ok {
		t.Fatal("no first claim")
	}

	if again, ok := w.claim(); ok {
		t.Fatalf("job %s was claimed while %s holds the target", again.Job.ID, first.Job.ID)
	}
	if got := w.job(*second.JobID).State; got != domain.JobQueued {
		t.Errorf("blocked job state = %s, want queued", got)
	}
}

func TestDeploymentLocks_ReleasedWhenTheJobEnds(t *testing.T) {
	w := newDeployWorld(t)
	w.queued()
	w.queued(func(r *CreateDeployment) { r.CommitSHA = depOtherCommit })
	first, ok := w.claim()
	if !ok {
		t.Fatal("no first claim")
	}
	mustf(t, w.store.Succeed(context.Background(), first.Lease), "Succeed")

	if _, ok := w.claim(); !ok {
		t.Error("the waiting deployment was not claimable after the first one ended")
	}
}

func TestDeploymentLocks_HostPortsAreLockedOncePerAddressAndPort(t *testing.T) {
	w := newDeployWorld(t)
	job := jobs.Job{Type: deploymentCreateAction, Resource: domain.ResourceRef{Type: domain.ResourceAppTarget, ID: w.target.ID}}
	p := plan.Plan{Content: plan.Content{HostPorts: []string{"127.0.0.1:8080", "127.0.0.1:8080/udp", "[::1]:9000"}}}

	specs, err := deploymentLocks(context.Background(), w.db.Reader(), job, p)

	mustf(t, err, "deploymentLocks")
	want := []domain.LockSpec{
		domain.ComposeProjectLock(w.node.ID, "sm-web-dev", domain.LockExclusive),
		domain.PortLock(w.node.ID, "127.0.0.1", 8080, domain.LockExclusive),
		domain.PortLock(w.node.ID, "::1", 9000, domain.LockExclusive),
	}
	if !slices.Equal(specs, want) {
		t.Errorf("locks = %v, want %v", specs, want)
	}
}

func TestDeploymentLocks_AnUnreadableHostPortInThePlanIsAnError(t *testing.T) {
	w := newDeployWorld(t)
	job := jobs.Job{Type: deploymentCreateAction, Resource: domain.ResourceRef{Type: domain.ResourceAppTarget, ID: w.target.ID}}

	_, err := deploymentLocks(context.Background(), w.db.Reader(), job, plan.Plan{Content: plan.Content{HostPorts: []string{"8080"}}})

	wantError(t, err, smerr.CodeInternal, "")
}

func TestDeploymentLocks_BothDeploymentTypesAreExclusiveOnTheirTarget(t *testing.T) {
	for _, jobType := range []string{deploymentCreateAction, deploymentRollbackAction} {
		if lockModeByJobType[jobType] != domain.LockExclusive || !isDeploymentJob(jobType) {
			t.Errorf("%s: mode %q, deployment job %v", jobType, lockModeByJobType[jobType], isDeploymentJob(jobType))
		}
	}
	if isDeploymentJob("node.reboot") {
		t.Error("node.reboot is not a deployment job")
	}
}

func TestDeploymentLocks_ADeploymentJobWithoutAPlanCannotNameItsLocks(t *testing.T) {
	_, err := LockPlanner{}.PlanLocks(context.Background(), database.Querier(nil), jobs.Job{
		Type: deploymentRollbackAction, Resource: domain.ResourceRef{Type: domain.ResourceAppTarget, ID: "t"},
	})

	wantError(t, err, smerr.CodeInternal, "")
}

func TestDeploymentLocks_TheRollbackTargetsPortsAreLockedToo(t *testing.T) {
	w := newDeployWorld(t)
	next, good := w.afterKnownGood()
	w.exec(`UPDATE plans SET plan_json = json_set(plan_json, '$.content.host_ports', json('["127.0.0.1:9999","127.0.0.1:8080"]')) WHERE id = ?`, *good.PlanID)
	job := jobs.Job{Type: deploymentCreateAction, Resource: domain.ResourceRef{Type: domain.ResourceAppTarget, ID: w.target.ID}}

	specs, err := deploymentLocks(context.Background(), w.db.Reader(), job, w.planOf(next.ID))

	mustf(t, err, "deploymentLocks")
	want := []domain.LockSpec{
		domain.ComposeProjectLock(w.node.ID, "sm-web-dev", domain.LockExclusive),
		domain.PortLock(w.node.ID, "127.0.0.1", 8080, domain.LockExclusive),
		domain.PortLock(w.node.ID, "127.0.0.1", 9999, domain.LockExclusive),
	}
	if !slices.Equal(specs, want) {
		t.Errorf("locks = %v, want %v", specs, want)
	}
}

func TestDeploymentLocks_ARollbackTargetThatIsGoneCannotNameItsLocks(t *testing.T) {
	w := newDeployWorld(t)
	job := jobs.Job{Type: deploymentCreateAction, Resource: domain.ResourceRef{Type: domain.ResourceAppTarget, ID: w.target.ID}}
	p := plan.Plan{Content: plan.Content{RollbackTarget: &plan.RollbackTarget{DeploymentID: "missing"}}}

	_, err := deploymentLocks(context.Background(), w.db.Reader(), job, p)

	wantError(t, err, smerr.CodeNotFound, "")
}
