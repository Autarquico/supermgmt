package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/deployments/manifest"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/github"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
)

const (
	eventDeploymentFinalized = "deployment.finalized"
	finalizeFetchTimeout     = 2 * time.Minute
)

// errAppMoved asks for another try: the app was edited between reading its
// commit from GitHub and writing the plan, so what was read may not apply.
var errAppMoved = errors.New("app: the app changed while its commit was read")

// FinalizerDeps are what finalizing needs beyond the deployments service.
// Attestations may be nil: no digest is then bound by attestation.
type FinalizerDeps struct {
	Clients      GitHubClients
	Attestations github.AttestationVerifier
	Jobs         *jobs.Store
}

// DeploymentFinalizer finalizes provisional deployments (spec §20.2 step 2,
// ADR-0011) and requests rollbacks. It is the Deployments service plus what
// reading a commit and enqueueing a job need; wiring passes it as the
// Finalizer of the CI watcher and as the deployments service of the API.
type DeploymentFinalizer struct {
	*Deployments
	clients GitHubClients
	attest  github.AttestationVerifier
	plans   *Plans
}

var _ Finalizer = (*DeploymentFinalizer)(nil)

// NewDeploymentFinalizer validates deps. The job store must have been built
// with this package's Revalidator and LockPlanner.
func NewDeploymentFinalizer(d *Deployments, deps FinalizerDeps) (*DeploymentFinalizer, error) {
	if d == nil || deps.Clients == nil {
		return nil, errors.New("app: the finalizer needs the deployments service and the GitHub clients")
	}
	plans, err := NewPlans(d.cfg, deps.Jobs)
	if err != nil {
		return nil, err
	}
	return &DeploymentFinalizer{Deployments: d, clients: deps.Clients, attest: deps.Attestations, plans: plans}, nil
}

// ---- refusals -------------------------------------------------------------------------------

// refusal is a deployment that cannot be finalized for a reason of its own:
// the deployment fails with this code and reason. Anything else that goes wrong
// is a fault of the infrastructure, and finalizing is tried again.
type refusal struct{ err *smerr.Error }

func (r refusal) Error() string { return r.err.Error() }
func (r refusal) Unwrap() error { return r.err }

var refusalCodes = []smerr.Code{
	smerr.CodeInvalidArgument, smerr.CodeArtifactNotImmutable, smerr.CodePolicyDenied,
	smerr.CodeCapabilityUnavailable, smerr.CodeUnauthenticated, smerr.CodeDeploymentFailed,
}

// refusing turns a typed error that blames the deployment into a refusal and
// leaves every other error alone.
func refusing(err error) error {
	var typed *smerr.Error
	if errors.As(err, &typed) && slices.Contains(refusalCodes, typed.Code) {
		return refusal{typed}
	}
	return err
}

func (r refusal) failure() database.StateFailure {
	f := database.StateFailure{Code: string(r.err.Code), Reason: string(r.err.Reason)}
	if cause, ok := r.err.Details["cause"].(string); ok && f.Reason != "" {
		f.Cause = cause
	}
	return f
}

// failFinalization ends a provisional deployment as failed with the refusal.
func (f *DeploymentFinalizer) failFinalization(ctx context.Context, tx *database.Tx, id domain.ID, r refusal) error {
	row, err := database.GetDeployment(ctx, tx, id)
	if err != nil || !row.State.Provisional() {
		return err
	}
	ctx = audit.WithCorrelationID(ctx, id)
	failure := r.failure()
	if err := database.TransitionDeployment(ctx, tx, id, deployments.StateFailed, failure, f.cfg.Clock.Now()); err != nil {
		return err
	}
	data := map[string]any{"code": failure.Code, "reason": failure.Reason, "detail": r.err.Message}
	if failure.Cause != "" {
		data["cause"] = failure.Cause
	}
	return f.emit(ctx, tx, systemActor, eventDeploymentFailed, deploymentResource(id), domain.ResultFailed, data)
}

// ---- Finalize -------------------------------------------------------------------------------

// Finalize turns a provisional deployment whose CI passed (checks is the
// evidence, nil without a CI gate) into a final plan and a job: it reads the
// manifest and Compose source from the exact commit, binds every digest,
// freezes the model for the target, writes the execution snapshots and the plan
// with its rollback target, evaluates policy including sub-actions and
// enqueues the job. A deployment that cannot be accepted is failed with the
// reason and Finalize returns nil; an error means try again.
func (f *DeploymentFinalizer) Finalize(ctx context.Context, id domain.ID, checks []github.CheckEvidence) error {
	q := f.cfg.DB.Reader()
	dep, err := database.GetDeployment(ctx, q, id)
	if err != nil || !dep.State.Provisional() {
		return err
	}
	scope, err := loadDeploymentScope(ctx, q, dep.AppTargetID)
	if err != nil {
		return err
	}
	remote, err := f.fetchRemote(ctx, scope, dep)
	if err != nil {
		return f.failOrRetry(ctx, id, err)
	}
	return f.failOrRetry(ctx, id, f.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		return f.finalizeIn(ctx, tx, id, scope, remote, checks)
	}))
}

// failOrRetry fails the deployment when err is a refusal and passes any other
// error on.
func (f *DeploymentFinalizer) failOrRetry(ctx context.Context, id domain.ID, err error) error {
	var r refusal
	if !errors.As(err, &r) {
		return err
	}
	return f.write(ctx, func(ctx context.Context, tx *database.Tx) error { return f.failFinalization(ctx, tx, id, r) })
}

func (f *DeploymentFinalizer) finalizeIn(ctx context.Context, tx *database.Tx, id domain.ID, seen deploymentScope, remote remoteInputs, checks []github.CheckEvidence) error {
	dep, err := database.GetDeployment(ctx, tx, id)
	if err != nil || !dep.State.Provisional() {
		return err
	}
	scope, err := loadDeploymentScope(ctx, tx, dep.AppTargetID)
	if err != nil {
		return err
	}
	if scope.app.SpecRevision != seen.app.SpecRevision || scope.target.SpecRevision != seen.target.SpecRevision {
		return errAppMoved
	}
	err = f.finalizeDeploy(ctx, tx, dep, scope, remote, checks)
	var r refusal
	if errors.As(err, &r) {
		return f.failFinalization(ctx, tx, id, r)
	}
	return err
}

// deployed is what a deploy finalization works on.
type deployed struct {
	digest string
	ref    string
}

func deployedOf(dep database.Deployment, scope deploymentScope) (deployed, error) {
	requested, err := requestedImagesOf(dep.RequestedRaw)
	if err != nil {
		return deployed{}, err
	}
	for _, image := range requested {
		if image.Service == scope.spec.DeployedService {
			return deployed{digest: image.Digest, ref: scope.spec.ImagePolicy.Deployed + "@" + image.Digest}, nil
		}
	}
	return deployed{}, refuse(invalidArgument("the request does not name the deployed service %q", scope.spec.DeployedService))
}

func refuse(err error) error {
	var typed *smerr.Error
	if errors.As(err, &typed) {
		return refusal{typed}
	}
	return err
}

func (f *DeploymentFinalizer) finalizeDeploy(ctx context.Context, tx *database.Tx, dep database.Deployment, scope deploymentScope, remote remoteInputs, checks []github.CheckEvidence) error {
	actor, err := f.requester(ctx, tx, dep)
	if err != nil {
		return refusing(err)
	}
	image, err := deployedOf(dep, scope)
	if err != nil {
		return err
	}
	binding := remote.binding
	if !binding.bound() {
		if binding, err = oidcBinding(ctx, tx, dep, scope); err != nil {
			return err
		}
	}
	frozen, eff, err := freezeForTarget(ctx, scope, dep, remote, image, binding)
	if err != nil {
		return refusing(err)
	}
	bindings, secretIns, err := bindSecretVersions(ctx, tx, &frozen)
	if err != nil {
		return refusing(err)
	}
	snapshots, err := newSnapshotSet(f.cfg.Clock.Now(), composeSnapshotOf(frozen), scope.spec.Exceptions, eff)
	if err != nil {
		return err
	}
	target, err := rollbackTargetOf(ctx, tx, scope.target.ID)
	if err != nil {
		return err
	}
	content := deployContent(dep, remote, snapshots, frozen, bindings, target)
	b, err := buildDeploymentPlan(ctx, tx, deploymentPlanSpec{
		action: deploymentCreateAction, requester: dep.RequestedBy, scope: scope, content: content,
		secrets: secretIns, includeApp: true, backup: eff.PreDeployBackup != nil,
	})
	if err != nil {
		return err
	}
	res, err := f.decide(ctx, tx, actor, b)
	if err != nil {
		return err
	}
	if err := refusing(decisionError(res)); err != nil {
		return err
	}
	if err := snapshots.store(ctx, tx); err != nil {
		return err
	}
	if err := recordArtifact(ctx, f.core, tx, dep, image.ref, image.digest, binding, checks); err != nil {
		return err
	}
	return f.enqueue(ctx, tx, dep, b, res, snapshots.compose)
}

// requester is the actor behind the deployment, loaded again now: an identity
// disabled or a credential revoked since the request fails the deployment. A
// credential that merely expired (a session, an Actions token) does not.
func (f *DeploymentFinalizer) requester(ctx context.Context, q database.Querier, dep database.Deployment) (domain.Actor, error) {
	actor, err := loadActor(ctx, q, dep.RequestedBy, dep.Credential)
	if err != nil {
		return domain.Actor{}, err
	}
	return actor, f.requireStillValid(ctx, dep.Credential)
}

// freezeForTarget runs the Compose pipeline for the app target and applies §19
// precedence. The result is the model the plan binds and the effective policy,
// which must include a health check that the frozen model supports.
func freezeForTarget(ctx context.Context, scope deploymentScope, dep database.Deployment, remote remoteInputs, image deployed, binding digestBinding) (compose.Frozen, manifest.EffectivePolicy, error) {
	cp, err := policyOfTarget(scope.target)
	if err != nil {
		return compose.Frozen{}, manifest.EffectivePolicy{}, err
	}
	source := scope.spec.composeSource(image.digest)
	source.BoundDigests = binding.boundDigests(image.ref)
	if remote.composeText != nil {
		source.Raw = remote.composeText
	}
	frozen, err := freezeComposeSource(ctx, source, compose.Target{
		Project: scope.target.ComposeProject, Owner: scope.target.ID, AllowedBind: cp.AllowedBindAddresses,
	})
	if err != nil {
		return compose.Frozen{}, manifest.EffectivePolicy{}, err
	}
	requested, err := requestedImagesOf(dep.RequestedRaw)
	if err != nil {
		return compose.Frozen{}, manifest.EffectivePolicy{}, err
	}
	if err := requireRequestedImages(requested, frozen); err != nil {
		return compose.Frozen{}, manifest.EffectivePolicy{}, err
	}
	eff, err := manifest.Effective(cp, remote.manifest)
	if err != nil {
		return compose.Frozen{}, manifest.EffectivePolicy{}, err
	}
	return frozen, eff, requireDeployablePolicy(eff, scope.env, frozen)
}

// requireDeployablePolicy refuses a target that cannot be deployed safely: a
// stateful production target without a backup, and any target with no health
// check that the frozen model supports (a deployment is only successful when
// its health is verified).
func requireDeployablePolicy(eff manifest.EffectivePolicy, env domain.Environment, frozen compose.Frozen) error {
	if eff.Stateful && env.RiskLevel == domain.EnvironmentProduction && eff.PreDeployBackup == nil {
		return invalidArgument("a stateful target in a production environment needs a pre_deploy_backup")
	}
	check := eff.Health
	if check == nil {
		return invalidArgument("the target has no effective health check: define one in its deployment policy or in the manifest")
	}
	var err error
	if check.Origin == health.OriginManifest {
		_, err = health.ValidateManifest(*check, frozen.HostPorts)
	} else {
		_, err = health.ValidateControlPlane(*check, frozen.HostPorts, eff.AllowedBindAddresses)
	}
	if err != nil {
		return invalidArgument("health check: %v", err)
	}
	return nil
}

// rollbackTargetOf freezes the newest known-good deployment of the target as of
// now; none on a first deployment.
func rollbackTargetOf(ctx context.Context, q database.Querier, target domain.ID) (*plan.RollbackTarget, error) {
	good, err := database.NewestKnownGood(ctx, q, target, nil)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &plan.RollbackTarget{DeploymentID: good.ID.String(), ComposeHash: good.ComposeHash}, nil
}

func deployContent(dep database.Deployment, remote remoteInputs, snap snapshotSet, frozen compose.Frozen, secretBindings []plan.SecretBinding, target *plan.RollbackTarget) plan.Content {
	commit := dep.CommitSha
	images := make([]plan.Image, len(frozen.Images))
	for i, image := range frozen.Images {
		images[i] = plan.Image{Service: image.Service, Ref: image.Ref, Binding: image.Binding}
	}
	return plan.Content{
		CommitSHA: &commit, ManifestBlobSHA: remote.manifestBlob, ComposeHash: &snap.compose, Images: images,
		ExceptionsHash: &snap.exceptions, HealthHash: &snap.health, DeploymentPolicyHash: &snap.deployPol,
		HostPorts: hostPortStrings(frozen.HostPorts), RollbackTarget: target, SecretBindings: secretBindings,
	}
}

// hostPortStrings renders the published ports as addr:port, with /udp for UDP.
func hostPortStrings(ports []compose.HostPort) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		text := netip.AddrPortFrom(p.Addr, p.Port).String()
		if p.Proto == "udp" {
			text += "/udp"
		}
		if !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	return out
}

// ---- the plan -------------------------------------------------------------------------------

// deploymentPlanSpec is what a deployment plan is assembled from. A deploy plan
// reads the app, so it carries the app and its repository as inputs; a rollback
// plan reads only frozen snapshots and carries neither (ADR-0007).
type deploymentPlanSpec struct {
	action     string
	requester  domain.ID
	scope      deploymentScope
	content    plan.Content
	secrets    []plan.Input
	includeApp bool
	backup     bool
}

func buildDeploymentPlan(ctx context.Context, q database.Querier, s deploymentPlanSpec) (built, error) {
	action, ok := policy.Lookup(s.action)
	if !ok {
		return built{}, smerr.New(smerr.CodeInvalidArgument, smerr.ReasonUnknownAction, "unknown action: "+s.action)
	}
	risk, err := policy.RiskFor(s.action, nil)
	if err != nil {
		return built{}, err
	}
	target, err := s.scope.policyTarget(ctx, q, appTargetRef(s.scope.target.ID))
	if err != nil {
		return built{}, err
	}
	inputs, err := deploymentInputs(ctx, q, s)
	if err != nil {
		return built{}, err
	}
	subs, planned, err := backupSubActions(ctx, q, s)
	if err != nil {
		return built{}, err
	}
	revision := s.scope.target.SpecRevision
	return built{
		spec: action, target: target, subs: subs,
		plan: plan.Plan{
			Version: plan.Version, Action: s.action, Actor: "identity/" + s.requester.String(),
			Targets:    []plan.Target{{Type: string(domain.ResourceAppTarget), ID: s.scope.target.ID.String(), SpecRevision: &revision}},
			Inputs:     inputs,
			Content:    s.content,
			SubActions: planned, Parameters: map[string]any{}, Steps: deploymentSteps(s.backup), Risk: risk,
		},
	}, nil
}

func deploymentInputs(ctx context.Context, q database.Querier, s deploymentPlanSpec) ([]plan.Input, error) {
	node, err := database.GetNode(ctx, q, s.scope.target.NodeID)
	if err != nil {
		return nil, err
	}
	pinned, err := nodeInput(node)
	if err != nil {
		return nil, refusing(err)
	}
	inputs := []plan.Input{revisionInput(domain.ResourceEnvironment, s.scope.env.ID, s.scope.env.SpecRevision), pinned}
	if s.includeApp {
		inputs = append(inputs, revisionInput(domain.ResourceApp, s.scope.app.ID, s.scope.app.SpecRevision))
		if repo := s.scope.repo; repo != nil {
			inputs = append(inputs, plan.Input{Type: plan.InputTypeRepository, ID: repo.ID.String(), SpecRevision: &repo.SpecRevision})
		}
	}
	return append(inputs, s.secrets...), nil
}

// nodeInput pins the node's management endpoint and host key (spec §6.4).
func nodeInput(node domain.Node) (plan.Input, error) {
	fingerprint, err := sshnode.Fingerprint(node.Endpoint.HostPublicKey)
	if err != nil {
		return plan.Input{}, err
	}
	revision := node.SpecRevision
	return plan.Input{
		Type: string(domain.ResourceNode), ID: node.ID.String(), SpecRevision: &revision,
		Endpoint:            &plan.Endpoint{Address: node.Endpoint.Host, Port: int64(node.Endpoint.Port), User: node.Endpoint.User},
		HostPublicKeySHA256: &fingerprint,
	}, nil
}

// backupSubActions adds node.backup_template.run, evaluated by policy with the
// action, when the deployment backs up before it deploys (spec §11.3).
func backupSubActions(ctx context.Context, q database.Querier, s deploymentPlanSpec) ([]policy.SubAction, []plan.SubAction, error) {
	if !s.backup {
		return nil, nil, nil
	}
	nodeRef := domain.ResourceRef{Type: domain.ResourceNode, ID: s.scope.target.NodeID}
	nodeTarget, err := s.scope.policyTarget(ctx, q, nodeRef)
	if err != nil {
		return nil, nil, err
	}
	sub := policy.SubAction{Action: policy.ActionNodeBackupTemplateRun, Target: nodeTarget}
	planned := plan.SubAction{
		Action: policy.ActionNodeBackupTemplateRun, Target: plan.SubTarget{Type: string(nodeRef.Type), ID: nodeRef.ID.String()},
	}
	return []policy.SubAction{sub}, []plan.SubAction{planned}, nil
}

// deploymentSteps is the plan's step list in App. C order. The snapshot step is
// never planned (a Proxmox snapshot is refused in this version) and the backup
// step only when a backup is configured.
func deploymentSteps(backup bool) []string {
	steps := []string{deployments.StepPreflight}
	if backup {
		steps = append(steps, deployments.StepPreDeployBackup)
	}
	return append(steps, deployments.StepPull, deployments.StepMaterialize, deployments.StepVerifyOnNode,
		deployments.StepDeploy, deployments.StepHealthCheck)
}

// decide evaluates the plan for the requester and audits a refusal.
func (f *DeploymentFinalizer) decide(ctx context.Context, q database.Querier, actor domain.Actor, b built) (policy.Result, error) {
	res := f.authorize(b.request(actor))
	return res, f.auditDecision(ctx, q, actor, b.plan.Action, b.target.Ref, res)
}

// enqueue stores the plan, enqueues its job with the requester's stored
// credential context and moves the deployment on: awaiting approval when
// policy asks for it, queued otherwise.
func (f *DeploymentFinalizer) enqueue(ctx context.Context, tx *database.Tx, dep database.Deployment, b built, res policy.Result, composeHash string) error {
	ctx = audit.WithCorrelationID(ctx, dep.ID)
	by := Caller{ID: dep.RequestedBy, Credential: dep.Credential}
	rec, err := f.plans.persist(ctx, tx, by, b.plan)
	if err != nil {
		return err
	}
	job, err := f.plans.enqueue(ctx, tx, by, rec, b, res)
	if err != nil {
		return err
	}
	if err := database.MarkSubmitted(ctx, tx, rec.ID, job.ID); err != nil {
		return err
	}
	now := f.cfg.Clock.Now()
	if err := database.BindDeploymentPlan(ctx, tx, dep.ID, rec.ID, job.ID, rec.PlanHash, composeHash, now); err != nil {
		return err
	}
	next := deployments.StateQueued
	if res.ApprovalRequired {
		next = deployments.StateAwaitingApproval
	}
	if err := database.TransitionDeployment(ctx, tx, dep.ID, next, database.StateFailure{}, now); err != nil {
		return err
	}
	return f.emit(ctx, tx, systemActor, eventDeploymentFinalized, deploymentResource(dep.ID), domain.ResultSucceeded, map[string]any{
		"plan_id": rec.ID.String(), "plan_hash": rec.PlanHash, "job_id": job.ID.String(), "kind": dep.Kind,
		"compose_hash": composeHash, "approval_required": res.ApprovalRequired,
	})
}

// ---- reading the commit ---------------------------------------------------------------------

// remoteInputs is what finalizing reads from GitHub for the exact commit,
// outside any transaction: the manifest, a repository-sourced Compose file and
// the attestation of the deployed digest.
type remoteInputs struct {
	manifest     *manifest.Manifest
	manifestBlob *string
	composeText  []byte
	binding      digestBinding
}

func (f *DeploymentFinalizer) fetchRemote(ctx context.Context, scope deploymentScope, dep database.Deployment) (remoteInputs, error) {
	if scope.repo == nil {
		return remoteInputs{}, nil
	}
	image, err := deployedOf(dep, scope)
	if err != nil {
		return remoteInputs{}, err
	}
	client, err := f.clients.For(ctx, scope.repo.ProviderID)
	if err != nil {
		return remoteInputs{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, finalizeFetchTimeout)
	defer cancel()
	reader := commitReader{ctx: ctx, client: client, repo: githubRepoOf(*scope.repo), commit: dep.CommitSha}
	var in remoteInputs
	if in.manifest, in.manifestBlob, err = reader.manifest(scope.spec.ManifestPath, scope.spec.DeployedService); err != nil {
		return remoteInputs{}, err
	}
	if scope.spec.ComposeSource == composeSourceRepository {
		if in.composeText, err = reader.composeFile(in.manifest); err != nil {
			return remoteInputs{}, err
		}
	}
	in.binding, err = attestationBinding(ctx, client, f.attest, scope, dep.CommitSha, image.digest)
	return in, err
}

// commitReader reads files at one exact commit, never at a branch head.
type commitReader struct {
	ctx    context.Context
	client github.Client
	repo   github.Repo
	commit string
}

// manifest reads and checks the manifest; absent is fine (nil, nil).
func (r commitReader) manifest(path, deployedService string) (*manifest.Manifest, *string, error) {
	file, err := r.client.File(r.ctx, r.repo, r.commit, path, github.MaxFileBytes)
	switch {
	case isGitHubNotFound(err):
		return nil, nil, nil
	case errors.Is(err, github.ErrFileTooLarge):
		return nil, nil, refuse(smerr.FromReason(smerr.ReasonManifestInvalid, "the manifest is too large"))
	case err != nil:
		return nil, nil, fmt.Errorf("read the manifest at %s: %w", r.commit, err)
	}
	parsed, err := manifest.Parse(file.Content)
	if err != nil {
		return nil, nil, refuse(smerr.Wrap(err, smerr.CodeInvalidArgument, smerr.ReasonManifestInvalid, "the manifest is invalid"))
	}
	if parsed.Spec.Deployment.Service != deployedService {
		return nil, nil, refuse(smerr.FromReason(smerr.ReasonManifestInvalid, "the manifest's deployment.service is not the app's deployed service"))
	}
	return &parsed, &file.BlobSHA, nil
}

// composeFile reads the Compose file the manifest names (compose_source repository).
func (r commitReader) composeFile(m *manifest.Manifest) ([]byte, error) {
	if m == nil || m.Spec.Deployment.ComposeFile == "" {
		return nil, refuse(smerr.FromReason(smerr.ReasonComposeRejected, "compose_source repository needs a manifest that names composeFile"))
	}
	file, err := r.client.File(r.ctx, r.repo, r.commit, m.Spec.Deployment.ComposeFile, compose.MaxRawBytes)
	switch {
	case isGitHubNotFound(err), errors.Is(err, github.ErrFileTooLarge):
		return nil, refuse(smerr.FromReason(smerr.ReasonComposeRejected, "the Compose file is missing or too large at the commit"))
	case err != nil:
		return nil, fmt.Errorf("read the Compose file at %s: %w", r.commit, err)
	}
	return file.Content, nil
}

func isGitHubNotFound(err error) bool {
	var api *github.APIError
	return errors.As(err, &api) && api.Status == 404
}
