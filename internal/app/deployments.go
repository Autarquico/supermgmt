package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

// The actions and events of the deployment request (spec §20.0, ADR-0011).
const (
	deploymentCreateAction = "deployment.create"
	deploymentReadAction   = "deployment.read"

	eventDeploymentCreated   = "deployment.created"
	eventDeploymentCancelled = "deployment.cancelled"
	eventDeploymentFailed    = "deployment.failed"

	maxRequestedImages = 64
	maxDeploymentsPage = 500
)

var (
	deploymentCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	deploymentDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// jobCanceller is Governance.Cancel: once a deployment has a job, cancelling
// the deployment is cancelling that job (ADR-0011).
type jobCanceller interface {
	Cancel(ctx context.Context, by Caller, job domain.ID, planHash string) (jobs.Job, error)
}

// Deployments takes deployment requests (spec §20.0, ADR-0011). A request is
// recorded with its provisional inputs only: the target, the exact commit, the
// requested digests and the requester's credential context. Finalization (the
// final plan) and the CI watcher that triggers it are separate.
type Deployments struct {
	core
	poll      CIPolling
	canceller jobCanceller
}

// NewDeployments validates cfg. The governance service cancels the jobs of
// finalized deployments.
func NewDeployments(cfg Config, governance *Governance, poll CIPolling) (*Deployments, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if governance == nil {
		return nil, errors.New("app: deployments need the governance service")
	}
	return &Deployments{core: c, poll: poll.withDefaults(), canceller: governance}, nil
}

func deploymentResource(id domain.ID) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceDeployment, ID: id}
}

// ---- the scope of a request ---------------------------------------------------------------

// deploymentScope is everything a deployment of one app target is judged on.
type deploymentScope struct {
	target database.AppTarget
	app    database.App
	spec   appSpec
	repo   *database.Repository
	env    domain.Environment
}

func loadDeploymentScope(ctx context.Context, q database.Querier, targetID domain.ID) (deploymentScope, error) {
	target, err := database.GetAppTarget(ctx, q, targetID)
	if err != nil {
		return deploymentScope{}, err
	}
	return scopeOfTarget(ctx, q, target)
}

func scopeOfTarget(ctx context.Context, q database.Querier, target database.AppTarget) (deploymentScope, error) {
	app, err := database.GetApp(ctx, q, target.AppID)
	if err != nil {
		return deploymentScope{}, err
	}
	env, err := database.GetEnvironment(ctx, q, target.EnvironmentID)
	if err != nil {
		return deploymentScope{}, err
	}
	scope := deploymentScope{target: target, app: app, env: env}
	if app.RepositoryID != nil {
		repo, err := database.GetRepository(ctx, q, *app.RepositoryID)
		if err != nil {
			return deploymentScope{}, err
		}
		scope.repo = &repo
	}
	if scope.spec, err = specOfRow(app, scope.repo); err != nil {
		return deploymentScope{}, err
	}
	return scope, nil
}

// gated reports whether the app requires CI before it deploys (spec §18).
func (s deploymentScope) gated() bool { return s.spec.CI != nil && s.repo != nil }

// policyTarget is the policy view of the app target: the node's attributes and
// capabilities with the environment and app of the target itself.
func (s deploymentScope) policyTarget(ctx context.Context, q database.Querier, ref domain.ResourceRef) (policy.Target, error) {
	node, err := resolveNode(ctx, q, s.target.NodeID)
	if err != nil {
		return policy.Target{}, err
	}
	target := node.target
	target.Ref = ref
	target.Attrs.Environment, target.Attrs.EnvironmentRisk = s.env.Name, s.env.RiskLevel
	target.Attrs.ApprovalsRequired, target.Attrs.App = s.env.ApprovalsRequired, s.app.Name
	return target, nil
}

// ---- Create ---------------------------------------------------------------------------------

// deploymentRequest is a validated CreateDeployment in canonical form.
type deploymentRequest struct {
	targetID domain.ID
	commit   string
	images   []wire.RequestedImage
}

func requestOf(r CreateDeployment) (deploymentRequest, error) {
	switch {
	case r.AppTargetID == "":
		return deploymentRequest{}, invalidArgument("app_target_id is required")
	case !deploymentCommitPattern.MatchString(r.CommitSHA):
		return deploymentRequest{}, invalidArgument("commit_sha must be the full 40-character lower-case commit id")
	case len(r.Images) == 0 || len(r.Images) > maxRequestedImages:
		return deploymentRequest{}, invalidArgument("images needs between 1 and %d entries", maxRequestedImages)
	}
	images := make([]wire.RequestedImage, len(r.Images))
	for i, image := range r.Images {
		if !composeServiceName.MatchString(image.Service) {
			return deploymentRequest{}, invalidArgument("image service %q is not a valid service name", image.Service)
		}
		if !deploymentDigestPattern.MatchString(image.Digest) {
			return deploymentRequest{}, invalidArgument("image %q needs a digest of the form sha256:<64 hex>", image.Service)
		}
		images[i] = wire.RequestedImage{Service: image.Service, Digest: image.Digest}
	}
	slices.SortFunc(images, func(a, b wire.RequestedImage) int { return strings.Compare(a.Service, b.Service) })
	for i := 1; i < len(images); i++ {
		if images[i].Service == images[i-1].Service {
			return deploymentRequest{}, invalidArgument("image service %q is named twice", images[i].Service)
		}
	}
	return deploymentRequest{targetID: r.AppTargetID, commit: r.CommitSHA, images: images}, nil
}

// Create records a provisional deployment (action deployment.create): it
// authorizes the request, checks that the credential is entitled to this
// commit, stores the provisional inputs and, when the app has a CI gate, waits
// for CI. Nothing is planned yet; the CI watcher (or, without a gate, its next
// pass) finalizes it.
func (d *Deployments) Create(ctx context.Context, by Caller, r CreateDeployment) (DeploymentView, error) {
	req, err := requestOf(r)
	if err != nil {
		return DeploymentView{}, err
	}
	return commit(ctx, d.core, by, func(ctx context.Context, tx *database.Tx) (DeploymentView, error) {
		actor, err := d.beginRequest(ctx, tx, by)
		if err != nil {
			return DeploymentView{}, err
		}
		scope, err := loadDeploymentScope(ctx, tx, req.targetID)
		if err != nil {
			return DeploymentView{}, err
		}
		if err := d.authorizeCreate(ctx, tx, actor, scope); err != nil {
			return DeploymentView{}, err
		}
		if err := requireDeployedImage(scope, req.images); err != nil {
			return DeploymentView{}, err
		}
		if err := requireEntitled(ctx, tx, by, scope, req.commit); err != nil {
			return DeploymentView{}, err
		}
		row, err := d.insertProvisional(ctx, tx, by, actor, scope, req)
		if err != nil {
			return DeploymentView{}, err
		}
		return d.viewOf(ctx, tx, row)
	})
}

func (d *Deployments) authorizeCreate(ctx context.Context, q database.Querier, actor domain.Actor, scope deploymentScope) error {
	target, err := scope.policyTarget(ctx, q, appTargetRef(scope.target.ID))
	if err != nil {
		return err
	}
	res := d.authorize(policy.Request{Actor: actor, Action: deploymentCreateAction, Targets: []policy.Target{target}})
	if err := d.auditDecision(ctx, q, actor, deploymentCreateAction, target.Ref, res); err != nil {
		return err
	}
	if err := decisionError(res); err != nil {
		return reject(err)
	}
	return nil
}

// requireDeployedImage insists the request names the deployed service: the
// digest every other check of the deployment is about.
func requireDeployedImage(scope deploymentScope, images []wire.RequestedImage) error {
	if slices.ContainsFunc(images, func(i wire.RequestedImage) bool { return i.Service == scope.spec.DeployedService }) {
		return nil
	}
	return invalidArgument("images must name the deployed service %q", scope.spec.DeployedService)
}

func (d *Deployments) insertProvisional(ctx context.Context, tx *database.Tx, by Caller, actor domain.Actor, scope deploymentScope, req deploymentRequest) (database.Deployment, error) {
	now := d.cfg.Clock.Now()
	requested, err := json.Marshal(req.images)
	if err != nil {
		return database.Deployment{}, fmt.Errorf("encode requested images: %w", err)
	}
	row := database.Deployment{
		ID: d.cfg.IDs.NewID(), Kind: deployments.KindDeploy, AppID: scope.app.ID, AppTargetID: scope.target.ID,
		EnvironmentID: scope.env.ID, NodeID: scope.target.NodeID, State: deployments.StateCreated,
		RequestedBy: by.ID, CommitSha: req.commit, RequestedRaw: requested, Credential: by.Credential,
		CreatedAt: now, UpdatedAt: now,
	}
	if scope.gated() {
		deadline := now.Add(d.poll.Timeout)
		row.CIDeadlineAt, row.NextCICheck = &deadline, &now
	}
	ctx = audit.WithCorrelationID(ctx, row.ID)
	if err := database.InsertDeployment(ctx, tx, row); err != nil {
		return database.Deployment{}, err
	}
	data := map[string]any{
		"app_target_id": scope.target.ID.String(), "commit_sha": req.commit, "kind": row.Kind,
		"ci_gated": scope.gated(), "credential_kind": string(by.Credential.Kind),
	}
	if err := d.emit(ctx, tx, actor, eventDeploymentCreated,
		deploymentResource(row.ID), domain.ResultSucceeded, data); err != nil {
		return database.Deployment{}, err
	}
	if !scope.gated() {
		return row, nil
	}
	if err := database.TransitionDeployment(ctx, tx, row.ID, deployments.StateWaitingCI, database.StateFailure{}, now); err != nil {
		return database.Deployment{}, err
	}
	return database.GetDeployment(ctx, tx, row.ID)
}

// ---- GitHub Actions OIDC entitlement -------------------------------------------------------

// oidcStoredClaims reads github_oidc_credentials.claims_json, which the OIDC
// bearer resolver writes (internal/auth/github.go): the §18 claims under their
// GitHub names.
type oidcStoredClaims struct {
	RepositoryID   int64  `json:"repository_id"`
	WorkflowRef    string `json:"workflow_ref"`
	JobWorkflowRef string `json:"job_workflow_ref"`
	SHA            string `json:"sha"`
	Ref            string `json:"ref"`
	EventName      string `json:"event_name"`
	Environment    string `json:"environment"`
	RunID          int64  `json:"run_id"`
	RunAttempt     int64  `json:"run_attempt"`
}

// requireEntitled lets a GitHub Actions token deploy only the commit its
// claims were issued for, through the automation identity linked to this app
// (spec §18). The claims are the ones stored when the token was verified, so a
// CI wait longer than the token's lifetime changes nothing. Every other
// credential kind is judged by policy alone.
func requireEntitled(ctx context.Context, q database.Querier, by Caller, scope deploymentScope, commitSHA string) error {
	if by.Credential.Kind != domain.CredentialGitHubOIDC {
		return nil
	}
	denied := func(msg string, cause error) error {
		return reject(smerr.Wrap(cause, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, msg))
	}
	if scope.spec.CI == nil || scope.app.AutomationIdentityID == nil || *scope.app.AutomationIdentityID != by.ID {
		return denied("this identity is not the automation identity of the app", nil)
	}
	stored, err := database.GetGithubOIDCCredential(ctx, q, by.Credential.ID)
	if err != nil {
		return err
	}
	var claims oidcStoredClaims
	if err := json.Unmarshal(stored.ClaimsJSON, &claims); err != nil {
		return fmt.Errorf("stored oidc claims are unreadable: %w", err)
	}
	ciPolicy := githubCIPolicy(*scope.spec.CI)
	if err := github.MatchClaims(claims.verified(ciPolicy), ciPolicy, commitSHA, github.EnvRequirement{}); err != nil {
		return denied("the token's claims do not entitle this deployment", err)
	}
	return nil
}

// verified rebuilds the claims MatchClaims judges. The repository name comes
// from workflow_ref (<owner>/<repo>/<path>@<ref>) and is blank, so the match
// fails, when workflow_ref does not have that shape. The owner id is not
// stored with the credential: the resolver already bound the token to the
// repository id and workflow of the app's automation identity, so the policy's
// own owner id stands in for it.
func (c oidcStoredClaims) verified(p github.CIPolicy) github.Claims {
	repository, _ := strings.CutSuffix(c.WorkflowRef, "/"+p.DeployWorkflow+"@"+c.Ref)
	return github.Claims{
		RepositoryID: c.RepositoryID, RepositoryOwnerID: p.OwnerID, Repository: repository,
		Ref: c.Ref, SHA: c.SHA, EventName: c.EventName, WorkflowRef: c.WorkflowRef,
		JobWorkflowRef: c.JobWorkflowRef, Environment: c.Environment, RunID: c.RunID, RunAttempt: c.RunAttempt,
	}
}

func githubCIPolicy(ci wire.CIPolicy) github.CIPolicy {
	checks := make([]github.RequiredCheck, len(ci.RequiredChecks))
	for i, c := range ci.RequiredChecks {
		checks[i] = github.RequiredCheck{Name: c.Name, AppID: c.AppID, WorkflowPath: c.WorkflowPath}
	}
	return github.CIPolicy{
		RepositoryID: ci.RepositoryID, OwnerID: ci.OwnerID, Branch: ci.Branch, AllowedEvents: ci.AllowedEvents,
		RequiredChecks: checks, DeployWorkflow: ci.DeployWorkflow, DeployReusableWorkflow: ci.DeployReusableWorkflow,
	}
}

// ---- Cancel ---------------------------------------------------------------------------------

// Cancel cancels a deployment (action job.cancel). Before finalization there
// is no job: the deployment moves to cancelled itself. Once a job exists the
// request is that job's cancel, under §20.1's rules (ADR-0011).
func (d *Deployments) Cancel(ctx context.Context, by Caller, id domain.ID) (DeploymentView, error) {
	row, err := database.GetDeployment(ctx, d.cfg.DB.Reader(), id)
	if err != nil {
		return DeploymentView{}, err
	}
	if row.JobID == nil {
		return d.cancelProvisional(ctx, by, id)
	}
	if _, err := d.canceller.Cancel(ctx, by, *row.JobID, row.PlanHash); err != nil {
		return DeploymentView{}, err
	}
	return d.Get(ctx, by, id)
}

func (d *Deployments) cancelProvisional(ctx context.Context, by Caller, id domain.ID) (DeploymentView, error) {
	return commit(ctx, d.core, by, func(ctx context.Context, tx *database.Tx) (DeploymentView, error) {
		actor, err := d.beginRequest(ctx, tx, by)
		if err != nil {
			return DeploymentView{}, err
		}
		row, err := database.GetDeployment(ctx, tx, id)
		if err != nil {
			return DeploymentView{}, err
		}
		if row.JobID != nil {
			return DeploymentView{}, smerr.New(smerr.CodeConflict, "", "the deployment was finalized meanwhile; cancel it again")
		}
		if err := d.authorizeCancel(ctx, tx, actor, row); err != nil {
			return DeploymentView{}, err
		}
		ctx = audit.WithCorrelationID(ctx, id)
		now := d.cfg.Clock.Now()
		if err := database.TransitionDeployment(ctx, tx, id, deployments.StateCancelled, database.StateFailure{}, now); err != nil {
			return DeploymentView{}, err
		}
		if err := d.emit(ctx, tx, actor, eventDeploymentCancelled, deploymentResource(id), domain.ResultSucceeded,
			map[string]any{"from_state": string(row.State)}); err != nil {
			return DeploymentView{}, err
		}
		cancelled, err := database.GetDeployment(ctx, tx, id)
		if err != nil {
			return DeploymentView{}, err
		}
		return d.viewOf(ctx, tx, cancelled)
	})
}

func (d *Deployments) authorizeCancel(ctx context.Context, q database.Querier, actor domain.Actor, row database.Deployment) error {
	scope, err := loadDeploymentScope(ctx, q, row.AppTargetID)
	if err != nil {
		return err
	}
	target, err := scope.policyTarget(ctx, q, appTargetRef(scope.target.ID))
	if err != nil {
		return err
	}
	res := d.cfg.Policy.EvaluateGovernance(actor, policy.ActionJobCancel, []policy.Target{target}, nil)
	if err := d.auditDecision(ctx, q, actor, policy.ActionJobCancel, deploymentResource(row.ID), res); err != nil {
		return err
	}
	if err := decisionError(res); err != nil {
		return reject(err)
	}
	return nil
}

// ---- reads ----------------------------------------------------------------------------------

// Get returns one deployment with its steps (action deployment.read).
func (d *Deployments) Get(ctx context.Context, by Caller, id domain.ID) (DeploymentView, error) {
	q := d.cfg.DB.Reader()
	row, err := database.GetDeployment(ctx, q, id)
	if err != nil {
		return DeploymentView{}, err
	}
	if err := d.authorizeRead(ctx, by, q, row); err != nil {
		return DeploymentView{}, err
	}
	return d.viewOf(ctx, q, row)
}

// List returns the deployments the caller may read, newest first, among the
// most recent maxDeploymentsPage that match f.
func (d *Deployments) List(ctx context.Context, by Caller, f database.DeploymentFilter, page wire.PageQuery) (wire.Page[DeploymentView], error) {
	q := d.cfg.DB.Reader()
	actor, err := d.beginRequest(ctx, q, by)
	if err != nil {
		return wire.Page[DeploymentView]{}, err
	}
	rows, err := database.ListDeployments(ctx, q, f, maxDeploymentsPage)
	if err != nil {
		return wire.Page[DeploymentView]{}, err
	}
	readable := make([]database.Deployment, 0, len(rows))
	for _, row := range rows {
		allowed, err := d.mayRead(ctx, q, actor, row)
		if err != nil {
			return wire.Page[DeploymentView]{}, err
		}
		if allowed {
			readable = append(readable, row)
		}
	}
	paged, err := paginate(readable, page, func(row database.Deployment) domain.ID { return row.ID })
	if err != nil {
		return wire.Page[DeploymentView]{}, err
	}
	out := wire.Page[DeploymentView]{Items: make([]DeploymentView, len(paged.items)), NextCursor: paged.next}
	for i, row := range paged.items {
		if out.Items[i], err = d.viewOf(ctx, q, row); err != nil {
			return wire.Page[DeploymentView]{}, err
		}
	}
	return out, nil
}

func (d *Deployments) readRequest(ctx context.Context, q database.Querier, actor domain.Actor, row database.Deployment) (policy.Request, error) {
	scope, err := loadDeploymentScope(ctx, q, row.AppTargetID)
	if err != nil {
		return policy.Request{}, err
	}
	target, err := scope.policyTarget(ctx, q, deploymentResource(row.ID))
	if err != nil {
		return policy.Request{}, err
	}
	return policy.Request{Actor: actor, Action: deploymentReadAction, Targets: []policy.Target{target}}, nil
}

func (d *Deployments) mayRead(ctx context.Context, q database.Querier, actor domain.Actor, row database.Deployment) (bool, error) {
	req, err := d.readRequest(ctx, q, actor, row)
	if err != nil {
		return false, err
	}
	return d.authorize(req).Decision == policy.DecisionAllow, nil
}

func (d *Deployments) authorizeRead(ctx context.Context, by Caller, q database.Querier, row database.Deployment) error {
	actor, err := d.beginRequest(ctx, q, by)
	if err != nil {
		return err
	}
	req, err := d.readRequest(ctx, q, actor, row)
	if err != nil {
		return err
	}
	res := d.authorize(req)
	if res.Decision == policy.DecisionAllow {
		return nil
	}
	return d.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := d.auditDecision(ctx, tx, actor, deploymentReadAction, req.Targets[0].Ref, res); err != nil {
			return err
		}
		return reject(decisionError(res))
	})
}

// ---- views ----------------------------------------------------------------------------------

// viewOf is the wire shape of a deployment with its steps.
func (d *Deployments) viewOf(ctx context.Context, q database.Querier, row database.Deployment) (DeploymentView, error) {
	images, err := requestedImagesOf(row.RequestedRaw)
	if err != nil {
		return DeploymentView{}, err
	}
	steps, err := database.ListDeploymentSteps(ctx, q, row.ID)
	if err != nil {
		return DeploymentView{}, err
	}
	view := DeploymentView{
		ID: row.ID, Kind: row.Kind, AppID: row.AppID, AppTargetID: row.AppTargetID, EnvironmentID: row.EnvironmentID,
		NodeID: row.NodeID, CommitSHA: row.CommitSha, Images: images, ArtifactID: row.ArtifactID, PlanID: row.PlanID,
		PlanHash: textOrNil(row.PlanHash), JobID: row.JobID, State: string(row.State),
		StateCode: smerr.Code(row.Failure.Code), StateReason: smerr.Reason(row.Failure.Reason),
		RequestedBy: row.RequestedBy, PreviousDeploymentID: row.PreviousDeploymentID,
		RollbackOfDeploymentID: row.RollbackOfDeploymentID, KnownGood: row.KnownGood,
		ComposeHash: textOrNil(row.ComposeHash), Steps: make([]wire.DeploymentStep, len(steps)),
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, FinishedAt: row.FinishedAt,
	}
	for i, s := range steps {
		if view.Steps[i], err = stepView(s); err != nil {
			return DeploymentView{}, err
		}
	}
	return view, nil
}

func textOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func requestedImagesOf(raw json.RawMessage) ([]wire.RequestedImage, error) {
	images := []wire.RequestedImage{}
	switch strings.TrimSpace(string(raw)) {
	case "", "{}", "null":
		return images, nil
	}
	if err := json.Unmarshal(raw, &images); err != nil {
		return nil, fmt.Errorf("stored requested images are unreadable: %w", err)
	}
	return images, nil
}

func stepView(s database.DeploymentStep) (wire.DeploymentStep, error) {
	view := wire.DeploymentStep{
		Ordinal: s.Ordinal, Name: s.Name, State: string(s.State), Attempt: s.Attempt,
		StartedAt: s.StartedAt, FinishedAt: s.FinishedAt, OutputRef: s.OutputRef,
	}
	if len(s.ErrorJSON) == 0 {
		return view, nil
	}
	var stepErr wire.StepError
	if err := json.Unmarshal(s.ErrorJSON, &stepErr); err != nil {
		return wire.DeploymentStep{}, fmt.Errorf("stored step error is unreadable: %w", err)
	}
	view.Error = &stepErr
	return view, nil
}

// failProvisional ends a provisional deployment as failed with its reason and
// audits it. A deployment that is no longer provisional (cancelled, finalized
// elsewhere) is left alone.
func (c core) failProvisional(ctx context.Context, tx *database.Tx, id domain.ID, reason smerr.Reason, data map[string]any) error {
	row, err := database.GetDeployment(ctx, tx, id)
	if err != nil {
		return err
	}
	if row.State != deployments.StateCreated && row.State != deployments.StateWaitingCI {
		return nil
	}
	ctx = audit.WithCorrelationID(ctx, id)
	failure := database.StateFailure{Code: string(smerr.CodeFor(reason)), Reason: string(reason)}
	if err := database.TransitionDeployment(ctx, tx, id, deployments.StateFailed, failure, c.cfg.Clock.Now()); err != nil {
		return err
	}
	data["code"], data["reason"] = failure.Code, failure.Reason
	return c.emit(ctx, tx, systemActor, eventDeploymentFailed, deploymentResource(id), domain.ResultFailed, data)
}
