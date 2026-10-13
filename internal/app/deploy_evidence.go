package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Operation names of the deployment intents (deploy_handler.go, deploy_restore.go).
const (
	operationComposePull        = "compose.pull"
	operationComposeMaterialize = "compose.materialize"
	operationComposeUp          = "compose.up"
)

// composeServiceLabel is the label Compose puts on each container it creates.
const composeServiceLabel = "com.docker.compose.service"

var errDeploymentContainersUnsettled = errors.New("the project's containers are still changing")

// DeploymentEvidence implements jobs.EvidenceSource for the dispatched intents
// of deployments (ADR-0029). Completion is proven only by the node-side marker
// (.done holding exit 0), exactly as for service actions; a marker that never
// appeared proves the command never began. What the project looks like after a
// proven `compose up` is a separate judgement, classified from the containers:
//
//	complete        every container belongs to this deployment's directory, runs
//	                the frozen digest, and every frozen service is present
//	not_started     no container carries this deployment's label
//	partial_stable  anything in between, with no container still changing
//
// A project whose containers are still changing, or any read that fails, is an
// error, which the reconciler reads as "no evidence yet".
type DeploymentEvidence struct {
	core
	dial   func(domain.Node, *runtimes.SetupMeta) (transport.Executor, error)
	intent *jobs.Store
}

var _ jobs.EvidenceSource = (*DeploymentEvidence)(nil)

// NewDeploymentEvidence validates cfg. store lists the intents of a job, which
// a restore-deploy needs to find the directory its restore-materialize wrote.
func NewDeploymentEvidence(cfg Config, conn Connector, store *jobs.Store) (*DeploymentEvidence, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("app: deployment evidence needs the job store")
	}
	return &DeploymentEvidence{core: c, dial: conn.Automated, intent: store}, nil
}

// Collect gathers evidence for one dispatched deployment intent.
func (e *DeploymentEvidence) Collect(ctx context.Context, intent jobs.Intent) (jobs.Evidence, error) {
	if intent.DispatchedAt == nil {
		return jobs.Evidence{}, fmt.Errorf("intent %s was never dispatched", intent.ID)
	}
	q := e.cfg.DB.Reader()
	dep, err := database.GetDeployment(ctx, q, domain.ID(intent.TargetID))
	if err != nil {
		return jobs.Evidence{}, err
	}
	node, err := database.GetNode(ctx, q, dep.NodeID)
	if err != nil {
		return jobs.Evidence{}, err
	}
	setup, err := loadSetup(ctx, q, node.ID)
	if err != nil {
		return jobs.Evidence{}, err
	}
	ex, err := e.dial(node, setup)
	if err != nil {
		return jobs.Evidence{}, err
	}
	state, err := markerState(ctx, ex, intent.Marker)
	if err != nil {
		return jobs.Evidence{}, err
	}
	switch state.Kind {
	case templates.MarkerAbsent:
		return markerAbsent(intent), nil
	case templates.MarkerStarted, templates.MarkerDone:
		return e.observed(ctx, ex, dep, intent, state)
	case templates.MarkerUnavailable:
	}
	return jobs.Evidence{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "the node's markers directory cannot be read")
}

func (e *DeploymentEvidence) observed(ctx context.Context, ex transport.Executor, dep database.Deployment,
	intent jobs.Intent, state templates.MarkerState,
) (jobs.Evidence, error) {
	ev := jobs.Evidence{Done: state.Kind == templates.MarkerDone, ExitStatus: state.ExitStatus}
	if ev.Done {
		ev.Proof = jobs.ProofDoneFile
	}
	var fingerprint deploymentFingerprint
	switch intent.Operation {
	case operationComposePull, operationComposeMaterialize, policy.ActionNodeBackupTemplateRun:
		ev.Classification, fingerprint = markerClassification(state), deploymentFingerprint{Marker: string(state.Kind), Exit: state.ExitStatus}
	case operationComposeUp:
		class, containers, err := e.classifyUp(ctx, ex, dep, intent)
		if err != nil {
			return jobs.Evidence{}, err
		}
		ev.Classification = class
		fingerprint = deploymentFingerprint{Marker: string(state.Kind), Exit: state.ExitStatus, Containers: containers}
	default:
		return jobs.Evidence{}, fmt.Errorf("no evidence source for deployment operation %q", intent.Operation)
	}
	raw, err := json.Marshal(fingerprint)
	if err != nil {
		return jobs.Evidence{}, fmt.Errorf("encode deployment fingerprint: %w", err)
	}
	ev.Fingerprint = raw
	return withFingerprint(ev, intent)
}

// markerClassification is the judgement for an operation whose only outcome is
// its exit status: a command that ran to exit 0 is complete. Anything else is
// unknown, and without proof it is never acted on anyway.
func markerClassification(state templates.MarkerState) jobs.Classification {
	if state.CompletionProof() {
		return jobs.ClassComplete
	}
	return jobs.ClassUnknown
}

// deploymentFingerprint is what two samples must agree on to form a pair.
type deploymentFingerprint struct {
	Marker     string   `json:"marker"`
	Exit       int      `json:"exit"`
	Containers []string `json:"containers,omitempty"`
}

// ---- compose up: judging the project's containers -----------------------------------------------

// upExpectation is what a finished `compose up` leaves behind: the directory
// (deployment label) it ran from and the digest each service must run.
type upExpectation struct {
	directory domain.ID
	images    map[string]string // service -> repo@sha256:<hex>
}

// upContainer is the part of `docker inspect` the classification reads.
type upContainer struct {
	ID     string `json:"Id"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status   string `json:"Status"`
		ExitCode int    `json:"ExitCode"`
	} `json:"State"`
}

func (e *DeploymentEvidence) classifyUp(ctx context.Context, ex transport.Executor, dep database.Deployment,
	intent jobs.Intent,
) (jobs.Classification, []string, error) {
	q := e.cfg.DB.Reader()
	want, err := e.expectedUp(ctx, q, dep, intent)
	if err != nil {
		return "", nil, err
	}
	target, err := database.GetAppTarget(ctx, q, dep.AppTargetID)
	if err != nil {
		return "", nil, err
	}
	containers, err := projectContainersOf(ctx, ex, target.ComposeProject)
	if err != nil {
		return "", nil, err
	}
	class, err := classifyUpContainers(containers, want)
	return class, upFingerprint(containers, want.directory), err
}

func projectContainersOf(ctx context.Context, ex transport.Executor, project string) ([]upContainer, error) {
	cmd, err := templates.Render("compose.project_containers", map[string]string{"project": project})
	if err != nil {
		return nil, fmt.Errorf("render compose.project_containers: %w", err)
	}
	res, err := ex.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("run compose.project_containers: %w", err)
	}
	if res.ExitStatus != 0 || res.Truncated {
		return nil, fmt.Errorf("compose.project_containers did not complete (exit %d)", res.ExitStatus)
	}
	if strings.TrimSpace(string(res.Stdout)) == "" {
		return nil, nil
	}
	var containers []upContainer
	if err := json.Unmarshal(res.Stdout, &containers); err != nil {
		return nil, fmt.Errorf("the project's containers could not be read: %w", err)
	}
	return containers, nil
}

// classifyUpContainers judges the project's containers against what a finished
// `compose up` of want leaves. It is pure.
func classifyUpContainers(containers []upContainer, want upExpectation) (jobs.Classification, error) {
	for _, c := range containers {
		if slices.Contains([]string{"created", "restarting", "removing"}, c.State.Status) {
			return "", errDeploymentContainersUnsettled
		}
	}
	ours := 0
	present := map[string]bool{}
	faithful := true
	for _, c := range containers {
		service := c.Config.Labels[composeServiceLabel]
		if c.Config.Labels[compose.LabelDeployment] != want.directory.String() {
			faithful = false
			continue
		}
		ours++
		if c.Config.Image != want.images[service] || !upContainerSettledWell(c) {
			faithful = false
			continue
		}
		present[service] = true
	}
	switch {
	case ours == 0:
		return jobs.ClassNotStarted, nil
	case faithful && len(present) == len(want.images):
		return jobs.ClassComplete, nil
	}
	return jobs.ClassPartialStable, nil
}

// upContainerSettledWell is a container that is up, or ran to a clean exit.
func upContainerSettledWell(c upContainer) bool {
	return c.State.Status == "running" || (c.State.Status == "exited" && c.State.ExitCode == 0)
}

// upFingerprint lists every container's identity and state, sorted: two samples
// pair only if nothing moved between them.
func upFingerprint(containers []upContainer, directory domain.ID) []string {
	out := make([]string, 0, len(containers))
	for _, c := range containers {
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|%s", c.Config.Labels[composeServiceLabel], c.ID, c.Config.Image,
			c.State.Status, c.Config.Labels[compose.LabelDeployment]))
	}
	slices.Sort(out)
	return append(out, "directory|"+directory.String())
}

// expectedUp resolves what the intent's step was bringing up: the deployment's
// own frozen model for the deploy step, the frozen rollback target's for the
// restore-deploy step.
func (e *DeploymentEvidence) expectedUp(ctx context.Context, q database.Querier, dep database.Deployment,
	intent jobs.Intent,
) (upExpectation, error) {
	p, err := planOfDeployment(ctx, q, dep)
	if err != nil {
		return upExpectation{}, err
	}
	switch intent.Step {
	case deployments.StepDeploy:
		images, err := frozenImagesOf(ctx, q, p.Content)
		return upExpectation{directory: dep.ID, images: images}, err
	case deployments.StepRestoreDeploy:
		return e.expectedRestoreUp(ctx, q, p, intent)
	}
	return upExpectation{}, fmt.Errorf("step %q does not run compose up", intent.Step)
}

func (e *DeploymentEvidence) expectedRestoreUp(ctx context.Context, q database.Querier, p plan.Plan, intent jobs.Intent) (upExpectation, error) {
	if p.Content.RollbackTarget == nil {
		return upExpectation{}, errors.New("the plan froze no rollback target")
	}
	good, err := database.GetDeployment(ctx, q, domain.ID(p.Content.RollbackTarget.DeploymentID))
	if err != nil {
		return upExpectation{}, err
	}
	goodPlan, err := planOfDeployment(ctx, q, good)
	if err != nil {
		return upExpectation{}, err
	}
	images, err := frozenImagesOf(ctx, q, goodPlan.Content)
	if err != nil {
		return upExpectation{}, err
	}
	directory, err := e.restoreDirectory(ctx, q, intent)
	return upExpectation{directory: directory, images: images}, err
}

// restoreDirectory is the directory the restore-materialize of the same
// attempt wrote: the restore picks a fresh id for it (deploy_restore.go).
func (e *DeploymentEvidence) restoreDirectory(ctx context.Context, q database.Querier, up jobs.Intent) (domain.ID, error) {
	siblings, err := e.intent.Intents(ctx, q, up.JobID)
	if err != nil {
		return "", err
	}
	for _, in := range slices.Backward(siblings) {
		if in.Step != deployments.StepRestoreMaterialize || in.LeaseGeneration != up.LeaseGeneration {
			continue
		}
		var pre struct {
			Directory domain.ID `json:"directory"`
		}
		if err := json.Unmarshal(in.PreState, &pre); err != nil || pre.Directory == "" {
			return "", fmt.Errorf("restore-materialize intent %s names no directory", in.ID)
		}
		return pre.Directory, nil
	}
	return "", errors.New("the restore materialized no directory in this attempt")
}

func planOfDeployment(ctx context.Context, q database.Querier, dep database.Deployment) (plan.Plan, error) {
	if dep.PlanID == nil {
		return plan.Plan{}, fmt.Errorf("deployment %s has no plan", dep.ID)
	}
	rec, err := database.GetPlan(ctx, q, *dep.PlanID)
	if err != nil {
		return plan.Plan{}, err
	}
	stored, err := plan.Parse(rec.PlanJSON)
	if err != nil {
		return plan.Plan{}, err
	}
	return *stored, nil
}

func frozenImagesOf(ctx context.Context, q database.Querier, c plan.Content) (map[string]string, error) {
	model, err := readSnapshotJSON[composeSnapshot](ctx, q, c.ComposeHash)
	if err != nil {
		return nil, err
	}
	images := make(map[string]string, len(model.Images))
	for _, image := range model.Images {
		images[image.Service] = image.Ref
	}
	return images, nil
}
