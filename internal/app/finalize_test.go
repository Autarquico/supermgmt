package app

import (
	"context"
	"crypto/sha1" //nolint:gosec // git blob ids are SHA-1 by definition
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/plan"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

const (
	finWebCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
`
	finManifest = `
apiVersion: supermgmt.dev/v1
kind: Application
metadata:
  name: web
spec:
  deployment:
    strategy: docker-compose
    composeFile: compose.yaml
    service: web
`
	finRepoCompose = `
services:
  web:
    image: ghcr.io/acme/web:placeholder
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
      - {target: 9090, published: 9090, host_ip: 127.0.0.1}
`
	finFixedHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	finOtherCommit  = "00000000000000000000000000000000000000aa"
	finSecretName   = "apps/web/database_url"
)

var (
	finPinnedWeb = "ghcr.io/acme/web@" + depWebDigest
	finOtherSum  = "sha256:" + strings.Repeat("d", 64)
)

// ---- fakes ------------------------------------------------------------------------------------

// finGitHub serves files at exact commits and attestation bundles, and records
// every read so a test can see which commits were asked for.
type finGitHub struct {
	mu      sync.Mutex
	files   map[string][]byte
	reads   []string
	bundles map[string][]json.RawMessage
	fileErr error
	onFile  func()
}

func newFinGitHub() *finGitHub {
	return &finGitHub{files: map[string][]byte{}, bundles: map[string][]json.RawMessage{}}
}

func (g *finGitHub) put(commit, path, content string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.files[commit+"\x00"+path] = []byte(content)
}

func (g *finGitHub) attest(digest string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bundles[digest] = []json.RawMessage{json.RawMessage(`{"bundle":true}`)}
}

func (g *finGitHub) commitsRead() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.reads)
}

func (g *finGitHub) For(context.Context, domain.ID) (github.Client, error) {
	return finClient{g: g}, nil
}

type finClient struct {
	github.Client
	g *finGitHub
}

func finBlobSHA(content []byte) string {
	h := sha1.New() //nolint:gosec // see import
	fmt.Fprintf(h, "blob %d\x00", len(content))
	_, _ = h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c finClient) File(_ context.Context, _ github.Repo, sha, path string, _ int64) (github.File, error) {
	c.g.mu.Lock()
	hook, fileErr := c.g.onFile, c.g.fileErr
	c.g.reads = append(c.g.reads, sha)
	content, ok := c.g.files[sha+"\x00"+path]
	c.g.mu.Unlock()
	if hook != nil {
		hook()
	}
	switch {
	case fileErr != nil:
		return github.File{}, fileErr
	case !ok:
		return github.File{}, &github.APIError{Status: http.StatusNotFound, Message: "Not Found"}
	}
	return github.File{Path: path, BlobSHA: finBlobSHA(content), Content: content}, nil
}

func (c finClient) Attestations(_ context.Context, _ github.Repo, digest string) ([]json.RawMessage, error) {
	c.g.mu.Lock()
	defer c.g.mu.Unlock()
	return c.g.bundles[digest], nil
}

// finVerifier accepts any bundle with evidence, or fails with err, and records
// what provenance it was asked to prove.
type finVerifier struct {
	evidence github.Evidence
	err      error
	wanted   []github.Provenance
}

func (v *finVerifier) Verify(bundles []json.RawMessage, digest string, want github.Provenance) (github.Evidence, error) {
	v.wanted = append(v.wanted, want)
	switch {
	case len(bundles) == 0:
		return github.Evidence{}, github.ErrNoAttestation
	case v.err != nil:
		return github.Evidence{}, v.err
	}
	evidence := v.evidence
	evidence.Digest, evidence.CommitSHA = digest, want.CommitSHA
	return evidence, nil
}

// ---- fixture ----------------------------------------------------------------------------------

type finOptions struct {
	gated  bool // repository, CI policy and automation identity
	pinned bool // the deployed digest is in image_policy.pinned
	app    []func(*wire.CreateAppRequest)
}

type finFixture struct {
	*depFixture
	gh     *finGitHub
	verify *finVerifier
	final  *DeploymentFinalizer
}

func newFinFixture(t *testing.T, o finOptions) *finFixture {
	t.Helper()
	af := newAppsFixture(t)
	governance, err := NewGovernance(af.cfg, af.store)
	mustf(t, err, "NewGovernance")
	service, err := NewDeployments(af.cfg, governance, CIPolling{Initial: 10 * time.Second, Max: time.Minute, Timeout: time.Hour})
	mustf(t, err, "NewDeployments")
	dep := &depFixture{appsFixture: af, deployments: service, canceller: &depCanceller{}}
	dep.deployments.canceller = dep.canceller
	mutate := slices.Clone(o.app)
	if o.gated {
		mutate = append([]func(*wire.CreateAppRequest){withAutomation(af)}, mutate...)
	}
	if o.pinned {
		mutate = append(mutate, func(r *wire.CreateAppRequest) { r.ImagePolicy.Pinned = append(r.ImagePolicy.Pinned, finPinnedWeb) })
	}
	dep.app = af.createApp(mutate...)
	dep.target = af.mustTarget(dep.app, "dev", finHTTPHealth)
	dep.inTx(func(ctx context.Context, tx *database.Tx) error {
		dep.deployer = dep.identity(ctx, tx, "dana", domain.ActorHuman, dep.role(ctx, tx, "deployer"))
		for _, capability := range []string{capabilityComposeDeploy, "node.exec.template"} {
			err := database.SetNodeCapability(ctx, tx, dep.node.ID, database.NodeCapability{
				Capability: capability, Available: true, CheckedAt: dep.clock.Now(),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	f := &finFixture{depFixture: dep, gh: newFinGitHub(), verify: &finVerifier{}}
	f.final, err = NewDeploymentFinalizer(service, FinalizerDeps{Clients: f.gh, Attestations: f.verify, Jobs: af.store})
	mustf(t, err, "NewDeploymentFinalizer")
	f.putSecret(finSecretName)
	return f
}

func finHTTPHealth(p *wire.DeploymentPolicy) {
	p.Health = &wire.HealthCheck{Type: "http", Port: 8080, Path: "/health"}
}

// putSecret stores the next version of a secret; the bytes are not a real
// ciphertext because finalizing only binds versions.
func (f *finFixture) putSecret(name string) int {
	f.t.Helper()
	var version int
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		rec, err := database.PutSecretVersion(ctx, tx, database.SecretRecord{
			ID: f.ids.NewID(), Name: name, EnvelopeVersion: 1, KEKID: f.ids.NewID(),
			WrappedDEK: []byte("dek"), Ciphertext: []byte("ciphertext"), CreatedAt: f.clock.Now(),
		})
		version = rec.Version
		return err
	})
	return version
}

func (f *finFixture) finalize(id domain.ID, checks ...github.CheckEvidence) error {
	return f.final.Finalize(context.Background(), id, checks)
}

func (f *finFixture) mustFinalize(id domain.ID, checks ...github.CheckEvidence) database.Deployment {
	f.t.Helper()
	mustf(f.t, f.finalize(id, checks...), "Finalize")
	return f.row(id)
}

// planOf reads the final plan of a deployment.
func (f *finFixture) planOf(id domain.ID) plan.Plan {
	f.t.Helper()
	row := f.row(id)
	if row.PlanID == nil {
		f.t.Fatalf("deployment %s has no plan (state %s)", id, row.State)
	}
	rec, err := database.GetPlan(context.Background(), f.db.Reader(), *row.PlanID)
	mustf(f.t, err, "GetPlan")
	parsed, err := plan.Parse(rec.PlanJSON)
	mustf(f.t, err, "plan.Parse")
	return *parsed
}

func (f *finFixture) exec(query string, args ...any) {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	})
}

// markKnownGood stands in for a deployment that ran and was verified.
func (f *finFixture) markKnownGood(id domain.ID) {
	f.t.Helper()
	f.exec(`UPDATE deployments SET state = 'succeeded', known_good = 1, finished_at = ? WHERE id = ?`,
		domain.UnixMillis(f.clock.Now()), id)
}

func (f *finFixture) wantFailed(id domain.ID, code smerr.Code, reason smerr.Reason) {
	f.t.Helper()
	row := f.row(id)
	if row.State != deployments.StateFailed || row.Failure.Code != string(code) || row.Failure.Reason != string(reason) {
		f.t.Fatalf("state %s code %q reason %q; want failed %s/%s", row.State, row.Failure.Code, row.Failure.Reason, code, reason)
	}
	if row.PlanID != nil || row.JobID != nil {
		f.t.Errorf("a failed deployment must have no plan or job: %+v", row)
	}
}

// ---- finalizing -------------------------------------------------------------------------------

func TestFinalize_WithoutAGateBuildsThePlanAndQueuesTheJob(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()

	row := f.mustFinalize(created.ID)

	if row.State != deployments.StateQueued || row.PlanID == nil || row.JobID == nil || row.PlanHash == "" {
		t.Fatalf("row = %+v, want queued with plan and job", row)
	}
	p := f.planOf(created.ID)
	c := p.Content
	if p.Action != "deployment.create" || p.Actor != "identity/"+f.deployer.String() || len(p.Targets) != 1 || *p.Targets[0].SpecRevision != 1 {
		t.Errorf("plan header = %+v", p)
	}
	if *c.CommitSHA != depCommit || c.ManifestBlobSHA != nil || c.RollbackTarget != nil {
		t.Errorf("content = %+v", c)
	}
	if len(c.Images) != 1 || c.Images[0].Ref != finPinnedWeb || c.Images[0].Binding != compose.BindingPinned {
		t.Errorf("images = %+v", c.Images)
	}
	if !slices.Equal(c.HostPorts, []string{"127.0.0.1:8080"}) {
		t.Errorf("host_ports = %v", c.HostPorts)
	}
	wantSteps := []string{"preflight", "pull", "materialize", "verify-on-node", "deploy", "health-check"}
	if !slices.Equal(p.Steps, wantSteps) || len(p.SubActions) != 0 {
		t.Errorf("steps %v sub-actions %v", p.Steps, p.SubActions)
	}
	if *c.ComposeHash != row.ComposeHash {
		t.Errorf("deployments.compose_hash %s, plan %s", row.ComposeHash, *c.ComposeHash)
	}
	for _, hash := range []*string{c.ComposeHash, c.ExceptionsHash, c.HealthHash, c.DeploymentPolicyHash} {
		if _, err := database.GetExecutionSnapshot(context.Background(), f.db.Reader(), *hash); err != nil {
			t.Errorf("snapshot %s: %v", *hash, err)
		}
	}
	job := f.job(*row.JobID)
	if job.PlanID == nil || *job.PlanID != *row.PlanID || job.PlanHash != row.PlanHash || job.ActorID != f.deployer {
		t.Errorf("job = %+v", job)
	}
	if job.CredentialKind != row.Credential.Kind || job.CredentialID != row.Credential.ID {
		t.Errorf("job credential %s/%s, want the stored context %+v", job.CredentialKind, job.CredentialID, row.Credential)
	}
	events := f.events(eventDeploymentFinalized)
	if len(events) != 1 || events[0].CorrelationID != created.ID.String() || events[0].Data["plan_hash"] != row.PlanHash {
		t.Errorf("events = %+v", events)
	}
}

func TestFinalize_PinsTheNodeAndEveryConfiguredInput(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()
	f.mustFinalize(created.ID)

	p := f.planOf(created.ID)

	byType := map[string]plan.Input{}
	for _, in := range p.Inputs {
		byType[in.Type] = in
	}
	for _, want := range []string{"app", "environment", "node", "secret"} {
		if _, ok := byType[want]; !ok {
			t.Errorf("inputs lack %q: %+v", want, p.Inputs)
		}
	}
	node := byType["node"]
	if node.Endpoint == nil || node.Endpoint.Address != "10.0.0.5" || node.Endpoint.Port != 22 || node.Endpoint.User != "supermgmt" ||
		node.HostPublicKeySHA256 == nil || !strings.HasPrefix(*node.HostPublicKeySHA256, "SHA256:") {
		t.Errorf("node input = %+v", node)
	}
	secret := byType["secret"]
	if secret.ID != finSecretName || secret.Version == nil || *secret.Version != 1 {
		t.Errorf("secret input = %+v", secret)
	}
	if bindings := p.Content.SecretBindings; len(bindings) != 1 || bindings[0].Service != "web" || bindings[0].EnvName != "DATABASE_URL" ||
		bindings[0].SecretID != finSecretName || bindings[0].Version != 1 {
		t.Errorf("secret_bindings = %+v", bindings)
	}
}

func TestFinalize_BindsTheNewestSecretVersion(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	f.putSecret(finSecretName)
	created := f.create()

	f.mustFinalize(created.ID)

	p := f.planOf(created.ID)
	if got := p.Content.SecretBindings[0].Version; got != 2 {
		t.Errorf("bound version %d, want the newest (2)", got)
	}
}

func TestFinalize_AMissingSecretFailsTheDeployment(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	f.exec(`DELETE FROM secrets WHERE name = ?`, finSecretName)
	created := f.create()

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeInvalidArgument, "")
}

func TestFinalize_PlanGoldenHash(t *testing.T) {
	hashOf := func() string {
		f := newFinFixture(t, finOptions{pinned: true})
		f.exec(`UPDATE nodes SET endpoint_json = json_set(endpoint_json, '$.host_public_key', ?) WHERE id = ?`, finFixedHostKey, f.node.ID)
		created := f.create()
		return f.mustFinalize(created.ID).PlanHash
	}

	first, second := hashOf(), hashOf()

	if first != second {
		t.Fatalf("the same inputs hashed to %s and %s", first, second)
	}
	const golden = "sha256:1a5580a32d987cf2f108a86570baeefbff722d895e006e06f6b09c84d53ed3d0"
	if first != golden {
		t.Errorf("plan hash = %s; update the golden value if the plan changed on purpose", first)
	}
}

func TestFinalize_ProvisionalStatesOnly(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()
	first := f.mustFinalize(created.ID)

	mustf(t, f.finalize(created.ID), "second Finalize")

	if again := f.row(created.ID); again.PlanID == nil || *again.PlanID != *first.PlanID {
		t.Errorf("a second Finalize changed the plan: %+v", again)
	}
	if got := len(f.events(eventDeploymentFinalized)); got != 1 {
		t.Errorf("deployment.finalized events = %d, want 1", got)
	}
}

func TestFinalize_GatedDeploymentLeavesWaitingCI(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true, pinned: true})
	created := f.create()
	evidence := github.CheckEvidence{CheckName: "test", AppID: githubActionsAppID, WorkflowPath: ".github/workflows/ci.yml", RunID: 700, RunAttempt: 2, Conclusion: "success", CompletedAt: f.clock.Now()}
	f.attestDigest(depWebDigest)

	row := f.mustFinalize(created.ID, evidence)

	if row.State != deployments.StateQueued || row.ArtifactID == nil {
		t.Fatalf("state %s artifact %v; want queued with an artifact", row.State, row.ArtifactID)
	}
	checks, err := database.ListArtifactChecks(context.Background(), f.db.Reader(), *row.ArtifactID)
	mustf(t, err, "ListArtifactChecks")
	if len(checks) != 1 || checks[0].CheckName != "test" || checks[0].Conclusion != "success" || *checks[0].RunID != 700 {
		t.Errorf("artifact checks = %+v, want the evidence per check", checks)
	}
}

// attestDigest makes GitHub hold an attestation the verifier accepts.
func (f *finFixture) attestDigest(digest string) {
	f.gh.attest(digest)
	f.verify.evidence = github.Evidence{Method: "attestation", RepositoryID: 4242, RunID: 700, RunAttempt: 2}
}

// ---- the commit ---------------------------------------------------------------------------------

func finRepositoryApp(r *wire.CreateAppRequest) {
	r.ComposeSource, r.ComposeContent, r.SecretRefs = composeSourceRepository, "", nil
}

func TestFinalize_UsesCIPassedCommitNeverBranchHead(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true, pinned: true, app: []func(*wire.CreateAppRequest){finRepositoryApp}})
	f.gh.put(depCommit, ".supermgmt.yaml", finManifest)
	f.gh.put(depCommit, "compose.yaml", finRepoCompose)
	// main moved after CI passed: its head carries a different, privileged file.
	f.gh.put(finOtherCommit, ".supermgmt.yaml", finManifest)
	f.gh.put(finOtherCommit, "compose.yaml", "services:\n  web:\n    image: ghcr.io/acme/web:placeholder\n    privileged: true\n")
	created := f.create()

	row := f.mustFinalize(created.ID)

	if row.State != deployments.StateQueued {
		t.Fatalf("state = %s (%+v), want queued", row.State, row.Failure)
	}
	if reads := f.gh.commitsRead(); len(reads) == 0 || slices.ContainsFunc(reads, func(c string) bool { return c != depCommit }) {
		t.Errorf("commits read = %v, want only the CI-passed %s", reads, depCommit)
	}
	p := f.planOf(created.ID)
	if !slices.Equal(p.Content.HostPorts, []string{"127.0.0.1:8080", "127.0.0.1:9090"}) {
		t.Errorf("host_ports = %v, want the ports of the file at the commit", p.Content.HostPorts)
	}
	if blob := p.Content.ManifestBlobSHA; blob == nil || *blob != finBlobSHA([]byte(finManifest)) {
		t.Errorf("manifest_blob_sha = %v, want the blob of the manifest at the commit", blob)
	}
	var repository bool
	for _, in := range p.Inputs {
		repository = repository || in.Type == plan.InputTypeRepository
	}
	if !repository {
		t.Errorf("inputs lack the repository: %+v", p.Inputs)
	}
}

func TestFinalize_RepositorySourceNeedsTheManifestAndTheFile(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*finGitHub)
		want  smerr.Reason
	}{
		{"no manifest", func(*finGitHub) {}, smerr.ReasonComposeRejected},
		{"manifest without the file", func(g *finGitHub) { g.put(depCommit, ".supermgmt.yaml", finManifest) }, smerr.ReasonComposeRejected},
		{"manifest for another service", func(g *finGitHub) {
			g.put(depCommit, ".supermgmt.yaml", strings.Replace(finManifest, "service: web", "service: worker", 1))
		}, smerr.ReasonManifestInvalid},
		{"unknown manifest field", func(g *finGitHub) { g.put(depCommit, ".supermgmt.yaml", finManifest+"  extra: true\n") }, smerr.ReasonManifestInvalid},
		{"privileged compose at the commit", func(g *finGitHub) {
			g.put(depCommit, ".supermgmt.yaml", finManifest)
			g.put(depCommit, "compose.yaml", "services:\n  web:\n    image: ghcr.io/acme/web:placeholder\n    privileged: true\n")
		}, smerr.ReasonComposeRejected},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinFixture(t, finOptions{gated: true, pinned: true, app: []func(*wire.CreateAppRequest){finRepositoryApp}})
			tc.setup(f.gh)
			created := f.create()

			f.mustFinalize(created.ID)

			row := f.row(created.ID)
			if row.State != deployments.StateFailed || row.Failure.Reason != string(tc.want) {
				t.Fatalf("state %s failure %+v, want failed %s", row.State, row.Failure, tc.want)
			}
		})
	}
}

func TestFinalize_ATagOrUnboundSidecarAtTheCommitFailsAsNotImmutable(t *testing.T) {
	unboundRedis := "docker.io/library/redis@sha256:" + strings.Repeat("4", 64)
	tests := []struct {
		name    string
		compose string
		want    smerr.Reason
	}{
		{"tag", "services:\n  web:\n    image: ghcr.io/acme/web:x\n    ports:\n      - {target: 8080, published: 8080, host_ip: 127.0.0.1}\n  redis:\n    image: docker.io/library/redis:7\n", smerr.ReasonTagReference},
		{"digest neither bound nor pinned", "services:\n  web:\n    image: ghcr.io/acme/web:x\n    ports:\n      - {target: 8080, published: 8080, host_ip: 127.0.0.1}\n  redis:\n    image: " + unboundRedis + "\n", smerr.ReasonDigestUnbound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFinFixture(t, finOptions{gated: true, pinned: true, app: []func(*wire.CreateAppRequest){
				finRepositoryApp,
				func(r *wire.CreateAppRequest) {
					r.ImagePolicy.Sidecars = map[string]string{"redis": "docker.io/library/redis"}
				},
			}})
			f.gh.put(depCommit, ".supermgmt.yaml", finManifest)
			f.gh.put(depCommit, "compose.yaml", tc.compose)
			created := f.create()

			f.mustFinalize(created.ID)

			f.wantFailed(created.ID, smerr.CodeArtifactNotImmutable, tc.want)
		})
	}
}

func TestFinalize_ARequestedDigestOfASidecarMustBeTheOneInTheModel(t *testing.T) {
	redis := "docker.io/library/redis@sha256:" + strings.Repeat("4", 64)
	f := newFinFixture(t, finOptions{gated: true, pinned: true, app: []func(*wire.CreateAppRequest){
		finRepositoryApp,
		func(r *wire.CreateAppRequest) {
			r.ImagePolicy.Sidecars = map[string]string{"redis": "docker.io/library/redis"}
			r.ImagePolicy.Pinned = append(r.ImagePolicy.Pinned, redis)
		},
	}})
	f.gh.put(depCommit, ".supermgmt.yaml", finManifest)
	f.gh.put(depCommit, "compose.yaml", "services:\n  web:\n    image: ghcr.io/acme/web:x\n    ports:\n      - {target: 8080, published: 8080, host_ip: 127.0.0.1}\n  redis:\n    image: "+redis+"\n")
	created := f.create(func(r *CreateDeployment) {
		r.Images = append(r.Images, RequestedImage{Service: "redis", Digest: finOtherSum})
	})

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeInvalidArgument, "")
}

func TestFinalize_GitHubFailuresAreRetriedNotFatal(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true, pinned: true})
	f.gh.fileErr = &github.APIError{Status: http.StatusBadGateway, Message: "bad gateway"}
	created := f.create()

	err := f.finalize(created.ID)

	if err == nil {
		t.Fatal("Finalize = nil, want the GitHub failure so the watcher tries again")
	}
	if row := f.row(created.ID); row.State != deployments.StateWaitingCI {
		t.Errorf("state = %s, want it left waiting_ci", row.State)
	}
	f.gh.fileErr = nil
	if row := f.mustFinalize(created.ID); row.State != deployments.StateQueued {
		t.Errorf("after recovery state = %s, want queued", row.State)
	}
}

func TestFinalize_AnAppEditedWhileTheCommitWasReadIsRetried(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true, pinned: true})
	created := f.create()
	f.gh.onFile = func() {
		f.exec(`UPDATE apps SET spec_revision = spec_revision + 1 WHERE id = ?`, f.app.ID)
	}

	err := f.finalize(created.ID)

	if !errors.Is(err, errAppMoved) {
		t.Fatalf("Finalize = %v, want errAppMoved", err)
	}
	if row := f.row(created.ID); row.State != deployments.StateWaitingCI || row.PlanID != nil {
		t.Errorf("row = %+v, want it untouched", row)
	}
}

// ---- binding ------------------------------------------------------------------------------------

func TestFinalize_UnboundDigestFailsAsNotImmutable(t *testing.T) {
	f := newFinFixture(t, finOptions{})
	created := f.create()

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeArtifactNotImmutable, smerr.ReasonDigestUnbound)
	failed := f.events(eventDeploymentFailed)
	if len(failed) != 1 || failed[0].Data["reason"] != string(smerr.ReasonDigestUnbound) {
		t.Errorf("events = %+v", failed)
	}
}

func TestFinalize_AnAttestationBindsTheDigestAndIsAskedForTheExactCommit(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	f.attestDigest(depWebDigest)
	created := f.create()

	row := f.mustFinalize(created.ID)

	if row.State != deployments.StateQueued {
		t.Fatalf("state %s failure %+v", row.State, row.Failure)
	}
	if got := f.planOf(created.ID).Content.Images[0].Binding; got != compose.BindingAttestation {
		t.Errorf("binding = %s, want attestation", got)
	}
	want := github.Provenance{RepositoryID: 4242, Repository: "acme/web", WorkflowPath: ".github/workflows/deploy.yml", Branch: "main", CommitSHA: depCommit}
	if len(f.verify.wanted) != 1 || f.verify.wanted[0] != want {
		t.Errorf("provenance asked = %+v, want %+v", f.verify.wanted, want)
	}
	artifact, err := database.GetArtifact(context.Background(), f.db.Reader(), *row.ArtifactID)
	mustf(t, err, "GetArtifact")
	if artifact.ProvenanceMethod != compose.BindingAttestation || artifact.Digest != depWebDigest || artifact.CommitSHA != depCommit ||
		artifact.ImmutableRef != finPinnedWeb || *artifact.SourceRunID != 700 || *artifact.SourceRunAttempt != 2 {
		t.Errorf("artifact = %+v", artifact)
	}
}

func TestFinalize_OIDCClaimsBindTheDigestAfterTheTokenExpired(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	caller := f.oidcCaller("jti-1")
	created, err := f.deployments.Create(context.Background(), caller, f.request())
	mustf(t, err, "Create")
	f.clock.Advance(30 * time.Minute)
	f.creds.set(caller.Credential.ID, CredentialExpired)

	row := f.mustFinalize(created.ID)

	if row.State != deployments.StateQueued {
		t.Fatalf("state %s failure %+v, want queued after the token expired", row.State, row.Failure)
	}
	if got := f.planOf(created.ID).Content.Images[0].Binding; got != compose.BindingOIDCClaims {
		t.Errorf("binding = %s, want oidc_claims", got)
	}
	artifact, err := database.GetArtifact(context.Background(), f.db.Reader(), *row.ArtifactID)
	mustf(t, err, "GetArtifact")
	if artifact.ProvenanceMethod != compose.BindingOIDCClaims || *artifact.SourceRunID != 9 {
		t.Errorf("artifact = %+v", artifact)
	}
}

func TestFinalize_RequireProvenanceAcceptsOnlyAnAttestation(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	f.exec(`UPDATE environments SET config_json = json_set(config_json, '$.require_provenance', json('true')) WHERE id = ?`, f.dev.ID)
	caller := f.oidcCaller("jti-2")
	created, err := f.deployments.Create(context.Background(), caller, f.request())
	mustf(t, err, "Create")

	f.mustFinalize(created.ID)
	f.wantFailed(created.ID, smerr.CodeArtifactNotImmutable, smerr.ReasonDigestUnbound)

	f.attestDigest(depWebDigest)
	again, err := f.deployments.Create(context.Background(), caller, f.request())
	mustf(t, err, "Create")
	if row := f.mustFinalize(again.ID); row.State != deployments.StateQueued {
		t.Errorf("with an attestation state = %s (%+v), want queued", row.State, row.Failure)
	}
}

func TestFinalize_ARejectedAttestationFallsBackToThePinnedSet(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true})
	f.gh.attest(depWebDigest)
	f.verify.err = fmt.Errorf("%w: wrong workflow", github.ErrAttestationRejected)
	created := f.create()

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeArtifactNotImmutable, smerr.ReasonDigestUnbound)
}

func TestFinalize_AnUnverifiableAttestationIsRetried(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true, pinned: true})
	f.gh.attest(depWebDigest)
	f.verify.err = errors.New("trust root is stale")
	created := f.create()

	if err := f.finalize(created.ID); err == nil {
		t.Fatal("Finalize = nil, want the verification failure (fail closed, try again)")
	}
	if row := f.row(created.ID); row.State != deployments.StateWaitingCI {
		t.Errorf("state = %s, want waiting_ci", row.State)
	}
}

// ---- the requester and policy ---------------------------------------------------------------------

func TestFinalize_ARevokedRequesterFailsTheDeployment(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()
	f.creds.set(f.caller(f.deployer).Credential.ID, CredentialRevoked)

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
}

func TestFinalize_ADisabledRequesterFailsTheDeployment(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()
	f.exec(`UPDATE identities SET disabled_at = ? WHERE id = ?`, domain.UnixMillis(f.clock.Now()), f.deployer)

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodePolicyDenied, smerr.ReasonDefaultDeny)
}

func TestFinalize_AnExpiredAPITokenFailsTheDeployment(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()
	f.creds.set(f.caller(f.deployer).Credential.ID, CredentialExpired)

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeUnauthenticated, smerr.ReasonCredentialExpired)
}

func TestFinalize_PolicyIsEvaluatedOnTheFinalPlan(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
			Capability: capabilityComposeDeploy, Available: false, CheckedAt: f.clock.Now(),
		})
	})

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeCapabilityUnavailable, "")
	if denied := f.events("policy.capability_unavailable"); len(denied) != 1 {
		t.Errorf("policy events = %+v, want the refusal audited", denied)
	}
}

func TestFinalize_ProductionWaitsForApproval(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	target := f.mustTarget(f.app, "prod", finHTTPHealth)
	created := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID })

	row := f.mustFinalize(created.ID)

	if row.State != deployments.StateAwaitingApproval {
		t.Fatalf("state = %s, want awaiting_approval (production needs 2 approvals)", row.State)
	}
	if job := f.job(*row.JobID); job.State != domain.JobAwaitingApproval {
		t.Errorf("job state = %s", job.State)
	}
}

// ---- policy of the target -------------------------------------------------------------------------

func TestFinalize_ATargetWithoutAnEffectiveHealthCheckIsRejected(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	f.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`, `{"rollback":"manual","health":null}`, f.target.ID)
	created := f.create()

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeInvalidArgument, "")
	if events := f.events(eventDeploymentFailed); len(events) != 1 || !strings.Contains(fmt.Sprint(events[0].Data["detail"]), "health") {
		t.Errorf("events = %+v, want the missing health check explained", events)
	}
}

func TestFinalize_AManifestHealthHintStandsInWhenThePolicyHasNone(t *testing.T) {
	f := newFinFixture(t, finOptions{gated: true, pinned: true})
	f.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`, `{"rollback":"manual"}`, f.target.ID)
	f.gh.put(depCommit, ".supermgmt.yaml", finManifest+"  health:\n    type: http\n    port: 8080\n    path: /up\n")
	created := f.create()

	row := f.mustFinalize(created.ID)

	if row.State != deployments.StateQueued {
		t.Fatalf("state %s failure %+v, want queued with the manifest check", row.State, row.Failure)
	}
	var check struct{ Origin string }
	snapshot, err := database.GetExecutionSnapshot(context.Background(), f.db.Reader(), *f.planOf(created.ID).Content.HealthHash)
	mustf(t, err, "health snapshot")
	mustf(t, json.Unmarshal(snapshot.Content, &check), "decode health snapshot")
	if check.Origin != "manifest" {
		t.Errorf("health origin = %q, want manifest", check.Origin)
	}
}

func TestFinalize_AHealthCheckOnAPortTheModelDoesNotPublishIsRejected(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	f.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`,
		`{"rollback":"manual","health":{"type":"http","scope":"node","port":9999,"path":"/","timeout":"5s","interval":"2s","attempts":3}}`, f.target.ID)
	created := f.create()

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeInvalidArgument, "")
}

const finStatefulPolicy = `{"rollback":"manual","stateful":true,"health":{"type":"http","scope":"node","port":8080,"path":"/","timeout":"5s","interval":"2s","attempts":3}%s}`

func TestFinalize_StatefulProductionWithoutABackupIsRejected(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	target := f.mustTarget(f.app, "prod", finHTTPHealth)
	f.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`, fmt.Sprintf(finStatefulPolicy, ""), target.ID)
	created := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID })

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeInvalidArgument, "")
}

func TestFinalize_ABackupIsAPlanSubActionAndStep(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	target := f.mustTarget(f.app, "prod", finHTTPHealth)
	backup := `,"pre_deploy_backup":{"template":"postgres-dump","args":{"container":"db","database":"app"},"timeout":"5m0s"}`
	f.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`, fmt.Sprintf(finStatefulPolicy, backup), target.ID)
	created := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID })

	row := f.mustFinalize(created.ID)

	if row.State != deployments.StateAwaitingApproval {
		t.Fatalf("state %s failure %+v", row.State, row.Failure)
	}
	p := f.planOf(created.ID)
	if len(p.SubActions) != 1 || p.SubActions[0].Action != "node.backup_template.run" || p.SubActions[0].Target.ID != f.node.ID.String() {
		t.Errorf("sub_actions = %+v", p.SubActions)
	}
	if !slices.Contains(p.Steps, deployments.StepPreDeployBackup) {
		t.Errorf("steps = %v, want pre-deploy-backup", p.Steps)
	}
}

func TestFinalize_ADeniedBackupSubActionFailsTheDeployment(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	target := f.mustTarget(f.app, "prod", finHTTPHealth)
	backup := `,"pre_deploy_backup":{"template":"postgres-dump","args":{"container":"db","database":"app"},"timeout":"5m0s"}`
	f.exec(`UPDATE app_targets SET deployment_policy_json = ? WHERE id = ?`, fmt.Sprintf(finStatefulPolicy, backup), target.ID)
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{
			Capability: "node.exec.template", Available: false, CheckedAt: f.clock.Now(),
		})
	})
	created := f.create(func(r *CreateDeployment) { r.AppTargetID = target.ID })

	f.mustFinalize(created.ID)

	f.wantFailed(created.ID, smerr.CodeCapabilityUnavailable, "")
}

// ---- the rollback target ----------------------------------------------------------------------------

func TestFinalize_FreezesTheNewestKnownGoodAsTheRollbackTarget(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	first := f.create()
	f.mustFinalize(first.ID)
	f.markKnownGood(first.ID)
	second := f.create()

	f.mustFinalize(second.ID)

	target := f.planOf(second.ID).Content.RollbackTarget
	good := f.row(first.ID)
	if target == nil || target.DeploymentID != first.ID.String() || target.ComposeHash != good.ComposeHash {
		t.Fatalf("rollback_target = %+v, want the known-good %s with its compose hash", target, first.ID)
	}
}

func TestFinalize_TheFirstDeploymentHasNoRollbackTarget(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	created := f.create()

	f.mustFinalize(created.ID)

	if target := f.planOf(created.ID).Content.RollbackTarget; target != nil {
		t.Errorf("rollback_target = %+v, want null", target)
	}
}

// ---- the watcher seam ---------------------------------------------------------------------------------

func TestFinalize_IsTheWatchersFinalizer(t *testing.T) {
	f := newFinFixture(t, finOptions{pinned: true})
	watcher, err := newCIWatcher(f.cfg, f.gh, f.final, CIPolling{Initial: time.Second, Max: time.Minute, Timeout: time.Hour}, CIWatcherOptions{})
	mustf(t, err, "newCIWatcher")
	created := f.create()

	mustf(t, watcher.pollDue(context.Background()), "pollDue")

	if row := f.row(created.ID); row.State != deployments.StateQueued {
		t.Errorf("state = %s, want the watcher's pass to have finalized the ungated deployment", row.State)
	}
}
