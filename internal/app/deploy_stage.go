package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// deployDir names one deployment's directory on the node:
// <deploy_root>/<project>/<deployment>. Every staging and run template takes
// these three values as separately validated parameters.
type deployDir struct {
	Root       string
	Project    string
	Deployment domain.ID
}

func (d deployDir) args() map[string]string {
	return map[string]string{"root": d.Root, "project": d.Project, "deployment": d.Deployment.String()}
}

// deployStage runs the staging steps of a deployment on one node (spec §20.3
// steps 8-10): pull, materialize, verify. Nothing here touches a running
// service, so a failure leaves the project exactly as it was.
//
// The exported-style methods are the forward steps and refuse under
// safety_recovery (ADR-0029). The unexported stage* methods are the same
// operations without that refusal, for the restore steps, which redeploy the
// frozen rollback target.
type deployStage struct {
	exec transport.Executor
}

// maxReportedDiffs bounds how many differences an error lists: the node's
// output is untrusted and must not be able to inflate an error.
const maxReportedDiffs = 10

// Pull is the forward pull step. Each distinct image is pulled under the
// marker "<marker>-<n>", n counting from 0 in sorted reference order.
func (s deployStage) Pull(ctx context.Context, mode deployments.RecoveryMode, marker string, images []compose.ImageUse) error {
	if err := refuseForwardStep(deployments.StepPull, mode); err != nil {
		return err
	}
	return s.stagePull(ctx, marker, images)
}

// Materialize is the forward materialize step.
func (s deployStage) Materialize(ctx context.Context, mode deployments.RecoveryMode, dir deployDir, marker string,
	f compose.Frozen, values []compose.ResolvedSecret,
) error {
	if err := refuseForwardStep(deployments.StepMaterialize, mode); err != nil {
		return err
	}
	return s.stageMaterialize(ctx, dir, marker, f, values)
}

// Verify is the forward verify-on-node step.
func (s deployStage) Verify(ctx context.Context, mode deployments.RecoveryMode, dir deployDir,
	f compose.Frozen, values []compose.ResolvedSecret,
) error {
	if err := refuseForwardStep(deployments.StepVerifyOnNode, mode); err != nil {
		return err
	}
	return s.stageVerify(ctx, dir, f, values)
}

// refuseForwardStep stops a forward step from running while the deployment is
// in safety recovery, where only restore steps may mutate the node.
func refuseForwardStep(step string, mode deployments.RecoveryMode) error {
	if mode == deployments.RecoverySafetyRecovery {
		return smerr.New(smerr.CodeConflict, smerr.ReasonInvalidTransition,
			fmt.Sprintf("step %q is a forward step and cannot run in safety recovery", step))
	}
	return nil
}

func (s deployStage) stagePull(ctx context.Context, marker string, images []compose.ImageUse) error {
	for i, ref := range distinctImageRefs(images) {
		cmd, err := templates.RenderMutating("compose.pull", fmt.Sprintf("%s-%d", marker, i), map[string]string{"image": ref})
		if err != nil {
			return fmt.Errorf("render pull: %w", err)
		}
		res, err := s.exec.Run(ctx, cmd)
		if err != nil {
			return fmt.Errorf("pull %s: %w", ref, err)
		}
		if res.ExitStatus != 0 {
			return stagingFailed(fmt.Sprintf("docker pull of %s exited %d", ref, res.ExitStatus), "")
		}
	}
	return nil
}

func distinctImageRefs(images []compose.ImageUse) []string {
	seen := map[string]bool{}
	var refs []string
	for _, img := range images {
		if !seen[img.Ref] {
			seen[img.Ref] = true
			refs = append(refs, img.Ref)
		}
	}
	sort.Strings(refs)
	return refs
}

// stageMaterialize writes the deployment directory. The files travel on stdin
// of a Sensitive command; the command line, the error messages and the
// node's output never carry them.
func (s deployStage) stageMaterialize(ctx context.Context, dir deployDir, marker string,
	f compose.Frozen, values []compose.ResolvedSecret,
) error {
	bundle, err := compose.Materialize(f, dir.Deployment, values)
	if err != nil {
		return err
	}
	stdin, err := templates.EncodeMaterialization(stagedFiles(bundle))
	if err != nil {
		return stagingFailed("cannot encode the deployment files: "+err.Error(), "")
	}
	cmd, err := templates.RenderMutatingInput("compose.materialize", marker, dir.args(), stdin, "")
	if err != nil {
		return fmt.Errorf("render materialize: %w", err)
	}
	res, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("materialize: %w", err)
	}
	if res.ExitStatus != 0 {
		return stagingFailed(fmt.Sprintf("materialize exited %d", res.ExitStatus), "")
	}
	return nil
}

func stagedFiles(b compose.Bundle) []templates.StagedFile {
	files := []templates.StagedFile{{Path: "compose.yaml", Content: b.ComposeYAML}}
	paths := make([]string, 0, len(b.EnvFiles))
	for p := range b.EnvFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		files = append(files, templates.StagedFile{Path: p, Content: []byte(b.EnvFiles[p].Reveal())})
	}
	return files
}

// nodeVerification is the one line compose.verify prints: the masked
// effective model and the resolved-environment hash set (ADR-0010).
type nodeVerification struct {
	Model json.RawMessage `json:"model"`
	Set   []nodeEnvHash   `json:"set"`
}

type nodeEnvHash struct {
	Service string  `json:"service"`
	EnvName string  `json:"env_name"`
	SHA256  *string `json:"sha256"`
}

// stageVerify proves the node resolved exactly what the control plane froze:
// the resolved environment hashes and the whole effective model. Any
// difference is STAGING_FAILED; the error names paths and variable names,
// never values.
func (s deployStage) stageVerify(ctx context.Context, dir deployDir, f compose.Frozen, values []compose.ResolvedSecret) error {
	cmd, err := templates.Render("compose.verify", dir.args())
	if err != nil {
		return fmt.Errorf("render verify: %w", err)
	}
	res, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if res.ExitStatus != 0 || res.Truncated {
		return stagingFailed(fmt.Sprintf("compose verification failed on the node (exit %d)", res.ExitStatus), "")
	}
	var got nodeVerification
	if err := json.Unmarshal(bytes.TrimSpace(res.Stdout), &got); err != nil || len(got.Model) == 0 {
		return stagingFailed("compose verification output is not understood", "")
	}
	want := compose.ExpectedEnvHashes(f, values)
	if diffs := envHashDiffs(want, got.Set); len(diffs) > 0 {
		return stagingFailedWithDiffs("the resolved environment differs on the node", deployments.CauseEnvHashMismatch, diffs)
	}
	expected, err := expectedMaskedModel(f, dir.Deployment, want)
	if err != nil {
		return err
	}
	diffs, err := compose.Equivalent(expected, got.Model)
	if err != nil {
		return stagingFailed("node model is not understood: "+err.Error(), deployments.CauseModelMismatch)
	}
	if len(diffs) > 0 {
		return stagingFailedWithDiffs("the node's effective model differs from the frozen one", deployments.CauseModelMismatch, diffs)
	}
	return nil
}

// envHashDiffs compares the expected hash set with the node's, exactly: a
// missing name, an extra name, a null (unresolved) entry or a different hash
// is a difference. Entries read "<service>/<NAME>: <kind>".
func envHashDiffs(want []compose.EnvHash, got []nodeEnvHash) []string {
	type key struct{ service, name string }
	expected := make(map[key]string, len(want))
	for _, w := range want {
		expected[key{w.Service, w.EnvName}] = w.SHA256
	}
	var diffs []string
	seen := map[key]bool{}
	for _, g := range got {
		k := key{g.Service, g.EnvName}
		hash, ok := expected[k]
		switch {
		case seen[k]:
			diffs = append(diffs, fmt.Sprintf("%s/%s: reported twice", k.service, k.name))
		case !ok || g.SHA256 == nil:
			diffs = append(diffs, fmt.Sprintf("%s/%s: unexpected on node", k.service, k.name))
		case hash != *g.SHA256:
			diffs = append(diffs, fmt.Sprintf("%s/%s: differs", k.service, k.name))
		}
		seen[k] = true
	}
	for k := range expected {
		if !seen[k] {
			diffs = append(diffs, fmt.Sprintf("%s/%s: missing from node", k.service, k.name))
		}
	}
	sort.Strings(diffs)
	return diffs
}

// expectedMaskedModel completes the freeze-time effective model with what
// materialization adds: the deployment label on every service and the
// environment names the secret env files provide, masked like the node masks
// them. `config` resolves env_file into `environment` and drops the wiring, so
// the wiring appears in neither model.
func expectedMaskedModel(f compose.Frozen, deployment domain.ID, hashes []compose.EnvHash) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(f.Effective))
	dec.UseNumber()
	var model map[string]any
	if err := dec.Decode(&model); err != nil {
		return nil, fmt.Errorf("decode the frozen effective model: %w", err)
	}
	services, _ := model["services"].(map[string]any)
	for name, raw := range services {
		svc, _ := raw.(map[string]any)
		if svc == nil {
			return nil, fmt.Errorf("frozen effective model: service %q is not an object", name)
		}
		objectField(svc, "labels")[compose.LabelDeployment] = deployment.String()
	}
	byName := make(map[string]string, len(hashes))
	for _, h := range hashes {
		byName[h.Service+"\x00"+h.EnvName] = h.SHA256
	}
	for _, u := range f.Secrets {
		svc, _ := services[u.Service].(map[string]any)
		hash, ok := byName[u.Service+"\x00"+u.EnvName]
		if svc == nil || !ok {
			return nil, fmt.Errorf("frozen secret %s/%s has no service or no resolved value", u.Service, u.EnvName)
		}
		objectField(svc, "environment")[u.EnvName] = "sha256:" + hash
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(model); err != nil {
		return nil, fmt.Errorf("encode the expected model: %w", err)
	}
	return bytes.TrimSpace(out.Bytes()), nil
}

// objectField returns svc[key] as an object, creating it when absent.
func objectField(svc map[string]any, key string) map[string]any {
	obj, ok := svc[key].(map[string]any)
	if !ok {
		obj = map[string]any{}
		svc[key] = obj
	}
	return obj
}

func stagingFailed(msg, cause string) *smerr.Error {
	e := smerr.FromReason(smerr.ReasonStagingFailed, msg)
	if cause != "" {
		e.Details = map[string]any{"cause": cause}
	}
	return e
}

func stagingFailedWithDiffs(msg, cause string, diffs []string) *smerr.Error {
	if len(diffs) > maxReportedDiffs {
		diffs = append(diffs[:maxReportedDiffs:maxReportedDiffs], fmt.Sprintf("... and %d more", len(diffs)-maxReportedDiffs))
	}
	e := stagingFailed(msg+": "+strings.Join(diffs, "; "), cause)
	e.Details["diffs"] = diffs
	return e
}
