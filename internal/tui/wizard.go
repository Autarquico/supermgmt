package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The deployment creation wizard (spec §22.3) and the rollback review are
// driven from the palette: `deploy <app> <env>` asks for the commit and the
// image digests, `rollback <app> <env>` goes straight to the review. Both end
// on a review screen, and nothing is sent to the daemon until the user
// confirms it: the only call that creates a deployment is the review's run.

const (
	wizardDeploy   = "deploy"
	wizardRollback = "rollback"

	digestPrefix = "sha256:"
	digestHexLen = 64
)

// wizardStartMsg carries what the wizard needs from the daemon to begin.
type wizardStartMsg struct {
	kind        string
	appRef, env string
	apps        []wire.App
	deployments []wire.Deployment // rollback only
	err         error
}

// deployDraft is a deployment as far as the wizard has collected it.
type deployDraft struct {
	app    wire.App
	target wire.AppTarget
	commit string
	images []wire.RequestedImage
}

func (m *Model) startWizard(kind, appRef, env string) tea.Cmd {
	apps, ok := m.api.(AppsAPI)
	if _, deploys := m.api.(DeployAPI); !ok || !deploys {
		m.notice = notice{text: unavailableApps, isErr: true}
		return nil
	}
	timeout, parent := m.opts.Timeout, m.ctx
	return func() tea.Msg {
		msg, err := within(parent, timeout, func(ctx context.Context) (wizardStartMsg, error) {
			msg := wizardStartMsg{kind: kind, appRef: appRef, env: env}
			page, err := apps.ListApps(ctx, wire.PageQuery{Limit: wire.MaxLimit})
			if err != nil {
				return msg, err
			}
			msg.apps = page.Items
			if kind == wizardRollback {
				deployments, err := apps.ListDeployments(ctx, wire.PageQuery{Limit: 100})
				msg.deployments = deployments.Items
				return msg, err
			}
			return msg, nil
		})
		msg.kind, msg.err = kind, err
		return msg
	}
}

func (m *Model) onWizardStart(msg wizardStartMsg) tea.Cmd {
	if msg.err != nil {
		m.failure("cannot start "+msg.kind, msg.err)
		return nil
	}
	app, target, err := resolveTarget(msg.apps, msg.appRef, msg.env)
	if err != nil {
		m.notice = notice{text: err.Error(), isErr: true}
		return nil
	}
	if msg.kind == wizardRollback {
		return m.reviewRollback(app, target, msg.deployments)
	}
	return m.askCommit(deployDraft{app: app, target: target}, "")
}

// resolveTarget finds an app by id or name and its target in one environment.
func resolveTarget(apps []wire.App, appRef, env string) (wire.App, wire.AppTarget, error) {
	for _, a := range apps {
		if string(a.ID) != appRef && !strings.EqualFold(a.Name, appRef) {
			continue
		}
		for _, t := range a.Targets {
			if t.Environment == env {
				return a, t, nil
			}
		}
		return wire.App{}, wire.AppTarget{}, fmt.Errorf("app %s has no target in environment %q", safe(a.Name), safe(env))
	}
	return wire.App{}, wire.AppTarget{}, fmt.Errorf("no app matches %q", safe(appRef))
}

// ---- deploy: commit, images, review -------------------------------------------

const wizardEscape = " · esc cancels"

func (m *Model) askCommit(draft deployDraft, problem string) tea.Cmd {
	return m.openPrompt("commit:", promptHint("full commit SHA CI built", problem), func(m *Model, text string) tea.Cmd {
		commit, err := parseCommit(text)
		if err != nil {
			return m.askCommit(draft, err.Error())
		}
		draft.commit = commit
		return m.askImages(draft, "")
	})
}

func (m *Model) askImages(draft deployDraft, problem string) tea.Cmd {
	return m.openPrompt("images:", promptHint("service=sha256:<digest>, comma separated", problem), func(m *Model, text string) tea.Cmd {
		images, err := parseImages(text)
		if err != nil {
			return m.askImages(draft, err.Error())
		}
		draft.images = images
		return m.reviewDeploy(draft)
	})
}

func promptHint(usage, problem string) string {
	if problem != "" {
		return problem + wizardEscape
	}
	return usage + wizardEscape
}

func parseCommit(text string) (string, error) {
	sha := strings.ToLower(strings.TrimSpace(text))
	if (len(sha) != 40 && len(sha) != 64) || !isHex(sha) {
		return "", fmt.Errorf("a commit is the full 40-character SHA, not %q", safe(text))
	}
	return sha, nil
}

func parseImages(text string) ([]wire.RequestedImage, error) {
	pairs := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(pairs) == 0 {
		return nil, fmt.Errorf("name at least one image as service=sha256:<digest>")
	}
	images := make([]wire.RequestedImage, 0, len(pairs))
	for _, pair := range pairs {
		service, digest, ok := strings.Cut(pair, "=")
		hex := strings.TrimPrefix(digest, digestPrefix)
		switch {
		case !ok || service == "":
			return nil, fmt.Errorf("%q must be service=sha256:<digest>", safe(pair))
		case len(hex) != digestHexLen || hex == digest || !isHex(hex):
			return nil, fmt.Errorf("the digest of %s must be sha256: and 64 hex characters", safe(service))
		case slices.ContainsFunc(images, func(i wire.RequestedImage) bool { return i.Service == service }):
			return nil, fmt.Errorf("%s is named twice", safe(service))
		}
		images = append(images, wire.RequestedImage{Service: service, Digest: strings.ToLower(digest)})
	}
	return images, nil
}

func isHex(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool {
		return (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F')
	})
}

// reviewDeploy shows exactly what will be requested. Confirming it is the only
// way a deployment is created.
func (m *Model) reviewDeploy(draft deployDraft) tea.Cmd {
	api, _ := m.api.(DeployAPI)
	lines := []string{
		"App:     " + safe(draft.app.Name),
		fmt.Sprintf("Target:  %s on node %s", safe(draft.target.Environment), shortID(draft.target.NodeID)),
		"Commit:  " + draft.commit,
	}
	for _, img := range draft.images {
		lines = append(lines, "Image:   "+safe(img.Service)+" "+img.Digest)
	}
	lines = append(lines, "",
		"Nothing runs yet. Confirming records the deployment; the daemon then",
		"verifies CI for this commit, freezes the plan and, when policy asks",
		"for it, waits for approval.")
	req := wire.CreateDeploymentRequest{
		AppTargetID: draft.target.ID, Kind: wizardDeploy, CommitSHA: draft.commit, Images: draft.images,
	}
	m.confirm = &confirmation{
		title: fmt.Sprintf("Deploy %s to %s", safe(draft.app.Name), safe(draft.target.Environment)),
		lines: lines,
		run: func(ctx context.Context) (string, error) {
			d, err := api.CreateDeployment(ctx, req)
			return deploymentNotice(d), err
		},
	}
	return nil
}

func deploymentNotice(d wire.Deployment) string {
	return fmt.Sprintf("%s %s is %s: follow it on the Deployments screen", d.Kind, shortID(d.ID), d.State)
}

// ---- rollback review -------------------------------------------------------------

func (m *Model) reviewRollback(app wire.App, target wire.AppTarget, deployments []wire.Deployment) tea.Cmd {
	current, ok := currentDeployment(deployments, target.ID)
	if !ok {
		m.notice = notice{text: fmt.Sprintf("nothing to roll back: %s / %s has no succeeded deployment", safe(app.Name), safe(target.Environment)), isErr: true}
		return nil
	}
	api, _ := m.api.(DeployAPI)
	m.confirm = &confirmation{
		title: fmt.Sprintf("Roll back %s in %s", safe(app.Name), safe(target.Environment)),
		lines: []string{
			fmt.Sprintf("Replaces deployment %s (commit %s)", shortID(current.ID), safe(current.CommitSHA[:min(len(current.CommitSHA), 7)])),
			"with the newest known-good deployment before it.",
			"",
			"The daemon picks that deployment and freezes the plan; policy may",
			"ask for approval before it runs.",
		},
		run: func(ctx context.Context) (string, error) {
			d, err := api.RollbackDeployment(ctx, current.ID, wire.RollbackRequest{})
			return deploymentNotice(d), err
		},
	}
	return nil
}

// currentDeployment is the newest succeeded deployment of a target: the one a
// rollback replaces.
func currentDeployment(deployments []wire.Deployment, target domain.ID) (wire.Deployment, bool) {
	var current wire.Deployment
	found := false
	for _, d := range deployments {
		if d.AppTargetID == target && d.State == "succeeded" && (!found || d.CreatedAt.After(current.CreatedAt)) {
			current, found = d, true
		}
	}
	return current, found
}
