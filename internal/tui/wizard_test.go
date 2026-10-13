package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

var (
	deployFlowCommit = strings.Repeat("ab", 20)
	deployFlowDigest = "sha256:" + strings.Repeat("c", 64)
)

// deployFlowAPI records what the wizard and the rollback review send.
type deployFlowAPI struct {
	*m4API
	created    []wire.CreateDeploymentRequest
	rolledBack []domain.ID
	rollbackTo []*domain.ID
	failCreate error
	detail     wire.Deployment
	events     []wire.Event
	eventQuery wire.EventQuery
}

func (f *deployFlowAPI) CreateDeployment(_ context.Context, r wire.CreateDeploymentRequest) (wire.Deployment, error) {
	f.created = append(f.created, r)
	return wire.Deployment{ID: m4DeployNew, Kind: r.Kind, State: "waiting_ci"}, f.failCreate
}

func (f *deployFlowAPI) RollbackDeployment(_ context.Context, id domain.ID, r wire.RollbackRequest) (wire.Deployment, error) {
	f.rolledBack = append(f.rolledBack, id)
	f.rollbackTo = append(f.rollbackTo, r.ToDeploymentID)
	return wire.Deployment{ID: m4DeployNew, Kind: "rollback", State: "created"}, nil
}

func (f *deployFlowAPI) GetDeployment(ctx context.Context, id domain.ID) (wire.Deployment, error) {
	if err := f.enter(ctx, "GetDeployment"); err != nil {
		return wire.Deployment{}, err
	}
	if f.detail.ID == "" {
		return wire.Deployment{ID: id}, nil
	}
	return f.detail, nil
}

func (f *deployFlowAPI) ListEvents(ctx context.Context, q wire.EventQuery) (wire.Page[wire.Event], error) {
	if err := f.enter(ctx, "ListEvents"); err != nil {
		return wire.Page[wire.Event]{}, err
	}
	f.eventQuery = q
	return wire.Page[wire.Event]{Items: f.events}, nil
}

const m4DeployNew domain.ID = "0192a000-0000-7000-8000-000000001099"

func newDeployFlow(t *testing.T) (*harness, *deployFlowAPI) {
	t.Helper()
	api := &deployFlowAPI{m4API: newM4API()}
	api.apps[0].Targets[1].NodeID = "0192a000-0000-7000-8000-00000000d001"
	h := newHarness(t, api, 80, 24)
	h.start()
	return h, api
}

func (h *harness) runPalette(line string) {
	h.t.Helper()
	h.press("/")
	h.typeText(line)
	h.press("enter")
}

// answerPrompt types text into the open prompt and submits it.
func (h *harness) answerPrompt(text string) {
	h.t.Helper()
	if h.m.prompt == nil {
		h.t.Fatalf("no prompt is open; view:\n%s", h.view())
	}
	h.typeText(text)
	h.press("enter")
}

func (h *harness) deployUntilReview() {
	h.t.Helper()
	h.runPalette("deploy shop production")
	h.answerPrompt(deployFlowCommit)
	h.answerPrompt("web=" + deployFlowDigest)
	if h.m.confirm == nil {
		h.t.Fatalf("the wizard did not reach the review:\n%s", h.view())
	}
}

func TestDeployWizardNeverCreatesWithoutReview(t *testing.T) {
	h, api := newDeployFlow(t)
	h.runPalette("deploy shop production")
	if h.m.prompt == nil || !strings.HasPrefix(h.m.input.Prompt, "commit:") {
		t.Fatalf("the wizard should ask for the commit first; prompt=%v", h.m.prompt)
	}
	h.answerPrompt(deployFlowCommit)
	if !strings.HasPrefix(h.m.input.Prompt, "images:") {
		t.Fatalf("the wizard should ask for the images next; prompt=%q", h.m.input.Prompt)
	}
	h.answerPrompt("web=" + deployFlowDigest)

	if len(api.created) != 0 {
		t.Fatalf("a deployment was created before the review was confirmed: %+v", api.created)
	}
	if h.m.confirm == nil {
		t.Fatal("the wizard must end on a review")
	}
	h.press("n")
	if len(api.created) != 0 || h.m.confirm != nil {
		t.Errorf("declining the review must create nothing; created=%d", len(api.created))
	}
}

func TestDeployWizardConfirmedReviewCreatesTheDeployment(t *testing.T) {
	h, api := newDeployFlow(t)
	h.deployUntilReview()
	h.press("y")

	want := wire.CreateDeploymentRequest{
		AppTargetID: m4TargetPrd, Kind: "deploy", CommitSHA: deployFlowCommit,
		Images: []wire.RequestedImage{{Service: "web", Digest: deployFlowDigest}},
	}
	if len(api.created) != 1 {
		t.Fatalf("created %d deployments, want 1", len(api.created))
	}
	got := api.created[0]
	if got.AppTargetID != want.AppTargetID || got.Kind != want.Kind || got.CommitSHA != want.CommitSHA ||
		len(got.Images) != 1 || got.Images[0] != want.Images[0] {
		t.Errorf("request = %+v, want %+v", got, want)
	}
	if notice := h.m.notice.text; !strings.Contains(notice, "waiting_ci") || h.m.notice.isErr {
		t.Errorf("notice = %q, want the new deployment's state", notice)
	}
}

func TestDeployWizardCreateFailureIsReported(t *testing.T) {
	h, api := newDeployFlow(t)
	api.failCreate = errors.New("CI not green")
	h.deployUntilReview()
	h.press("y")
	if notice := h.m.notice; !notice.isErr || !strings.Contains(notice.text, "CI not green") {
		t.Errorf("notice = %+v, want the failure", notice)
	}
}

func TestDeployWizardAsksAgainOnInvalidAnswers(t *testing.T) {
	cases := []struct {
		name   string
		answer func(*harness)
		want   string
		prompt string
	}{
		{"short commit", func(h *harness) { h.answerPrompt("abc123") }, "full 40-character SHA", "commit:"},
		{"bare image", func(h *harness) { h.answerPrompt(deployFlowCommit); h.answerPrompt("web") }, "service=sha256", "images:"},
		{"short digest", func(h *harness) { h.answerPrompt(deployFlowCommit); h.answerPrompt("web=sha256:abc") }, "64 hex", "images:"},
		{"duplicate service", func(h *harness) {
			h.answerPrompt(deployFlowCommit)
			h.answerPrompt("web=" + deployFlowDigest + ",web=" + deployFlowDigest)
		}, "named twice", "images:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, api := newDeployFlow(t)
			h.runPalette("deploy shop production")
			tc.answer(h)
			if h.m.prompt == nil || !strings.HasPrefix(h.m.input.Prompt, tc.prompt) {
				t.Fatalf("the wizard should ask %s again; prompt=%v", tc.prompt, h.m.prompt)
			}
			if !strings.Contains(h.m.prompt.hint, tc.want) {
				t.Errorf("hint = %q, want it to say %q", h.m.prompt.hint, tc.want)
			}
			if h.m.confirm != nil || len(api.created) != 0 {
				t.Error("an invalid answer must not reach the review")
			}
		})
	}
}

func TestDeployWizardEscapeCancels(t *testing.T) {
	h, api := newDeployFlow(t)
	h.runPalette("deploy shop production")
	h.press("esc")
	if h.m.prompt != nil || h.m.confirm != nil || len(api.created) != 0 {
		t.Error("esc must leave the wizard without creating anything")
	}
}

func TestDeployWizardRejectsUnknownTargets(t *testing.T) {
	for line, want := range map[string]string{
		"deploy nope production": `no app matches "nope"`,
		"deploy shop mars":       `no target in environment "mars"`,
		"deploy shop":            "usage: deploy <app> <environment>",
		"rollback shop":          "usage: rollback <app> <environment>",
	} {
		h, _ := newDeployFlow(t)
		h.runPalette(line)
		if notice := h.m.notice; !notice.isErr || !strings.Contains(notice.text, want) || h.m.prompt != nil {
			t.Errorf("%q: notice = %+v prompt=%v, want %q", line, notice, h.m.prompt, want)
		}
	}
}

func TestDeployWizardNeedsADaemonThatServesApps(t *testing.T) {
	h := newHarness(t, newFake(), 80, 24)
	h.start()
	h.runPalette("deploy shop production")
	if notice := h.m.notice; !notice.isErr || !strings.Contains(notice.text, unavailableApps) {
		t.Errorf("notice = %+v, want %q", notice, unavailableApps)
	}
}

func TestDeployWizardReportsAFailedStart(t *testing.T) {
	h, api := newDeployFlow(t)
	api.hook("ListApps", func(context.Context) error { return errors.New("daemon went away") })
	h.runPalette("deploy shop production")
	if notice := h.m.notice; !notice.isErr || !strings.Contains(notice.text, "cannot start deploy") {
		t.Errorf("notice = %+v", notice)
	}
}

func TestRollbackReviewReplacesTheNewestDeploymentAndNamesTheKnownGoodOne(t *testing.T) {
	h, api := newDeployFlow(t)
	// Production: known-good 1005 (-3h30), then 1002 failed (-2h), then 1003
	// waiting_ci (-1h), the newest. The CLI would pass 1003 and the daemon
	// restores 1005, the newest known-good before it.
	api.deployments = append(api.deployments,
		wire.Deployment{
			ID: "0192a000-0000-7000-8000-000000001005", Kind: "deploy", AppID: m4AppShop, AppTargetID: m4TargetPrd,
			State: "succeeded", KnownGood: true, CommitSHA: "5555555eeee", CreatedAt: epoch.Add(-210 * time.Minute),
		},
		wire.Deployment{
			ID: "0192a000-0000-7000-8000-000000001006", Kind: "deploy", AppID: m4AppShop, AppTargetID: m4TargetPrd,
			State: "succeeded", KnownGood: true, CommitSHA: "6666666ffff", CreatedAt: epoch.Add(-300 * time.Minute),
		})
	h.runPalette("rollback shop production")
	if h.m.confirm == nil {
		t.Fatalf("no review opened:\n%s", h.view())
	}
	view := h.view()
	for _, want := range []string{"3333333", "known-good deployment", "5555555"} {
		if !strings.Contains(view, want) {
			t.Errorf("review does not show %q:\n%s", want, view)
		}
	}
	if len(api.rolledBack) != 0 {
		t.Fatal("the rollback was requested before the review was confirmed")
	}
	h.press("y")
	if len(api.rolledBack) != 1 || api.rolledBack[0] != m4DeployTri {
		t.Errorf("rolled back %v, want the newest deployment of production in any state", api.rolledBack)
	}
	if api.rollbackTo[0] != nil {
		t.Errorf("the daemon should pick the known-good target, got %v", *api.rollbackTo[0])
	}
}

func TestRollbackWithNoDeploymentIsRefused(t *testing.T) {
	h, api := newDeployFlow(t)
	h.runPalette("rollback shop staging")
	if h.m.confirm == nil {
		t.Fatalf("staging has a deployment; no review opened:\n%s", h.view())
	}
	h.press("n")

	api.deployments = nil
	h.runPalette("rollback shop production")
	if notice := h.m.notice; h.m.confirm != nil || !notice.isErr || !strings.Contains(notice.text, "nothing to roll back") {
		t.Errorf("notice = %+v confirm=%v, want a refusal", notice, h.m.confirm)
	}
}

func TestParseImages(t *testing.T) {
	good, err := parseImages("web=" + deployFlowDigest + ", worker=" + deployFlowDigest)
	if err != nil || len(good) != 2 || good[1].Service != "worker" {
		t.Fatalf("parseImages = %+v, %v", good, err)
	}
	for _, bad := range []string{"", "  ", "=" + deployFlowDigest, "web=" + strings.Repeat("c", 64), "web=sha256:" + strings.Repeat("z", 64)} {
		if _, err := parseImages(bad); err == nil {
			t.Errorf("parseImages(%q) accepted it", bad)
		}
	}
}

func TestWizardReviewGolden(t *testing.T) {
	h, _ := newDeployFlow(t)
	h.deployUntilReview()
	bw, bh := h.m.bodySize()
	assertGolden(t, "m4_wizard_review", stripANSI(strings.Join(fitLines(h.m.confirmBody(bw), bw, bh), "\n")), bw, bh)
}
