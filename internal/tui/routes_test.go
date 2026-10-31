package tui

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

type routesAPI struct {
	*m4API
	exposed   []wire.ExposeAppRouteRequest
	exposedOn []domain.ID
	removed   []string
}

func (f *routesAPI) ExposeAppRoute(_ context.Context, target domain.ID, r wire.ExposeAppRouteRequest) (wire.AppRouteSubmission, error) {
	f.exposed, f.exposedOn = append(f.exposed, r), append(f.exposedOn, target)
	return wire.AppRouteSubmission{Submission: wire.Submission{Job: wire.Job{ID: idJob, State: domain.JobAwaitingApproval}}}, nil
}

func (f *routesAPI) UnexposeAppRoute(_ context.Context, _ domain.ID, hostname string) (wire.AppRouteSubmission, error) {
	f.removed = append(f.removed, hostname)
	return wire.AppRouteSubmission{Submission: wire.Submission{Job: wire.Job{ID: idJob, State: domain.JobQueued}}}, nil
}

func TestExposeViaPaletteWarnsAboutAPublicRouteAndSubmitsOnConfirm(t *testing.T) {
	api := &routesAPI{m4API: newM4API()}
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("expose shop production shop.example.com web 8080")
	h.press("enter")

	contains(t, h.view(), "reachable from the internet with no authentication")
	if len(api.exposed) != 0 {
		t.Fatalf("exposed before the confirmation: %+v", api.exposed)
	}
	h.press("y")
	if len(api.exposed) != 1 || api.exposedOn[0] != m4TargetPrd {
		t.Fatalf("exposed %+v on %v", api.exposed, api.exposedOn)
	}
	if got := api.exposed[0]; got.Hostname != "shop.example.com" || got.Service != "web" || got.Port != 8080 || got.Access != "public" {
		t.Errorf("request = %+v", got)
	}
}

func TestExposeOwnersViaPaletteHasNoPublicWarning(t *testing.T) {
	api := &routesAPI{m4API: newM4API()}
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("expose shop staging shop.example.com web 8080 owners")
	h.press("enter")

	lacks(t, h.view(), "no authentication")
	h.press("y")
	if len(api.exposed) != 1 || api.exposed[0].Access != "owners" || api.exposedOn[0] != m4TargetStg {
		t.Errorf("exposed %+v on %v", api.exposed, api.exposedOn)
	}
}

func TestUnexposeViaPaletteAsksFirst(t *testing.T) {
	api := &routesAPI{m4API: newM4API()}
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("unexpose shop production shop.example.com")
	h.press("enter")
	if len(api.removed) != 0 {
		t.Fatalf("removed before the confirmation: %v", api.removed)
	}
	h.press("y")
	if len(api.removed) != 1 || api.removed[0] != "shop.example.com" {
		t.Errorf("removed = %v", api.removed)
	}
}

func TestRouteCommandsValidateTheirWordsAndTheDaemon(t *testing.T) {
	api := &routesAPI{m4API: newM4API()}
	h := newHarness(t, api, 120, 28)
	h.start()
	for line, want := range map[string]string{
		"expose shop production shop.example.com web":           "usage: expose",
		"expose shop production shop.example.com web x":         "the port is a number",
		"expose shop production shop.example.com web 80 anyone": "usage: expose",
		"unexpose shop production":                              "usage: unexpose",
		"expose nope production shop.example.com web 8080":      "no app matches",
		"expose shop nowhere shop.example.com web 8080 public":  "has no target",
	} {
		h.press("esc", "/")
		h.typeText(line)
		h.press("enter")
		contains(t, h.view(), want)
	}

	bare := newHarness(t, newM4API(), 120, 28)
	bare.start()
	bare.press("/")
	bare.typeText("expose shop production shop.example.com web 8080")
	bare.press("enter")
	contains(t, bare.view(), unavailableRoutes)
}
