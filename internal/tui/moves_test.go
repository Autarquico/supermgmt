package tui

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

type movesAPI struct {
	*m4API
	moved   []domain.ID
	movedTo []domain.ID
}

func (f *movesAPI) MoveApp(_ context.Context, target, to domain.ID) (wire.AppMoveSubmission, error) {
	f.moved, f.movedTo = append(f.moved, target), append(f.movedTo, to)
	return wire.AppMoveSubmission{
		Move:       wire.AppMove{Stateful: true},
		Submission: wire.Submission{Job: wire.Job{ID: idJob, State: domain.JobAwaitingApproval}},
	}, nil
}

func TestMoveViaPaletteAsksFirstAndSubmitsTheResolvedNode(t *testing.T) {
	api := &movesAPI{m4API: newM4API()}
	h := newHarness(t, api, 120, 28)
	h.start()

	h.press("/")
	h.typeText("move shop production db-1")
	h.press("enter")

	contains(t, h.view(), "stops while their data is copied")
	if len(api.moved) != 0 {
		t.Fatalf("moved before the confirmation: %v", api.moved)
	}
	h.press("y")
	if len(api.moved) != 1 || api.moved[0] != m4TargetPrd || api.movedTo[0] != idDB {
		t.Errorf("moved %v to %v", api.moved, api.movedTo)
	}
}

func TestMoveCommandValidatesItsWordsAndTheDaemon(t *testing.T) {
	api := &movesAPI{m4API: newM4API()}
	h := newHarness(t, api, 120, 28)
	h.start()
	for line, want := range map[string]string{
		"move shop production":           "usage: move",
		"move shop production nowhere-9": "nowhere-9",
		"move nope production db-1":      "no app matches",
		"move shop nowhere db-1":         "has no target",
	} {
		h.press("esc", "/")
		h.typeText(line)
		h.press("enter")
		contains(t, h.view(), want)
	}

	bare := newHarness(t, newM4API(), 120, 28)
	bare.start()
	bare.press("/")
	bare.typeText("move shop production db-1")
	bare.press("enter")
	contains(t, bare.view(), unavailableMoves)
}
