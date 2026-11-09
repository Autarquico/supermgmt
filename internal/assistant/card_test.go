package assistant

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

type namedService struct {
	Reader
	name string
}

func (n namedService) GetService(_ context.Context, id domain.ID) (wire.Service, error) {
	return wire.Service{ID: id, Name: n.name, Node: "web-1"}, nil
}

func TestTargetNameKeepsARemoteNameToOneRow(t *testing.T) {
	id := "0191f2a4-7c3e-7b1a-8d2f-3a4b5c6d7e8f"
	hostile := "nginx" + strings.Repeat(" ", 200) + "Risk: low"
	got := targetName(context.Background(), namedService{name: hostile}, "service", id)
	if strings.Contains(got, "  ") || len([]rune(got)) > 2*maxNameRunes+100 || !strings.Contains(got, id) {
		t.Fatalf("target row = %q", got)
	}
	got = targetName(context.Background(), namedService{name: strings.Repeat("x", 500)}, "service", id)
	if len([]rune(got)) > 2*maxNameRunes+100 {
		t.Fatalf("a long name was not cut: %d runes", len([]rune(got)))
	}
}

func TestNewCardBoundsTargetsAndRefusesAnUnreadablePlan(t *testing.T) {
	var plan strings.Builder
	plan.WriteString(`{"action":"restart\n","risk":"low","steps":["a\tb"],"targets":[`)
	for i := range 13 {
		if i > 0 {
			plan.WriteString(",")
		}
		plan.WriteString(`{"type":"service","id":"s` + string(rune('a'+i)) + `"}`)
	}
	plan.WriteString("]}")
	card, ok := NewCard(context.Background(), namedService{name: "web"}, wire.Approval{Plan: []byte(plan.String())})
	if !ok || len(card.Targets) != maxCardTargets || card.More != 3 || strings.ContainsAny(card.Plan.Action, "\n") {
		t.Fatalf("card = %+v ok=%v", card, ok)
	}
	if _, ok := NewCard(context.Background(), namedService{}, wire.Approval{Plan: []byte(`{"risk":"low"}`)}); ok {
		t.Fatal("a plan without an action was offered")
	}
}
