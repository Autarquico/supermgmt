package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

func TestWebhookAuditRecordsAProviderEventWithTheDeliveryData(t *testing.T) {
	f := newAppsFixture(t)
	audit := NewWebhookAudit(f.cfg)
	ev := github.WebhookEvent{DeliveryID: "d-1", Type: "check_run", RepositoryID: 4242, HeadSHA: "abc123"}

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return audit.Record(ctx, tx, f.ghHost, ev, "nudged")
	})

	got := f.events(eventWebhookReceived)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	e := got[0]
	if e.ResourceType != domain.ResourceProvider || e.ResourceID != f.ghHost.ID || e.ActorType != domain.ActorSystem || e.Result != domain.ResultSucceeded {
		t.Errorf("event = %+v", e)
	}
	for k, want := range map[string]any{"delivery_id": "d-1", "event_type": "check_run", "head_sha": "abc123", "status": "nudged"} {
		if e.Data[k] != want {
			t.Errorf("data[%s] = %v, want %v", k, e.Data[k], want)
		}
	}
	if e.Data["repository_id"] != float64(4242) {
		t.Errorf("repository_id = %v (%T), want 4242", e.Data["repository_id"], e.Data["repository_id"])
	}
}
