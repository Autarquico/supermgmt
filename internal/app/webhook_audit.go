package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

const eventWebhookReceived = "webhook.received"

// WebhookAudit records the verified GitHub webhook deliveries (ADR-0029): the
// event is attributed to the provider whose secret signed the delivery.
type WebhookAudit struct{ core }

// NewWebhookAudit builds the recorder from the app configuration.
func NewWebhookAudit(cfg Config) WebhookAudit {
	return WebhookAudit{core{cfg: cfg, emitter: audit.Emitter{Clock: cfg.Clock, IDs: cfg.IDs, Source: eventSource}}}
}

// Record appends the delivery's event through q, so it commits with the
// delivery row. status is what the webhook did with it (nudged | ignored).
func (w WebhookAudit) Record(ctx context.Context, q database.Querier, p domain.Provider, ev github.WebhookEvent, status string) error {
	return w.emit(ctx, q, systemActor, eventWebhookReceived, domain.ResourceRef{Type: domain.ResourceProvider, ID: p.ID},
		domain.ResultSucceeded, map[string]any{
			"delivery_id":   ev.DeliveryID,
			"event_type":    ev.Type,
			"repository_id": ev.RepositoryID,
			"head_sha":      ev.HeadSHA,
			"status":        status,
		})
}
