package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// ExemptWebhook is for the GitHub webhook endpoint: it carries no bearer
// token, its caller is authenticated by the HMAC of the body (spec §18,
// ADR-0012). It is served over HTTPS only; in local mode CI is polled.
const ExemptWebhook = "exempt:webhook"

const (
	webhookSecretRefKey = "webhook_secret_ref"
	maxDeliveryIDBytes  = 128

	webhookNudged    = "nudged"
	webhookIgnored   = "ignored"
	webhookDuplicate = "duplicate"
)

// webhookRate bounds deliveries per client address; a push fans out into
// several check events, so the burst is wider than the login buckets.
var webhookRate = bucketRate{perMinute: 120, burst: 60}

// Nudger is what a verified webhook triggers: one re-evaluation of the
// deployments waiting on a commit (app.CIWatcher).
type Nudger interface {
	Nudge(repositoryID int64, sha string)
}

// SecretReader reads secret values (secrets.Store).
type SecretReader interface {
	Get(ctx context.Context, ref secrets.Ref) (audit.Secret, error)
}

// GitHubWebhook serves POST /github/webhook. A delivery is attributed to the
// GitHub provider whose webhook secret signs it; an unsigned or wrongly
// signed body acts on nothing.
type GitHubWebhook struct {
	DB      *database.DB
	Secrets SecretReader
	Watcher Nudger

	// Audit, when set, records each new delivery in the transaction that
	// stores it (app.WebhookAudit.Record); a failure rejects the delivery
	// so the sender retries it.
	Audit func(ctx context.Context, q database.Querier, p domain.Provider, ev github.WebhookEvent, status string) error
}

func (w GitHubWebhook) complete() error {
	if w.DB == nil || w.Secrets == nil || w.Watcher == nil {
		return errors.New("api: the github webhook needs a database, a secret reader and a CI watcher")
	}
	return nil
}

type webhookAck struct {
	Status string `json:"status"` // nudged | ignored | duplicate
}

func (rs *routeSet) webhook() {
	s := rs.s
	if s.webhooks == nil {
		return
	}
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathGitHubWebhook, action: ExemptWebhook, auth: authNone, httpsOnly: true,
		maxBody: github.MaxWebhookBody, do: s.receiveWebhook,
	})
}

func (s *Server) receiveWebhook(w http.ResponseWriter, r *http.Request) error {
	if ok, after := s.webhookLimit.allow(scopeOf(r.Context()).client.String()); !ok {
		return &rateLimited{after: after}
	}
	in, err := readInput(r)
	if err != nil {
		return err
	}
	deliveryID, err := deliveryIDOf(r)
	if err != nil {
		return err
	}
	provider, event, err := s.webhooks.authenticate(r.Context(), r.Header.Get(github.HeaderSignature), in.body, s.log)
	if err != nil {
		return err
	}
	event.DeliveryID = deliveryID
	status, err := s.webhooks.accept(r.Context(), s.clock.Now, s.ids, provider, event)
	if err != nil {
		return err
	}
	s.writeData(w, r, http.StatusOK, webhookAck{Status: status})
	return nil
}

func deliveryIDOf(r *http.Request) (string, error) {
	id := r.Header.Get(github.HeaderDelivery)
	if id == "" || len(id) > maxDeliveryIDBytes || !utf8.ValidString(id) || strings.ContainsFunc(id, func(c rune) bool { return c < ' ' || c == 0x7f }) {
		return "", invalid("%s must be a printable delivery id of at most %d bytes", github.HeaderDelivery, maxDeliveryIDBytes)
	}
	return id, nil
}

// authenticate finds the provider whose webhook secret signs body and returns
// it with the payload reduced to what re-evaluation needs. No match is the
// same UNAUTHENTICATED whatever the reason, so a sender learns nothing about
// which providers exist.
func (g GitHubWebhook) authenticate(ctx context.Context, signature string, body []byte, log *slog.Logger) (domain.Provider, github.WebhookEvent, error) {
	providers, err := database.ListProviders(ctx, g.DB.Reader())
	if err != nil {
		return domain.Provider{}, github.WebhookEvent{}, err
	}
	for _, p := range providers {
		secret, ok := g.webhookSecretOf(ctx, p, log)
		if !ok {
			continue
		}
		event, err := github.VerifyWebhook(secret, signature, body)
		switch {
		case err == nil:
			return p, event, nil
		case errors.Is(err, github.ErrBadWebhookBody):
			return domain.Provider{}, github.WebhookEvent{}, invalid("the webhook body is not a supported GitHub event payload")
		}
	}
	return domain.Provider{}, github.WebhookEvent{}, smerr.New(smerr.CodeUnauthenticated, "", "the webhook signature does not match")
}

func (g GitHubWebhook) webhookSecretOf(ctx context.Context, p domain.Provider, log *slog.Logger) (audit.Secret, bool) {
	if p.Type != github.ProviderType {
		return "", false
	}
	ref, _ := p.Config[webhookSecretRefKey].(string)
	name, ok := strings.CutPrefix(ref, "secret://")
	if !ok || name == "" {
		return "", false
	}
	secret, err := g.Secrets.Get(ctx, secrets.Ref{Name: name})
	if err != nil {
		log.WarnContext(ctx, "github webhook secret unavailable", "provider", p.Name)
		return "", false
	}
	return secret, true
}

// accept records the delivery once and, if it is new, nudges the CI watcher
// for the commit it names. A redelivery acts on nothing.
func (g GitHubWebhook) accept(ctx context.Context, now func() time.Time, ids domain.IDGenerator, p domain.Provider, ev github.WebhookEvent) (string, error) {
	received := now()
	var fresh bool
	err := g.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		var err error
		fresh, err = database.RecordWebhookDelivery(ctx, tx, database.WebhookDelivery{
			ID: ids.NewID(), Provider: p.ID.String(), DeliveryID: ev.DeliveryID,
			ReceivedAt: received, SignatureValid: true, EventType: ev.Type,
		})
		if err != nil || !fresh {
			return err
		}
		status := resultOf(ev)
		if err := database.MarkWebhookDeliveryProcessed(ctx, tx, p.ID.String(), ev.DeliveryID, received, status); err != nil {
			return err
		}
		return g.audit(ctx, tx, p, ev, status)
	})
	switch {
	case err != nil:
		return "", err
	case !fresh:
		return webhookDuplicate, nil
	case ev.Type == "":
		return webhookIgnored, nil
	}
	g.Watcher.Nudge(ev.RepositoryID, ev.HeadSHA)
	return webhookNudged, nil
}

func (g GitHubWebhook) audit(ctx context.Context, q database.Querier, p domain.Provider, ev github.WebhookEvent, status string) error {
	if g.Audit == nil {
		return nil
	}
	return g.Audit(ctx, q, p, ev, status)
}

func resultOf(ev github.WebhookEvent) string {
	if ev.Type == "" {
		return webhookIgnored
	}
	return webhookNudged
}
