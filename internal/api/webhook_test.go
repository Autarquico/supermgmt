package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

const (
	webhookSecretValue = "whsec-test"
	webhookSHA         = "0123456789abcdef0123456789abcdef01234567"
	webhookCheckRun    = `{"repository":{"id":42},"check_run":{"head_sha":"` + webhookSHA + `"}}`
	webhookPing        = `{"repository":{"id":42},"zen":"keep it logically awesome"}`
)

func signed(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// withWebhookProvider registers a github provider whose webhook secret exists.
func (f *m4Fixture) withWebhookProvider() {
	f.t.Helper()
	f.secrets["providers/gh/webhook"] = webhookSecretValue
	must(f.t, f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.CreateProvider(ctx, tx, domain.Provider{
			ID: f.ids.NewID(), Type: github.ProviderType, Name: "gh", Origin: domain.ProviderStatic, Endpoint: "https://api.github.com",
			CredentialRef: "secret://providers/gh/token", Status: "ready",
			Config: map[string]any{"webhook_secret_ref": "secret://providers/gh/webhook"}, CreatedAt: f.clock.Now(), UpdatedAt: f.clock.Now(),
		})
		return err
	}))
}

func (f *m4Fixture) deliver(delivery, signature, body string) reply {
	f.t.Helper()
	headers := []string{github.HeaderSignature, signature, "Content-Type", "application/json"}
	if delivery != "" {
		headers = append(headers, github.HeaderDelivery, delivery)
	}
	return f.do(http.MethodPost, wire.PathGitHubWebhook, "", body, headers...)
}

func (f *m4Fixture) deliveryRows() int {
	f.t.Helper()
	var n int
	must(f.t, f.db.Reader().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM webhook_deliveries`).Scan(&n))
	return n
}

func TestWebhookSignedDeliveryNudgesTheWatcherOnceWithoutABearerToken(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()

	r := f.deliver("d-1", signed(webhookSecretValue, webhookCheckRun), webhookCheckRun)

	if r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"nudged"`) {
		t.Fatalf("status %d body %s", r.Status, r.Body)
	}
	if got := f.nudges.seen(); len(got) != 1 || got[0] != (nudgeCall{42, webhookSHA}) {
		t.Errorf("nudges = %+v, want one for repository 42 at %s", got, webhookSHA)
	}
	if f.deliveryRows() != 1 {
		t.Errorf("delivery rows = %d, want 1", f.deliveryRows())
	}
}

func TestWebhookReplayedDeliveryIsAcknowledgedAndNotReevaluated(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()
	sig := signed(webhookSecretValue, webhookCheckRun)

	f.deliver("d-1", sig, webhookCheckRun)
	r := f.deliver("d-1", sig, webhookCheckRun)

	if r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"duplicate"`) {
		t.Fatalf("status %d body %s", r.Status, r.Body)
	}
	if n := len(f.nudges.seen()); n != 1 {
		t.Errorf("nudges = %d, want 1", n)
	}
	if f.deliveryRows() != 1 {
		t.Errorf("delivery rows = %d, want 1", f.deliveryRows())
	}
}

func TestWebhookForgedDeliveriesAreRefusedAndActOnNothing(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()
	cases := []struct{ name, signature string }{
		{"wrong secret", signed("other", webhookCheckRun)},
		{"signature of another body", signed(webhookSecretValue, webhookPing)},
		{"no signature", ""},
		{"truncated header", "sha256="},
		{"wrong scheme", "sha1=" + strings.Repeat("0", 40)},
		{"odd hex", "sha256=abc"},
	}
	for i, tc := range cases {
		r := f.deliver(fmt.Sprintf("forged-%d", i), tc.signature, webhookCheckRun)
		if r.Status != http.StatusUnauthorized {
			t.Errorf("%s: status %d body %s, want 401", tc.name, r.Status, r.Body)
		}
	}
	if n := len(f.nudges.seen()); n != 0 {
		t.Errorf("a forged delivery nudged %d times", n)
	}
	if f.deliveryRows() != 0 {
		t.Errorf("a forged delivery was recorded")
	}
}

func TestWebhookWithoutAProviderSecretIsRefused(t *testing.T) {
	f := newM4Fixture(t)
	if r := f.deliver("d-1", signed(webhookSecretValue, webhookCheckRun), webhookCheckRun); r.Status != http.StatusUnauthorized {
		t.Errorf("status %d body %s, want 401", r.Status, r.Body)
	}
}

func TestWebhookOversizeBodyIsRefused(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()
	body := `{"pad":"` + strings.Repeat("a", github.MaxWebhookBody) + `"}`

	r := f.deliver("d-1", signed(webhookSecretValue, body), body)

	if r.Status != http.StatusBadRequest {
		t.Errorf("status %d, want 400", r.Status)
	}
	if len(f.nudges.seen()) != 0 || f.deliveryRows() != 0 {
		t.Error("an oversize delivery acted")
	}
}

func TestWebhookNeedsADeliveryID(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()
	if r := f.deliver("", signed(webhookSecretValue, webhookCheckRun), webhookCheckRun); r.Status != http.StatusBadRequest {
		t.Errorf("status %d body %s, want 400", r.Status, r.Body)
	}
}

func TestWebhookEventsOtherThanChecksAreAcknowledgedAndIgnored(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()

	r := f.deliver("d-ping", signed(webhookSecretValue, webhookPing), webhookPing)

	if r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"ignored"`) {
		t.Fatalf("status %d body %s", r.Status, r.Body)
	}
	if len(f.nudges.seen()) != 0 {
		t.Error("an ignored event nudged")
	}
}

func TestWebhookIsRateLimitedPerClient(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()
	sig := signed(webhookSecretValue, webhookPing)
	var last reply
	for i := 0; i <= int(webhookRate.burst); i++ {
		last = f.deliver(fmt.Sprintf("d-%d", i), sig, webhookPing)
	}
	if last.Status != http.StatusTooManyRequests {
		t.Errorf("delivery %d: status %d, want 429", int(webhookRate.burst)+1, last.Status)
	}
}

type auditedDelivery struct {
	provider domain.ID
	delivery string
	status   string
}

// acceptWithAudit runs the webhook's accept step with an Audit hook that
// records its calls, or fails with auditErr.
func (f *m4Fixture) acceptWithAudit(auditErr error, deliveries ...github.WebhookEvent) ([]auditedDelivery, []error, domain.Provider) {
	f.t.Helper()
	providers, err := database.ListProviders(context.Background(), f.db.Reader())
	must(f.t, err)
	var seen []auditedDelivery
	hook := GitHubWebhook{
		DB: f.db, Secrets: f.secrets, Watcher: f.nudges,
		Audit: func(_ context.Context, _ database.Querier, p domain.Provider, ev github.WebhookEvent, status string) error {
			seen = append(seen, auditedDelivery{p.ID, ev.DeliveryID, status})
			return auditErr
		},
	}
	var errs []error
	for _, ev := range deliveries {
		_, err := hook.accept(context.Background(), f.clock.Now, f.ids, providers[0], ev)
		errs = append(errs, err)
	}
	return seen, errs, providers[0]
}

func TestWebhookAuditsEachNewDeliveryOnceWithItsOutcome(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()
	check := github.WebhookEvent{DeliveryID: "d-1", Type: "check_run", RepositoryID: 42, HeadSHA: webhookSHA}
	ping := github.WebhookEvent{DeliveryID: "d-2"}

	seen, errs, p := f.acceptWithAudit(nil, check, check, ping)

	for _, err := range errs {
		must(t, err)
	}
	want := []auditedDelivery{{p.ID, "d-1", webhookNudged}, {p.ID, "d-2", webhookIgnored}}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("audited %+v, want %+v (a redelivery is not audited again)", seen, want)
	}
}

func TestWebhookAuditFailureRejectsTheDeliveryAndRecordsNothing(t *testing.T) {
	f := newM4Fixture(t)
	f.withWebhookProvider()

	_, errs, _ := f.acceptWithAudit(fmt.Errorf("audit down"), github.WebhookEvent{DeliveryID: "d-1", Type: "check_run", RepositoryID: 42, HeadSHA: webhookSHA})

	if errs[0] == nil {
		t.Fatal("accept succeeded although the audit failed")
	}
	if f.deliveryRows() != 0 || len(f.nudges.seen()) != 0 {
		t.Errorf("a rejected delivery left rows=%d nudges=%d; a retry must be treated as new", f.deliveryRows(), len(f.nudges.seen()))
	}
}
