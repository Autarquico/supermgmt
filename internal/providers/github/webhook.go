package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
)

const signaturePrefix = "sha256="

// ErrBadSignature means the webhook signature is missing, malformed or does
// not match the body. The caller answers 401 and acts on nothing.
var ErrBadSignature = errors.New("github: webhook signature does not match")

// ErrBadWebhookBody means a correctly signed body is unreadable or too large.
var ErrBadWebhookBody = errors.New("github: unreadable webhook body")

// VerifyWebhook checks the X-Hub-Signature-256 value over the raw body with
// HMAC-SHA256 (constant-time compare) and reduces the payload to what
// re-evaluation needs. Type is derived from the payload (check_run,
// check_suite, workflow_run); any other payload yields an empty Type, which
// the caller acknowledges and ignores. DeliveryID is not in the body: the
// caller fills it from X-GitHub-Delivery.
func VerifyWebhook(secret audit.Secret, signature string, body []byte) (WebhookEvent, error) {
	if secret.Reveal() == "" {
		return WebhookEvent{}, errors.New("github: webhook secret is empty")
	}
	if len(body) > MaxWebhookBody {
		return WebhookEvent{}, ErrBadWebhookBody
	}
	if !signatureMatches(secret, signature, body) {
		return WebhookEvent{}, ErrBadSignature
	}
	return parseWebhook(body)
}

func signatureMatches(secret audit.Secret, signature string, body []byte) bool {
	hexMAC, ok := strings.CutPrefix(signature, signaturePrefix)
	if !ok {
		return false
	}
	given, err := hex.DecodeString(hexMAC)
	if err != nil || len(given) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret.Reveal()))
	mac.Write(body)
	return hmac.Equal(given, mac.Sum(nil))
}

type webhookObject struct {
	HeadSHA string `json:"head_sha"`
}

func parseWebhook(body []byte) (WebhookEvent, error) {
	var doc struct {
		Repository struct {
			ID int64 `json:"id"`
		} `json:"repository"`
		CheckRun    *webhookObject `json:"check_run"`
		CheckSuite  *webhookObject `json:"check_suite"`
		WorkflowRun *webhookObject `json:"workflow_run"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return WebhookEvent{}, ErrBadWebhookBody
	}
	ev := WebhookEvent{RepositoryID: doc.Repository.ID}
	switch {
	case doc.CheckRun != nil:
		ev.Type, ev.HeadSHA = "check_run", doc.CheckRun.HeadSHA
	case doc.CheckSuite != nil:
		ev.Type, ev.HeadSHA = "check_suite", doc.CheckSuite.HeadSHA
	case doc.WorkflowRun != nil:
		ev.Type, ev.HeadSHA = "workflow_run", doc.WorkflowRun.HeadSHA
	default:
		return WebhookEvent{RepositoryID: ev.RepositoryID}, nil
	}
	if ev.RepositoryID <= 0 || !commitPattern.MatchString(ev.HeadSHA) {
		return WebhookEvent{}, ErrBadWebhookBody
	}
	return ev, nil
}
