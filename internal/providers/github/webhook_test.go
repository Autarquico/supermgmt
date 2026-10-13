package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
)

const webhookSecret = audit.Secret("whsec-test-0123456789")

func webhookSign(secret audit.Secret, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret.Reveal()))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhook_ReducesVerifiedEvents(t *testing.T) {
	tests := []struct {
		name string
		body string
		want WebhookEvent
	}{
		{"check_run", `{"action":"completed","check_run":{"head_sha":"` + commitA + `"},"repository":{"id":42}}`, WebhookEvent{Type: "check_run", RepositoryID: 42, HeadSHA: commitA}},
		{"check_suite", `{"check_suite":{"head_sha":"` + commitA + `"},"repository":{"id":42}}`, WebhookEvent{Type: "check_suite", RepositoryID: 42, HeadSHA: commitA}},
		{"workflow_run", `{"workflow_run":{"head_sha":"` + commitA + `"},"repository":{"id":42}}`, WebhookEvent{Type: "workflow_run", RepositoryID: 42, HeadSHA: commitA}},
		{"other event is acknowledged, not interpreted", `{"zen":"hi","repository":{"id":42}}`, WebhookEvent{RepositoryID: 42}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			got, err := VerifyWebhook(webhookSecret, webhookSign(webhookSecret, body), body)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("event = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestVerifyWebhook_RejectsBadSignatures(t *testing.T) {
	body := []byte(`{"check_run":{"head_sha":"` + commitA + `"},"repository":{"id":42}}`)
	good := webhookSign(webhookSecret, body)
	tests := []struct {
		name      string
		signature string
		body      []byte
		secret    audit.Secret
	}{
		{"wrong secret", webhookSign("another-secret", body), body, webhookSecret},
		{"tampered body", good, append([]byte(" "), body...), webhookSecret},
		{"empty header", "", body, webhookSecret},
		{"missing prefix", strings.TrimPrefix(good, "sha256="), body, webhookSecret},
		{"sha1 scheme", "sha1=" + strings.TrimPrefix(good, "sha256="), body, webhookSecret},
		{"truncated header", good[:len(good)-2], body, webhookSecret},
		{"truncated to the prefix", "sha256=", body, webhookSecret},
		{"odd-length hex", good[:len(good)-1], body, webhookSecret},
		{"not hex", "sha256=" + strings.Repeat("zz", 32), body, webhookSecret},
		{"uppercase prefix", strings.Replace(good, "sha256", "SHA256", 1), body, webhookSecret},
		{"overlong", good + "00", body, webhookSecret},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyWebhook(tc.secret, tc.signature, tc.body)
			if !errors.Is(err, ErrBadSignature) {
				t.Errorf("err = %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestVerifyWebhook_EmptySecretNeverVerifies(t *testing.T) {
	body := []byte(`{}`)
	if _, err := VerifyWebhook("", webhookSign("", body), body); err == nil {
		t.Fatal("an empty secret must not verify anything")
	}
}

func TestVerifyWebhook_OversizeBodyIsRefusedBeforeHashing(t *testing.T) {
	body := []byte(`{"pad":"` + strings.Repeat("x", MaxWebhookBody) + `"}`)
	_, err := VerifyWebhook(webhookSecret, webhookSign(webhookSecret, body), body)
	if !errors.Is(err, ErrBadWebhookBody) {
		t.Errorf("err = %v, want ErrBadWebhookBody", err)
	}
}

func TestVerifyWebhook_SignedButMalformedPayload(t *testing.T) {
	tests := []struct{ name, body string }{
		{"not json", `not json`},
		{"check_run without repository", `{"check_run":{"head_sha":"` + commitA + `"}}`},
		{"check_run with a bad sha", `{"check_run":{"head_sha":"main"},"repository":{"id":42}}`},
		{"workflow_run without a sha", `{"workflow_run":{},"repository":{"id":42}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			_, err := VerifyWebhook(webhookSecret, webhookSign(webhookSecret, body), body)
			if !errors.Is(err, ErrBadWebhookBody) {
				t.Errorf("err = %v, want ErrBadWebhookBody", err)
			}
		})
	}
}
