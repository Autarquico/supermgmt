package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// webhookRequest asks the simulator to deliver one webhook the way GitHub does: a JSON body signed
// with HMAC-SHA256 in X-Hub-Signature-256, the event name in X-GitHub-Event and a delivery id.
type webhookRequest struct {
	URL          string `json:"url"`
	Secret       string `json:"secret"`
	CAPEM        string `json:"ca_pem"`
	Event        string `json:"event"` // check_run | check_suite | workflow_run
	Delivery     string `json:"delivery"`
	RepositoryID int64  `json:"repository_id"`
	HeadSHA      string `json:"head_sha"`
	// BadSignature signs the body with another secret, as a forged delivery would be.
	BadSignature bool `json:"bad_signature"`
}

// webhookBody is the part of a GitHub payload that carries the event: the repository id and the
// object (named like the event) holding the head SHA.
func webhookBody(r webhookRequest) ([]byte, error) {
	switch r.Event {
	case "check_run", "check_suite", "workflow_run":
	default:
		return nil, fmt.Errorf("event %q is not one of check_run, check_suite, workflow_run", r.Event)
	}
	return json.Marshal(map[string]any{
		"action":     "completed",
		"repository": map[string]any{"id": r.RepositoryID},
		r.Event:      map[string]any{"head_sha": r.HeadSHA},
	})
}

func webhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// sendWebhook delivers the webhook and reports the status the receiver answered.
func (s *sim) sendWebhook(w http.ResponseWriter, r *http.Request) {
	var req webhookRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	status, err := deliverWebhook(r, req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"status": status})
}

func deliverWebhook(parent *http.Request, req webhookRequest) (int, error) {
	body, err := webhookBody(req)
	if err != nil {
		return 0, err
	}
	signedWith := req.Secret
	if req.BadSignature {
		signedWith = "not-" + req.Secret
	}
	out, err := http.NewRequestWithContext(parent.Context(), http.MethodPost, req.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	out.Header.Set("Content-Type", "application/json")
	out.Header.Set("User-Agent", "GitHub-Hookshot/ghsim")
	out.Header.Set("X-GitHub-Event", req.Event)
	out.Header.Set("X-GitHub-Delivery", req.Delivery)
	out.Header.Set("X-Hub-Signature-256", webhookSignature(signedWith, body))

	roots := x509.NewCertPool()
	if req.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(req.CAPEM)) {
		return 0, errors.New("ca_pem holds no certificate")
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(out)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}
