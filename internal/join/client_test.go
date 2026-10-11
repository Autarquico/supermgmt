package join

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func serverCA(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func newEnrollServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL, serverCA(srv))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return srv, client
}

func TestClientPostsTheTokenInTheBodyAndDecodesTheEnvelope(t *testing.T) {
	var seen *http.Request
	var body wire.EnrollRequest
	_, client := newEnrollServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(wire.Envelope[wire.Enrolled]{Data: wire.Enrolled{NodeID: "node-1", SSHUser: "supermgmt"}})
	})

	got, err := client.Enroll(context.Background(), wire.EnrollRequest{Token: "smj_secret", Hostname: "edge-1"})

	if err != nil || got.NodeID != "node-1" {
		t.Fatalf("Enroll = %+v, %v", got, err)
	}
	if seen.Method != http.MethodPost || seen.URL.Path != wire.PathEnroll || seen.URL.RawQuery != "" || body.Token != "smj_secret" {
		t.Errorf("request = %s %s, body %+v", seen.Method, seen.URL, body)
	}
	if seen.Header.Get("Authorization") != "" || seen.Header.Get(wire.HeaderIdempotencyKey) != "" {
		t.Error("an enrollment must carry neither Authorization nor Idempotency-Key")
	}
}

func TestClientMapsErrorEnvelopesToTypedErrors(t *testing.T) {
	_, client := newEnrollServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(wire.ErrorEnvelope{Error: wire.Error{Code: smerr.CodeConflict, Message: "join token is exhausted"}})
	})

	_, err := client.Enroll(context.Background(), wire.EnrollRequest{Token: "smj_secret"})

	wantCode(t, err, smerr.CodeConflict)
	if strings.Contains(err.Error(), "smj_secret") {
		t.Error("the error echoes the token")
	}
}

func TestClientRefusesRedirectsSoTheTokenGoesNowhereElse(t *testing.T) {
	var elsewhere bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere = true }))
	t.Cleanup(other.Close)
	_, client := newEnrollServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})

	_, err := client.Enroll(context.Background(), wire.EnrollRequest{Token: "smj_secret"})

	if err == nil || elsewhere {
		t.Fatalf("err = %v, followed = %v; want the redirect refused", err, elsewhere)
	}
}

func TestClientRejectsAnUnreadableAnswer(t *testing.T) {
	_, client := newEnrollServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) })

	if _, err := client.Enroll(context.Background(), wire.EnrollRequest{Token: "smj_secret"}); err == nil {
		t.Fatal("want an error")
	}
}

func TestClientDoesNotTrustAnUnknownCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL, nil) // system roots only
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := client.Enroll(context.Background(), wire.EnrollRequest{Token: "smj_secret"}); err == nil {
		t.Fatal("want the self-signed server refused")
	}
}

func TestNewClientRequiresHTTPSAndAValidCA(t *testing.T) {
	for name, server := range map[string]string{
		"plain http":  "http://mgmt.example.com",
		"no scheme":   "mgmt.example.com",
		"credentials": "https://user:pass@mgmt.example.com",
		"empty":       "",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewClient(server, nil)

			wantCode(t, err, smerr.CodeInvalidArgument)
		})
	}
	_, err := NewClient("https://mgmt.example.com", []byte("not pem"))
	wantCode(t, err, smerr.CodeInvalidArgument)
}
