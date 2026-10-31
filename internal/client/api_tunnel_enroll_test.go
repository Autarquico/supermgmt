package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestStartTunnelEnrollmentIsKeyedAndReturnsTheEnrollment(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 201, wire.Direct[wire.TunnelEnrollment]{Applied: &wire.TunnelEnrollment{Name: "vps1", Phase: "started"}})
	})

	res, err := d.client(client.Options{}).StartTunnelEnrollment(context.Background(),
		wire.StartTunnelEnrollmentRequest{Name: "vps1", ExpiresIn: "2h"})

	got := d.Requests()[0]
	if err != nil || res.Applied == nil || res.Applied.Name != "vps1" {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if got.Method != "POST" || got.Path != "/api/v1/nodes/ssh/tunnel-enrollments" || got.Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Errorf("request = %s %s key=%q", got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
	}
	var body wire.StartTunnelEnrollmentRequest
	if err := json.Unmarshal(got.Body, &body); err != nil || body.Name != "vps1" || body.ExpiresIn != "2h" {
		t.Errorf("body = %s", got.Body)
	}
}

func TestTunnelEnrollmentReadsAddressTheName(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nodes/ssh/tunnel-enrollments" {
			respond(w, 200, wire.Page[wire.TunnelEnrollment]{Items: []wire.TunnelEnrollment{{Name: "vps1"}}})
			return
		}
		respond(w, 200, wire.TunnelEnrollment{Name: "vps1", Phase: "scanned"})
	})
	api := d.client(client.Options{})

	page, err := api.ListTunnelEnrollments(context.Background())
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list = %+v, %v", page, err)
	}
	one, err := api.GetTunnelEnrollment(context.Background(), "vps1")
	if err != nil || one.Phase != "scanned" {
		t.Fatalf("get = %+v, %v", one, err)
	}
	if got := d.Requests()[1]; got.Method != "GET" || got.Path != "/api/v1/nodes/ssh/tunnel-enrollments/vps1" {
		t.Errorf("request = %s %s", got.Method, got.Path)
	}
}

func TestTunnelEnrollmentTokenIsAnUnkeyedRead(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, wire.TunnelEnrollmentToken{Token: "connector"})
	})

	token, err := d.client(client.Options{}).TunnelEnrollmentToken(context.Background(), "vps1")

	got := d.Requests()[0]
	if err != nil || token.Token != "connector" {
		t.Fatalf("token = %+v, %v", token, err)
	}
	if got.Method != "GET" || got.Path != "/api/v1/nodes/ssh/tunnel-enrollments/vps1/token" || got.Header.Get(wire.HeaderIdempotencyKey) != "" {
		t.Errorf("request = %s %s key=%q", got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
	}
}

func TestConfirmRefuseAndCancelAreKeyedPostsOnTheName(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nodes/ssh/tunnel-enrollments/vps1/refuse" {
			respondError(w, 409, smerr.CodeSSHHostKeyMismatch, "", "the host key was not accepted")
			return
		}
		respond(w, 200, wire.TunnelEnrollment{Name: "vps1", Phase: "confirmed"})
	})
	api := d.client(client.Options{})

	if got, err := api.ConfirmTunnelEnrollment(context.Background(), "vps1", "e1", "ssh-ed25519 AAAA"); err != nil || got.Phase != "confirmed" {
		t.Fatalf("confirm = %+v, %v", got, err)
	}
	if err := api.RefuseTunnelEnrollment(context.Background(), "vps1", "e1", "ssh-ed25519 AAAA"); smerr.CodeOf(err) != smerr.CodeSSHHostKeyMismatch {
		t.Fatalf("refuse = %v", err)
	}
	if _, err := api.CancelTunnelEnrollment(context.Background(), "vps1"); err != nil {
		t.Fatalf("cancel = %v", err)
	}
	for i, suffix := range []string{"confirm", "refuse", "cancel"} {
		got := d.Requests()[i]
		if got.Method != "POST" || got.Path != "/api/v1/nodes/ssh/tunnel-enrollments/vps1/"+suffix || got.Header.Get(wire.HeaderIdempotencyKey) == "" {
			t.Errorf("%s request = %s %s key=%q", suffix, got.Method, got.Path, got.Header.Get(wire.HeaderIdempotencyKey))
		}
	}
	var body wire.ConfirmTunnelEnrollmentRequest
	if err := json.Unmarshal(d.Requests()[0].Body, &body); err != nil || body.HostPublicKey != "ssh-ed25519 AAAA" || body.EnrollmentID != "e1" {
		t.Errorf("confirm body = %s", d.Requests()[0].Body)
	}
}
