package client_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
)

const mcpSocketToken = "smm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEf"

func TestSocketRequestsCarryTheBearerOnlyWhenATokenIsSet(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, wire.Me{}) })

	if _, err := d.client(client.Options{}).Me(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.client(client.Options{Token: audit.Secret(mcpSocketToken)}).Me(context.Background()); err != nil {
		t.Fatal(err)
	}

	reqs := d.Requests()
	if got := reqs[0].Header.Get(wire.HeaderAuthorization); got != "" {
		t.Errorf("tokenless client sent Authorization %q", got)
	}
	if got := reqs[1].Header.Get(wire.HeaderAuthorization); got != "Bearer "+mcpSocketToken {
		t.Errorf("Authorization = %q, want the bearer", got)
	}
}

func TestTheSocketTokenNeverAppearsInAnErrorOrInFormattedOptions(t *testing.T) {
	d := startFakeDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		respondError(w, 401, "UNAUTHENTICATED", "", "token rejected")
	})
	opts := client.Options{Token: audit.Secret(mcpSocketToken)}

	_, err := d.client(opts).Me(context.Background())

	if err == nil || strings.Contains(err.Error(), mcpSocketToken) {
		t.Errorf("error = %v", err)
	}
	if shown := fmt.Sprintf("%v %+v %#v", opts.Token, opts.Token, opts.Token); strings.Contains(shown, mcpSocketToken) {
		t.Errorf("Options formats the token: %s", shown)
	}
}

func TestTransportAndBaseURLRouteRequestsThroughTheSuppliedRoundTripper(t *testing.T) {
	var seen *http.Request
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return newJSONResponse(200, wire.Me{}), nil
	})
	c := client.New(client.Options{Socket: "/nonexistent/sm.sock", Transport: transport, BaseURL: "http://inproc.invalid"})

	if _, err := c.Me(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.URL.Host != "inproc.invalid" || seen.URL.Path != "/api/v1/me" {
		t.Fatalf("request = %v", seen)
	}
}

func TestTransportWithoutBaseURLKeepsTheDefaultHost(t *testing.T) {
	var host string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		host = r.URL.Host
		return newJSONResponse(200, wire.Me{}), nil
	})

	if _, err := client.New(client.Options{Transport: transport}).Me(context.Background()); err != nil {
		t.Fatal(err)
	}
	if host != "sm" {
		t.Errorf("host = %q", host)
	}
}
