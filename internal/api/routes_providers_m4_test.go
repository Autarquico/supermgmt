package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
)

const providerGitHubBody = `{"type":"github","name":"gh","credential_ref":"secret://providers/gh/token"}`

func storedProviderCount(t *testing.T, f *m4Fixture) int {
	t.Helper()
	providers, err := database.ListProviders(context.Background(), f.db.Reader())
	must(t, err)
	return len(providers)
}

func TestPostProvidersAcceptsAGitHubProvider(t *testing.T) {
	f := newM4Fixture(t)
	r := f.do(http.MethodPost, wire.PathProviders, m4AdminToken, providerGitHubBody, wire.HeaderIdempotencyKey, "gh-1")
	if r.Status != http.StatusCreated && r.Status != http.StatusAccepted {
		t.Fatalf("status %d body %s, want 201 (applied) or 202 (parked for approval)", r.Status, r.Body)
	}
	if r.Status == http.StatusCreated && storedProviderCount(t, f) != 1 {
		t.Errorf("applied but %d providers stored, want 1", storedProviderCount(t, f))
	}
}

func TestPostProvidersRefusesBadGitHubAndUnknownTypes(t *testing.T) {
	f := newM4Fixture(t)
	cases := map[string]string{
		"literal token":         `{"type":"github","name":"gh","credential_ref":"ghp_abc"}`,
		"http api url":          `{"type":"github","name":"gh","credential_ref":"secret://p/t","api_url":"http://api.github.com"}`,
		"unknown field":         `{"type":"github","name":"gh","credential_ref":"secret://p/t","extra":1}`,
		"github field on local": `{"type":"local","api_url":"https://api.github.com"}`,
		"unknown type":          `{"type":"proxmox","name":"pve"}`,
		"missing type":          `{}`,
		"malformed":             `{"type":`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := f.do(http.MethodPost, wire.PathProviders, m4AdminToken, body, wire.HeaderIdempotencyKey, "bad-"+strings.ReplaceAll(name, " ", "-"))
			if r.Status != http.StatusBadRequest {
				t.Errorf("status %d body %s, want 400", r.Status, r.Body)
			}
			if n := storedProviderCount(t, f); n != 0 {
				t.Errorf("a refused request stored %d providers", n)
			}
		})
	}
}

func TestPostProvidersStillRegistersTheLocalProvider(t *testing.T) {
	f := newM4Fixture(t)
	r := f.do(http.MethodPost, wire.PathProviders, m4AdminToken, `{"type":"local"}`, wire.HeaderIdempotencyKey, "local-1")
	if r.Status != http.StatusCreated && r.Status != http.StatusAccepted {
		t.Errorf("status %d body %s", r.Status, r.Body)
	}
}
