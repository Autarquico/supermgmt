package config

import (
	"errors"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func decodeConfig(doc string) (Config, error) {
	cfg := Defaults()
	err := DecodeStrict(strings.NewReader(doc), &cfg)
	return cfg, err
}

func TestDecodeStrictRejects(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want []string // every fragment must appear in the error
	}{
		{"unknown field at depth 1", "version: 1\nbogus: 1\n", []string{"bogus", "unknown field"}},
		{"unknown field at depth 3", "server:\n  tls:\n    modee: proxy\n", []string{"server.tls.modee", "unknown field"}},
		{"unknown field in list item", "environments:\n  - name: a\n    risk_levl: staging\n", []string{"environments[0].risk_levl"}},
		{
			"unknown field in ssh provider branch",
			"providers:\n  - type: ssh\n    name: n\n    endpoint:\n      host: h\n      prot: 22\n",
			[]string{"providers[0].endpoint.prot", "unknown field"},
		},
		{
			"unknown field in proxmox provider branch",
			"providers:\n  - type: proxmox\n    name: n\n    tags: [a]\n",
			[]string{"providers[0].tags"},
		},
		{
			"field of the other provider branch", "providers:\n  - type: proxmox\n    name: n\n    endpoint: https://x\n    environment: prod\n",
			[]string{"providers[0].environment"},
		},
		{"unsupported provider type", "providers:\n  - type: cloudflare\n    name: n\n", []string{"providers[0].type", "cloudflare"}},
		{"missing provider type", "providers:\n  - name: n\n", []string{"providers[0].type"}},
		{"duplicate key", "version: 1\nserver:\n  listen: a\n  listen: b\n", []string{"server.listen", "duplicate key", "line 4"}},
		{"second document", "version: 1\n---\nversion: 1\n", []string{"exactly one YAML document"}},
		{"empty file", "", []string{"empty"}},
		{"alias", "ui:\n  theme: &t dark\nserver:\n  listen: *t\n", []string{"aliases are not supported"}},
		{"anchor", "ui: &u\n  theme: dark\n", []string{"anchors are not supported"}},
		{"duration as bare number", "server:\n  request_timeout: 30\n", []string{"server.request_timeout", "duration"}},
		{"malformed yaml", "version: [1\n", []string{"malformed YAML"}},
		{"type mismatch", "version: one\n", []string{"invalid configuration file"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeConfig(tt.doc)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			for _, frag := range tt.want {
				if !strings.Contains(err.Error(), frag) {
					t.Errorf("error %q lacks %q", err, frag)
				}
			}
			if got := smerr.CodeOf(err); got != smerr.CodeInvalidArgument {
				t.Errorf("code = %s, want INVALID_ARGUMENT", got)
			}
		})
	}
}

func TestDecodeStrictRejectsMergeKey(t *testing.T) {
	_, err := decodeConfig("ui:\n  <<: {theme: dark}\n")
	if err == nil || !strings.Contains(err.Error(), "merge keys are not supported") {
		t.Fatalf("got %v, want merge key rejection", err)
	}
}

func TestDecodeStrictReportsEveryUnknownField(t *testing.T) {
	_, err := decodeConfig("aaa: 1\nui:\n  bbb: 2\n")
	var problems Problems
	if !errors.As(err, &problems) || len(problems) != 2 {
		t.Fatalf("want 2 problems, got %v", err)
	}
}

func TestDecodeStrictAcceptsKnownDocument(t *testing.T) {
	cfg, err := decodeConfig("version: 1\nserver:\n  request_timeout: 45s\n  trusted_proxies: [\"10.0.0.0/8\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.RequestTimeout.String(); got != "45s" {
		t.Errorf("request_timeout = %s, want 45s", got)
	}
	if got := cfg.Server.TrustedProxies; len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Errorf("trusted_proxies = %v, a list in the file must replace the default", got)
	}
	if cfg.Refresh.FocusedInterval.String() != "5s" {
		t.Errorf("absent keys must keep their defaults, got focused_interval %s", cfg.Refresh.FocusedInterval)
	}
}

func TestDecodeStrictProviderBranchesKeepTheirDefaults(t *testing.T) {
	cfg, err := decodeConfig("providers:\n  - {type: proxmox, name: p, endpoint: 'https://pve:8006', credential_ref: 'secret://p'}\n  - {type: ssh, name: s, endpoint: {host: h, user: u}, credential_ref: 'secret://s'}\n")
	if err != nil {
		t.Fatal(err)
	}
	px, ssh := cfg.Providers[0].Proxmox, cfg.Providers[1].SSH
	if px == nil || !px.VerifyTLS || px.SyncInterval.String() != "30s" {
		t.Errorf("proxmox defaults not applied: %+v", px)
	}
	if ssh == nil || ssh.Endpoint.Port != 22 {
		t.Errorf("ssh default port not applied: %+v", ssh)
	}
	if cfg.Providers[0].Type() != "proxmox" || cfg.Providers[1].Type() != "ssh" {
		t.Errorf("types = %q, %q", cfg.Providers[0].Type(), cfg.Providers[1].Type())
	}
}

func TestDecodeStrictRequiresPointerTarget(t *testing.T) {
	if err := DecodeStrict(strings.NewReader("version: 1\n"), Config{}); err == nil {
		t.Fatal("want error for non-pointer target")
	}
}
