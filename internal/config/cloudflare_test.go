package config

import (
	"strings"
	"testing"
)

const (
	cfAccount = "0123456789abcdef0123456789abcdef"
	cfBlock   = "cloudflare:\n  account_id: " + cfAccount + "\n  zone: example.com\n  owner_emails: [alex@example.com]\n"
)

func TestCloudflareAbsentMeansTheFeatureIsOff(t *testing.T) {
	if res := mustLoad(t, localDoc); res.Config.Cloudflare != nil {
		t.Errorf("Cloudflare = %+v, want nil", res.Config.Cloudflare)
	}
}

func TestCloudflareBlockGetsItsDefaults(t *testing.T) {
	cf := mustLoad(t, localDoc+cfBlock).Config.Cloudflare
	if cf == nil {
		t.Fatal("Cloudflare = nil")
	}
	if cf.APITokenRef != "secret://cloudflare/api-token" || cf.AccessTokenRef != "secret://cloudflare/access-service-token" {
		t.Errorf("refs = %q, %q", cf.APITokenRef, cf.AccessTokenRef)
	}
	if cf.AccountID != cfAccount || cf.Zone != "example.com" || len(cf.OwnerEmails) != 1 || len(cf.AccessIdentityProviders) != 0 {
		t.Errorf("cloudflare = %+v", cf)
	}
}

func TestCloudflareRejectsUnknownKeys(t *testing.T) {
	_, err := load(t, localDoc+cfBlock+"  api_token: oops\n")
	if err == nil || !strings.Contains(err.Error(), "cloudflare.api_token") {
		t.Fatalf("err = %v, want unknown key cloudflare.api_token", err)
	}
}

func TestCloudflareValidationReportsEveryProblemByPath(t *testing.T) {
	doc := localDoc + `cloudflare:
  account_id: nothex
  zone: "Bad;zone"
  api_token_ref: file:///etc/token
  access_token_ref: plain-looking-secret
  owner_emails: ["*@example.com", "alex@example.com", "Alex <alex@example.com>", "no-at-sign", "a b@example.com"]
  access_identity_providers: ["abc-123", "bad id", ""]
`
	_, err := load(t, doc)
	if err == nil {
		t.Fatal("Load accepted the block")
	}
	got := problemPaths(t, err)
	for _, want := range []string{
		"cloudflare.account_id", "cloudflare.zone", "cloudflare.api_token_ref", "cloudflare.access_token_ref",
		"cloudflare.owner_emails[0]", "cloudflare.owner_emails[2]", "cloudflare.owner_emails[3]", "cloudflare.owner_emails[4]",
		"cloudflare.access_identity_providers[1]", "cloudflare.access_identity_providers[2]",
	} {
		if !contains(got, want) {
			t.Errorf("missing problem at %s; got %v", want, got)
		}
	}
	for _, unwanted := range []string{"cloudflare.owner_emails[1]", "cloudflare.access_identity_providers[0]"} {
		if contains(got, unwanted) {
			t.Errorf("unexpected problem at %s", unwanted)
		}
	}
	if strings.Contains(err.Error(), "plain-looking-secret") {
		t.Error("a bare reference value must not be echoed")
	}
}

func TestCloudflareOwnerEmailsAreRequired(t *testing.T) {
	for name, block := range map[string]string{
		"missing": "cloudflare:\n  account_id: " + cfAccount + "\n  zone: example.com\n",
		"empty":   "cloudflare:\n  account_id: " + cfAccount + "\n  zone: example.com\n  owner_emails: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, localDoc+block)
			if err == nil || !strings.Contains(err.Error(), "cloudflare.owner_emails") {
				t.Fatalf("err = %v, want owner_emails required", err)
			}
		})
	}
}

func TestCloudflareRefsMustBeSecretReferences(t *testing.T) {
	cfg := resolved(t, localDoc+cfBlock)
	cfg.Cloudflare.APITokenRef = "ssh-agent://default"
	cfg.Cloudflare.AccessTokenRef = "secret://"
	got := problemPaths(t, cfg.Validate())
	if !contains(got, "cloudflare.api_token_ref") || !contains(got, "cloudflare.access_token_ref") {
		t.Errorf("paths = %v", got)
	}
}
