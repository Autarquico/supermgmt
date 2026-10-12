package config

import (
	"strings"
	"testing"
)

func githubDoc(fields string) string {
	return serverDoc + "providers:\n  - type: github\n    name: gh\n    credential_ref: secret://providers/gh/token\n" + fields
}

func TestGitHubSpecExampleLoads(t *testing.T) {
	res := mustLoad(t, serverDoc+asProviderList(readTestdata(t, "spec-8.3-github.yaml")))
	gh := res.Config.Providers[0].GitHub
	if gh == nil {
		t.Fatalf("providers[0] = %+v, want the github branch", res.Config.Providers[0])
	}
	if gh.WebhookSecretRef != "secret://providers/github/webhook-secret" {
		t.Errorf("webhook_secret_ref = %q", gh.WebhookSecretRef)
	}
	p := res.Config.Providers[0]
	if p.Type() != ProviderGitHub || p.Name() != "github" || p.CredentialRef() != "secret://providers/github/token" {
		t.Errorf("Type, Name, CredentialRef = %q, %q, %q", p.Type(), p.Name(), p.CredentialRef())
	}
}

func TestGitHubAPIURLDefaultsToGitHubCom(t *testing.T) {
	gh := mustLoad(t, githubDoc("")).Config.Providers[0].GitHub
	if gh.APIURL != DefaultGitHubAPIURL {
		t.Errorf("api_url = %q, want %q when absent", gh.APIURL, DefaultGitHubAPIURL)
	}
}

func TestGitHubProviderAcceptsEnterpriseServer(t *testing.T) {
	for _, doc := range []string{
		githubDoc("    api_url: https://ghe.example.com/api/v3\n    ca_file: /etc/supermgmt/ghe-ca.pem\n"),
		githubDoc("    api_url: https://10.0.0.5:8443/api/v3\n"),
		strings.Replace(githubDoc(""), serverDoc, localDoc, 1),
	} {
		if _, err := load(t, doc); err != nil {
			t.Errorf("want valid, got %v\n%s", err, doc)
		}
	}
}

func TestGitHubProviderRejections(t *testing.T) {
	tests := []struct {
		name   string
		fields string
		path   string
	}{
		{"http api_url", "    api_url: http://api.github.com\n", "providers[0].api_url"},
		{"empty api_url", "    api_url: \"\"\n", "providers[0].api_url"},
		{"api_url with userinfo", "    api_url: https://user@api.github.com\n", "providers[0].api_url"},
		{"api_url with query", "    api_url: https://api.github.com?x=1\n", "providers[0].api_url"},
		{"api_url with empty query", "    api_url: https://api.github.com?\n", "providers[0].api_url"},
		{"api_url with fragment", "    api_url: https://api.github.com#x\n", "providers[0].api_url"},
		{"api_url with trailing slash", "    api_url: https://ghe.example.com/api/v3/\n", "providers[0].api_url"},
		{"api_url with dot segments", "    api_url: https://ghe.example.com/api/../v3\n", "providers[0].api_url"},
		{"api_url with encoded path", "    api_url: https://ghe.example.com/api%2Fv3\n", "providers[0].api_url"},
		{"token not a secret ref", "    credential_ref: file:///etc/gh-token\n", "providers[0].credential_ref"},
		{"webhook secret not a secret ref", "    webhook_secret_ref: file:///etc/gh-hook\n", "providers[0].webhook_secret_ref"},
		{"relative ca_file", "    ca_file: ghe-ca.pem\n", "providers[0].ca_file"},
		{"unknown field", "    verify_tls: false\n", "providers[0].verify_tls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := githubDoc(tt.fields)
			if strings.Contains(tt.fields, "credential_ref") {
				doc = strings.Replace(doc, "    credential_ref: secret://providers/gh/token\n", "", 1)
			}
			_, err := load(t, doc)
			if err == nil || !strings.Contains(err.Error(), tt.path) {
				t.Fatalf("got %v, want an error at %s", err, tt.path)
			}
		})
	}
}

func TestGitHubProviderRequiresACredential(t *testing.T) {
	doc := serverDoc + "providers:\n  - {type: github, name: gh}\n"
	if _, err := load(t, doc); err == nil || !strings.Contains(err.Error(), "providers[0].credential_ref") {
		t.Fatalf("got %v, want credential_ref required", err)
	}
}

func TestGitHubProviderNamesShareTheProviderNamespace(t *testing.T) {
	doc := githubDoc("") + "  - {type: proxmox, name: gh, endpoint: \"https://pve:8006\", credential_ref: secret://providers/pve}\n"
	if _, err := load(t, doc); err == nil || !strings.Contains(err.Error(), `duplicate provider "gh"`) {
		t.Fatalf("got %v, want a duplicate-name error", err)
	}
}
