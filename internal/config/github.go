package config

import (
	"net/url"
	"path"
	"strings"
)

// ProviderGitHub is the type of a GitHub connector (spec §8.3, §18; ADR-0028).
const ProviderGitHub = "github"

// DefaultGitHubAPIURL is the API of github.com; GitHub Enterprise Server sets
// its own, e.g. https://ghe.example.com/api/v3.
const DefaultGitHubAPIURL = "https://api.github.com"

// GitHubProvider is one GitHub connector. CredentialRef holds a fine-grained,
// read-only token; WebhookSecretRef the webhook HMAC secret (server mode). The
// exact origin of APIURL is the only host the connector talks to and the only
// redirect target it follows.
type GitHubProvider struct {
	Type             string `yaml:"type"`
	Name             string `yaml:"name"`
	APIURL           string `yaml:"api_url"`
	CredentialRef    string `yaml:"credential_ref"`
	WebhookSecretRef string `yaml:"webhook_secret_ref"`
	CAFile           string `yaml:"ca_file"`
}

// githubProvider checks a GitHub provider: an https API URL without userinfo,
// query, fragment or trailing slash; secret:// references for the token and
// the webhook secret; an absolute ca_file.
func (v *validator) githubProvider(p GitHubProvider, at func(string) string) {
	if !githubAPIURL(p.APIURL) {
		v.add(at("api_url"), "must be an https URL with no query, fragment or trailing slash, e.g. %s, got %q",
			DefaultGitHubAPIURL, p.APIURL)
	}
	namespace := "secret://providers/" + p.Name + "/"
	if p.CredentialRef == "" {
		v.add(at("credential_ref"), "required")
	} else {
		v.secretRefOnly(at("credential_ref"), p.CredentialRef)
		if strings.HasPrefix(p.CredentialRef, "secret://") && p.CredentialRef != namespace+"token" {
			v.add(at("credential_ref"), "must be %stoken", namespace)
		}
	}
	if p.WebhookSecretRef != "" {
		v.secretRefOnly(at("webhook_secret_ref"), p.WebhookSecretRef)
		if strings.HasPrefix(p.WebhookSecretRef, "secret://") && !strings.HasPrefix(p.WebhookSecretRef, namespace) {
			v.add(at("webhook_secret_ref"), "must sit under %s", namespace)
		}
	}
	if p.CAFile != "" && !path.IsAbs(p.CAFile) {
		v.add(at("ca_file"), "must be an absolute path, got %q", p.CAFile)
	}
}

// githubAPIURL accepts an https URL whose path is empty or a clean absolute
// path (GitHub Enterprise Server's /api/v3).
func githubAPIURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !httpsURL(raw) || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.HasSuffix(raw, "/") {
		return false
	}
	return u.Path == "" || (u.RawPath == "" && path.Clean(u.Path) == u.Path)
}
