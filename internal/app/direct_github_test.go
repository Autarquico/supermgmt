package app

import (
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestGitHubProvider_SecretRefsStayInTheProvidersOwnNamespace(t *testing.T) {
	valid := githubProviderParams{
		Name: "gh", APIURL: defaultGitHubAPIURL,
		CredentialRef: "secret://providers/gh/token", WebhookSecretRef: "secret://providers/gh/webhook",
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("a provider using its own secrets was refused: %v", err)
	}
	refused := map[string]func(*githubProviderParams){
		"another provider's token":     func(p *githubProviderParams) { p.CredentialRef = "secret://providers/pve/token" },
		"own namespace, not the token": func(p *githubProviderParams) { p.CredentialRef = "secret://providers/gh/other" },
		"a prefix of another name":     func(p *githubProviderParams) { p.CredentialRef = "secret://providers/gh2/token" },
		"another provider's webhook":   func(p *githubProviderParams) { p.WebhookSecretRef = "secret://providers/pve/webhook" },
		"webhook in a sibling prefix":  func(p *githubProviderParams) { p.WebhookSecretRef = "secret://providers/gh2/webhook" },
		"webhook escaping with dots":   func(p *githubProviderParams) { p.WebhookSecretRef = "secret://providers/gh/../pve/token" },
	}
	for name, mutate := range refused {
		t.Run(name, func(t *testing.T) {
			p := valid
			mutate(&p)
			wantAppsCode(t, p.validate(), smerr.CodeInvalidArgument)
		})
	}
}
