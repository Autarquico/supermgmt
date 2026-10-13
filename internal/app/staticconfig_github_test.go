package app

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

func fileGitHub(apiURL string) config.Provider {
	return config.Provider{GitHub: &config.GitHubProvider{
		Type: "github", Name: "gh", APIURL: apiURL, CredentialRef: "secret://github/token",
		WebhookSecretRef: "secret://github/webhook", CAFile: "/etc/supermgmt/ghe-ca.pem",
	}}
}

func (f *fixture) githubStaticProvider() (domain.Provider, bool) {
	f.t.Helper()
	providers, err := database.ListProviders(context.Background(), f.db.Reader())
	mustf(f.t, err, "ListProviders")
	for _, p := range providers {
		if p.Name == "gh" {
			return p, true
		}
	}
	return domain.Provider{}, false
}

func TestReconcileStoresTheStaticGitHubProviderWithTheConventionOfTheClientFactory(t *testing.T) {
	f := newFixture(t)

	mustf(t, f.reconciler(t).Reconcile(context.Background(), nil, []config.Provider{fileGitHub("https://ghe.lan/api/v3")}), "Reconcile")

	p, ok := f.githubStaticProvider()
	if !ok {
		t.Fatal("provider not created")
	}
	if p.Type != "github" || p.Origin != domain.ProviderStatic || p.Endpoint != "https://ghe.lan/api/v3" || p.CredentialRef != "secret://github/token" {
		t.Errorf("provider = %+v", p)
	}
	if p.Config[providerConfigCAFile] != "/etc/supermgmt/ghe-ca.pem" || p.Config[providerConfigWebhookSecretRef] != "secret://github/webhook" {
		t.Errorf("config = %v", p.Config)
	}
	if added := f.events(eventProviderAdd); len(added) != 1 {
		t.Errorf("provider.add events = %d, want 1", len(added))
	}
}

func TestReconcileOmitsUnsetGitHubConfigKeys(t *testing.T) {
	f := newFixture(t)
	bare := fileGitHub("https://api.github.com")
	bare.GitHub.CAFile, bare.GitHub.WebhookSecretRef = "", ""

	mustf(t, f.reconciler(t).Reconcile(context.Background(), nil, []config.Provider{bare}), "Reconcile")

	if p, _ := f.githubStaticProvider(); len(p.Config) != 0 {
		t.Errorf("config = %v, want no keys", p.Config)
	}
}

func TestReconcileOfTheGitHubProviderIsIdempotentAndAuditsAChangeOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{fileGitHub("https://api.github.com")}), "first")
	first, _ := f.githubStaticProvider()

	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{fileGitHub("https://api.github.com")}), "repeat")
	repeated, _ := f.githubStaticProvider()
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{fileGitHub("https://ghe.lan/api/v3")}), "changed")
	changed, _ := f.githubStaticProvider()

	if repeated.SpecRevision != first.SpecRevision || len(f.events(eventProviderUpdate)) != 1 {
		t.Errorf("an unchanged file changed the provider: revision %d -> %d", first.SpecRevision, repeated.SpecRevision)
	}
	if changed.SpecRevision != first.SpecRevision+1 || changed.Endpoint != "https://ghe.lan/api/v3" {
		t.Errorf("after the change: %+v", changed)
	}
}

func TestReconcileStopsAGitHubProviderThatLeftTheFileAndRestoresItWhenItReturns(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{fileGitHub("https://api.github.com")}), "first")

	mustf(t, f.reconciler(t).Reconcile(ctx, nil, nil), "removed")
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, nil), "removed again")
	removed, _ := f.githubStaticProvider()
	removals := len(f.events(eventProviderRemove))
	mustf(t, f.reconciler(t).Reconcile(ctx, nil, []config.Provider{fileGitHub("https://api.github.com")}), "returned")
	returned, _ := f.githubStaticProvider()

	if removed.Status != ProviderStatusRemoved || removals != 1 {
		t.Errorf("after removal: %+v (%d provider.remove events); the row must stay and be audited once", removed, removals)
	}
	if returned.Status != "" {
		t.Errorf("after it returned: %+v", returned)
	}
}

func TestReconcileRefusesAGitHubProviderWhoseNameBelongsToAnotherProvider(t *testing.T) {
	f := newFixture(t)
	taken := fileGitHub("https://api.github.com")
	taken.GitHub.Name = f.provider.Name

	err := f.reconciler(t).Reconcile(context.Background(), nil, []config.Provider{taken})

	if err == nil || !strings.Contains(err.Error(), "not a static GitHub provider") {
		t.Errorf("err = %v", err)
	}
}
