package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// m4Builder is the builder of a server-mode instance after its core services:
// everything the M4 wiring is made of exists, nothing is listening.
func m4Builder(t *testing.T, extra string) *builder {
	t.Helper()
	i := newServerInstance(t, extra)
	prepared := prepare(t, i)
	t.Cleanup(func() { _ = prepared.Close() })
	o, err := Options{Config: i.cfg, ConfigFile: i.file}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	appCfg, _, err := appConfig(prepared.db, o)
	if err != nil {
		t.Fatal(err)
	}
	b := &builder{o: o, cfg: i.cfg, app: appCfg, db: prepared.db, kit: prepared.kit}
	if err := b.openGate(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.pool = ssh.NewPool(poolConfig(i.cfg), ssh.NewCredentials(prepared.kit.store), o.Clock)
	t.Cleanup(b.pool.Close)
	if err := b.coreServices(); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTheDeploymentJobTypesHaveHandlers(t *testing.T) {
	b := m4Builder(t, "")

	table, err := b.handlers()
	if err != nil {
		t.Fatal(err)
	}

	for _, jobType := range []string{"deployment.create", "deployment.rollback", app.JobControlPlaneApply} {
		if table[jobType] == nil {
			t.Errorf("no handler for %s", jobType)
		}
	}
}

func TestTheCIWatcherAndTheDeploymentEvidenceJoinTheBackgroundWork(t *testing.T) {
	b := m4Builder(t, "")
	table, err := b.handlers()
	if err != nil {
		t.Fatal(err)
	}

	work, err := b.background(table)
	if err != nil {
		t.Fatal(err)
	}

	if work.ci == nil || work.ci != b.ci {
		t.Errorf("the CI watcher is not part of the background work: %v", work.ci)
	}
}

func TestTheServicesOfTheAPICarryTheM4Services(t *testing.T) {
	b := m4Builder(t, "")

	services, err := b.apiServices()
	if err != nil {
		t.Fatal(err)
	}

	if services.Apps != b.apps || services.Repositories != b.repos || services.Deployments != b.finalizer ||
		services.Apps == nil || services.Repositories == nil || services.Deployments == nil {
		t.Errorf("apps %p, repositories %p, deployments %p", services.Apps, services.Repositories, services.Deployments)
	}
	if services.Governance != b.governance {
		t.Error("the deployments service and the API cancel through different governance services")
	}
}

func TestAnUnsignedWebhookReachesTheVerifierOfTheServer(t *testing.T) {
	b := m4Builder(t, "")
	services, err := b.apiServices()
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := b.bearerResolver()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Options{
		Services: services, IDs: b.o.IDs, Resolver: resolver, GitHubWebhook: b.githubWebhook(), DB: b.db, Clock: b.o.Clock, Log: b.o.Log,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, wire.PathGitHubWebhook, nil)
	req.Header.Set("X-GitHub-Delivery", "d-1")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (a 404 means the webhook is not served)", rec.Code)
	}
}

func TestGitHubActionsTokensAreAcceptedOnlyWithAnAudience(t *testing.T) {
	withAudience := m4Builder(t, "github:\n  oidc_audience: https://sm.example.com\n")
	without := m4Builder(t, "")

	on, err := withAudience.bearerResolver()
	if err != nil {
		t.Fatal(err)
	}
	off, err := without.bearerResolver()
	if err != nil {
		t.Fatal(err)
	}

	if bearer, ok := on.(auth.BearerResolver); !ok || bearer.GitHub == nil {
		t.Errorf("with an audience the resolver is %T, want one that also takes GitHub tokens", on)
	}
	if _, ok := off.(auth.DBResolver); !ok {
		t.Errorf("without an audience the resolver is %T, want native tokens only", off)
	}
}

func TestACredentialOfAnUnlinkedAutomationIdentityIsRevoked(t *testing.T) {
	b := m4Builder(t, "")

	state, err := b.app.Credentials.Status(context.Background(), domain.CredentialContext{Kind: domain.CredentialGitHubOIDC, ID: "gone"})

	if err != nil || state != app.CredentialRevoked {
		t.Errorf("state = %q, err = %v, want revoked", state, err)
	}
}

func TestTheHealthClientRefusesDestinationsOutsideTheAllowlist(t *testing.T) {
	b := m4Builder(t, "health:\n  allowed_private_cidrs: [\"10.0.0.0/8\"]\n")
	client, err := b.healthClient()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get("http://127.0.0.1:1/health") //nolint:noctx // refused before any I/O
	if resp != nil {
		_ = resp.Body.Close()
	}

	if err == nil {
		t.Fatal("a loopback destination was reachable")
	}
}

func TestAMalformedHealthAllowlistRefusesTheStart(t *testing.T) {
	b := m4Builder(t, "")
	b.cfg.Health.AllowedPrivateCIDRs = []string{"not-a-cidr"}

	if _, err := b.healthClient(); err == nil {
		t.Error("an allowlist that is not CIDRs was accepted")
	}
}

// The M4 routes answer in both modes: a route the daemon does not serve is a
// 404, and these must not be one.
func TestALocalDaemonServesTheM4Routes(t *testing.T) {
	i := newInstance(t, "")
	i.start()

	apps, err := i.client().ListApps(context.Background(), wire.PageQuery{})
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	deployments, err := i.client().ListDeployments(context.Background(), client.DeploymentQuery{})

	if len(apps.Items) != 0 || err != nil || len(deployments.Items) != 0 {
		t.Errorf("apps %v, deployments %v, err %v", apps.Items, deployments.Items, err)
	}
}

func TestAServerServesTheM4Routes(t *testing.T) {
	i := newServerInstance(t, "")
	r := i.start()
	token := r.bootstrap().APIToken.Value

	for _, path := range []string{wire.PathApps, wire.PathDeployments} {
		if status, body := r.call(http.MethodGet, path, token, ""); status != http.StatusOK {
			t.Errorf("GET %s = %d %s", path, status, body)
		}
	}
}
