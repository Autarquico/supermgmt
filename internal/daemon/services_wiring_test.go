package daemon

import (
	"context"
	"net/http"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// serverBuilder is the builder of a server-mode instance after its core services:
// everything the wiring is made of exists, nothing is listening.
func serverBuilder(t *testing.T, extra string) *builder {
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

func TestTheJobTypesOfRetiredWorkHaveNoHandlers(t *testing.T) {
	b := serverBuilder(t, "")

	table, err := b.handlers()
	if err != nil {
		t.Fatal(err)
	}

	for _, jobType := range []string{"deployment.create", "deployment.rollback"} {
		if table[jobType] != nil {
			t.Errorf("%s still has a handler", jobType)
		}
	}
	if table[app.JobControlPlaneApply] == nil {
		t.Errorf("no handler for %s", app.JobControlPlaneApply)
	}
}

func TestTheServicesOfTheAPICarryTheRoutesAndTheGovernance(t *testing.T) {
	b := serverBuilder(t, "")

	services, err := b.apiServices()
	if err != nil {
		t.Fatal(err)
	}

	if services.Routes == nil || services.Routes != b.routes {
		t.Errorf("routes %p, want %p", services.Routes, b.routes)
	}
	if services.Governance != b.governance {
		t.Error("the API and the builder hold different governance services")
	}
}

func TestBearersAreNativeTokensOnly(t *testing.T) {
	b := serverBuilder(t, "")

	if _, ok := b.bearerResolver().(auth.DBResolver); !ok {
		t.Errorf("the resolver is %T, want native tokens only", b.bearerResolver())
	}
}

func TestACredentialOfAnUnlinkedAutomationIdentityIsRevoked(t *testing.T) {
	b := serverBuilder(t, "")

	state, err := b.app.Credentials.Status(context.Background(), domain.CredentialContext{Kind: domain.CredentialGitHubOIDC, ID: "gone"})

	if err != nil || state != app.CredentialRevoked {
		t.Errorf("state = %q, err = %v, want revoked", state, err)
	}
}

func TestALocalDaemonServesTheNodeRoutes(t *testing.T) {
	i := newInstance(t, "")
	i.start()

	routes, err := i.client().ListAllNodeRoutes(context.Background(), false)

	if err != nil || len(routes.Items) != 0 {
		t.Errorf("routes %v, err %v", routes.Items, err)
	}
}

func TestAServerServesTheNodeRoutes(t *testing.T) {
	i := newServerInstance(t, "")
	r := i.start()
	token := r.bootstrap().APIToken.Value

	if status, body := r.call(http.MethodGet, wire.PathNodeRoutesAll, token, ""); status != http.StatusOK {
		t.Errorf("GET %s = %d %s", wire.PathNodeRoutesAll, status, body)
	}
	for _, path := range []string{"/api/v1/apps", "/api/v1/deployments", "/api/v1/github/webhook"} {
		if status, _ := r.call(http.MethodGet, path, token, ""); status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, status)
		}
	}
}
