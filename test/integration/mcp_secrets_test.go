package integration

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Secrets in remote text never reach a model (spec §24, §30; ADR-0031). The
// control plane runs with security.redact_command_output: false, so the API
// serves service logs raw, and the MCP tools must still scrub the supported
// set: SuperMgmt token formats, JWTs, `key=value`, `key: value` and JSON
// secret fields, Bearer and Basic credentials, PEM private keys, and every
// sensitive key of a metadata or event map. A secret under a harmless name is
// outside the guarantee and is not asserted (ADR-0031, docs/mcp.md).

const (
	secretsPassword = "hunter2hunter2"
	secretsAPIKey   = "sk-live-0123456789abcdef"
	secretsSMToken  = "smt_Zx9Qe7RtYu1Io3Pa5Sd7Fg9"
	secretsMCPToken = "smm_Zx9Qe7RtYu1Io3Pa5Sd7Fg9"
	secretsJWT      = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	secretsBearer   = "Zm9vYmFyYmF6cXV4MTIzNDU2"
	secretsPEMBody  = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
)

// secretsLeaks are the substrings of secrets that no tool output may contain.
var secretsLeaks = []string{
	secretsPassword, secretsAPIKey, secretsSMToken, secretsMCPToken, secretsBearer, secretsPEMBody,
	secretsJWT, strings.Split(secretsJWT, ".")[1], strings.Split(secretsJWT, ".")[2],
}

// secretsLogs holds one of every supported form among benign lines.
var secretsLogs = strings.Join([]string{
	"listening on :8080",
	"connecting with password=" + secretsPassword,
	`config {"api_key": "` + secretsAPIKey + `", "region": "eu"}`,
	"token: " + secretsSMToken,
	"mcp client sent " + secretsMCPToken,
	"session " + secretsJWT,
	"Authorization: Bearer " + secretsBearer,
	"-----BEGIN PRIVATE KEY-----",
	secretsPEMBody,
	"-----END PRIVATE KEY-----",
	"ready",
}, "\n") + "\n"

// secretsRuntime is the SSH boundary of the node: it prints secretsLogs.
type secretsRuntime struct{}

func (secretsRuntime) For(ssh.Target) transport.Executor { return secretsRuntime{} }

func (secretsRuntime) State(domain.ID) ssh.ConnState { return ssh.ConnState{} }

func (secretsRuntime) Invalidate(domain.ID, string) {}

func (secretsRuntime) Run(context.Context, templates.Command) (transport.Result, error) {
	return transport.Result{Stdout: []byte(secretsLogs)}, nil
}

// secretsFixture is the rig's inventory served by an API server that keeps
// command output raw, with secrets in a service's metadata and in an event.
type secretsFixture struct {
	rig    *mcpRig
	server *api.Server
}

func newSecretsFixture(t *testing.T) *secretsFixture {
	t.Helper()
	ctx := context.Background()
	clock, ids := domaintest.NewFakeClock(epoch), domain.UUIDv7Generator{}
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	mcpRigMust(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mcpRigMust(t, db.Migrate(ctx))
	rig := &mcpRig{t: t, db: db, clock: clock, ids: ids, fixtures: map[string]string{}, runtime: &mcpRigRuntime{}}
	rig.seedIdentities()
	rig.seedInventory()
	f := &secretsFixture{rig: rig}
	f.seedSecretsInRemoteData()
	f.server = f.serve(ctx)
	return f
}

func (f *secretsFixture) seedSecretsInRemoteData() {
	rig := f.rig
	metadata, err := json.Marshal(map[string]any{
		"env":    map[string]any{"DB_PASSWORD": secretsPassword, "api_key": secretsAPIKey},
		"labels": map[string]any{"note": "password=" + secretsPassword + " via " + secretsSMToken, "build": "42"},
	})
	mcpRigMust(rig.t, err)
	rig.inTx(func(ctx context.Context, tx *database.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE services SET metadata_json = ? WHERE id = ?`, string(metadata), rig.fixtures["service"]); err != nil {
			return err
		}
		_, err := database.EventsIn(tx).AppendEvent(ctx, domain.Event{
			EventID: rig.ids.NewID(), Timestamp: rig.clock.Now(), ActorType: domain.ActorSystem, ActorID: rig.admin.ID, Source: "api",
			Action: "service.observed", ResourceType: domain.ResourceService, ResourceID: domain.ID(rig.fixtures["service"]),
			Severity: domain.SeverityInfo, Result: domain.ResultSucceeded,
			Data: map[string]any{
				"detail":     "password=" + secretsPassword + " jwt " + secretsJWT,
				"api_key":    secretsAPIKey,
				"nested":     map[string]any{"authorization": "Bearer " + secretsBearer, "attempt": 3},
				"safe_field": "kept",
			},
		})
		return err
	})
}

// serve builds the real services the rig builds, except for the executor of
// a node, which prints secretsLogs, and the raw command output.
func (f *secretsFixture) serve(ctx context.Context) *api.Server {
	rig, t := f.rig, f.rig.t
	pol, err := policy.Parse(append(policy.DefaultYAML(), []byte(mcpRigGrant)...))
	mcpRigMust(t, err)
	cfg := app.Config{DB: rig.db, Clock: rig.clock, IDs: rig.ids, Policy: pol, Credentials: activeCredentials{}}
	reval, err := app.NewRevalidator(cfg)
	mcpRigMust(t, err)
	store, err := jobs.NewStore(jobs.Config{DB: rig.db, Clock: rig.clock, IDs: rig.ids, Revalidator: reval, LockPlanner: app.LockPlanner{}})
	mcpRigMust(t, err)
	repo := app.NewSecretsKeyRepo(rig.db, rig.clock)
	keys, err := secrets.OpenFileKeys(ctx, filepath.Join(t.TempDir(), "keys"), repo, rig.ids)
	mcpRigMust(t, err)
	secretStore := secrets.NewStore(keys, repo, rig.ids, rig.clock)
	_, err = app.EnsureInstanceIdentity(ctx, cfg, secretStore)
	mcpRigMust(t, err)

	var svc api.Services
	svc.Plans, err = app.NewPlans(cfg, store)
	mcpRigMust(t, err)
	svc.Approvals, err = app.NewApprovals(cfg, store)
	mcpRigMust(t, err)
	svc.Governance, err = app.NewGovernance(cfg, store)
	mcpRigMust(t, err)
	svc.Services, err = app.NewServices(cfg, store)
	mcpRigMust(t, err)
	svc.Queries, err = app.NewQueries(cfg, store, config.ModeLocal)
	mcpRigMust(t, err)
	svc.Inventory, err = app.NewInventory(cfg, app.InventoryOptions{
		Store: store, Connector: app.Connector{Remote: secretsRuntime{}}, Mode: config.ModeLocal, KeepLogsRaw: true,
	})
	mcpRigMust(t, err)
	svc.Sessions, err = app.NewSessions(cfg)
	mcpRigMust(t, err)
	svc.SSHKeys, err = api.NewSSHKeys(app.SSHIdentityOf(secretStore))
	mcpRigMust(t, err)
	svc.Proxmox, err = app.NewProxmoxSync(cfg, app.ProxmoxSyncOptions{Token: app.SecretToken(secretStore)})
	mcpRigMust(t, err)
	svc.Apps, err = app.NewApps(cfg, store, mcpRigGitHub{})
	mcpRigMust(t, err)
	svc.Repositories, err = app.NewRepositories(cfg, mcpRigGitHub{})
	mcpRigMust(t, err)
	deployments, err := app.NewDeployments(cfg, svc.Governance, app.CIPolling{})
	mcpRigMust(t, err)
	svc.Deployments, err = app.NewDeploymentFinalizer(deployments, app.FinalizerDeps{Clients: mcpRigGitHub{}, Jobs: store})
	mcpRigMust(t, err)
	svc.Auth, err = app.NewAuthService(cfg, app.AuthOptions{Tokens: auth.Minter{}})
	mcpRigMust(t, err)
	svc.Keys, err = app.NewKeyManager(cfg, store, secrets.NewKeyAdmin(keys, repo, rig.ids, backup.Archives{Dir: t.TempDir()}), secretStore, config.ModeLocal)
	mcpRigMust(t, err)
	svc.Backups, err = app.NewBackupService(cfg, svc.Plans, svc.Queries, store, app.BackupOptions{
		Directory: t.TempDir(), Retention: 3, KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"), SMVersion: "rig", Keys: keys,
	})
	mcpRigMust(t, err)
	svc.Hold, err = app.NewHold(cfg, store)
	mcpRigMust(t, err)
	svc.Enrollments, err = app.NewEnrollments(cfg, auth.Minter{}, app.SSHIdentityOf(secretStore))
	mcpRigMust(t, err)
	svc.MCPClients, err = app.NewMCPClients(cfg, store, app.MCPClientsOptions{Tokens: auth.Minter{}})
	mcpRigMust(t, err)

	server, err := api.New(api.Options{Services: svc, IDs: rig.ids, Identity: rig.admin.ID, DB: rig.db, Clock: rig.clock})
	mcpRigMust(t, err)
	return server
}

func (f *secretsFixture) api() *client.Client {
	return client.New(client.Options{Transport: f.server.InProcess(f.rig.mcp)})
}

func TestWithLogRedactionOffTheAPIServesLogsRawSoTheToolsAreTheOnlyScrub(t *testing.T) {
	f := newSecretsFixture(t)

	chunk, err := f.api().ServiceLogs(context.Background(), domain.ID(f.rig.fixtures["service"]), wire.LogQuery{})
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(chunk.Lines, "\n")
	for _, raw := range []string{secretsPassword, secretsSMToken, secretsMCPToken, secretsJWT} {
		if !strings.Contains(text, raw) {
			t.Errorf("the API scrubbed %q although security.redact_command_output is false: this suite would prove nothing", raw)
		}
	}
}

func TestTheSecretsAreReallyInTheMetadataAndEventsTheAPIServes(t *testing.T) {
	f := newSecretsFixture(t)
	ctx := context.Background()

	service, err := f.api().GetService(ctx, domain.ID(f.rig.fixtures["service"]))
	mcpRigMust(t, err)
	events, err := f.api().ListEvents(ctx, wire.EventQuery{ResourceType: domain.ResourceService, ResourceID: domain.ID(f.rig.fixtures["service"])})
	mcpRigMust(t, err)

	metadata, _ := json.Marshal(service.Metadata)
	data, _ := json.Marshal(events.Items)
	for name, served := range map[string]string{"metadata": string(metadata), "events": string(data)} {
		if !strings.Contains(served, secretsPassword) {
			t.Errorf("the %s the API serves lack the seeded secret: the leak test would prove nothing: %s", name, served)
		}
	}
}

func TestNoSupportedSecretInLogsMetadataOrEventsReachesToolOutput(t *testing.T) {
	f := newSecretsFixture(t)
	session := mcpSecSession(t, f.api(), false)
	calls := []struct {
		tool      string
		arguments map[string]any
	}{
		{"infra_get_service_logs", map[string]any{"ref": "web@dev-1"}},
		{"infra_get_service", map[string]any{"ref": "web@dev-1"}},
		{"infra_list_services", map[string]any{"node": "dev-1"}},
		{"infra_list_events", map[string]any{"resource_type": "service", "resource_id": f.rig.fixtures["service"]}},
	}
	for _, call := range calls {
		t.Run(call.tool, func(t *testing.T) {
			result, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: call.tool, Arguments: call.arguments})
			mcpRigMust(t, err)
			if result.IsError {
				t.Fatalf("%s failed: %+v", call.tool, result.Content)
			}
			everything, err := json.Marshal(result)
			mcpRigMust(t, err)
			for _, secret := range secretsLeaks {
				if strings.Contains(string(everything), secret) {
					t.Errorf("%s output contains %q", call.tool, secret)
				}
			}
			if !strings.Contains(string(everything), "untrusted_remote_output") {
				t.Errorf("%s output does not flag its remote content as untrusted", call.tool)
			}
		})
	}
}

func TestScrubbingKeepsTheBenignLinesAndLeavesAMarkerWhereASecretWas(t *testing.T) {
	f := newSecretsFixture(t)
	result, err := mcpSecSession(t, f.api(), false).CallTool(context.Background(),
		&sdk.CallToolParams{Name: "infra_get_service_logs", Arguments: map[string]any{"ref": "web@dev-1"}})
	mcpRigMust(t, err)
	everything, err := json.Marshal(result.StructuredContent)
	mcpRigMust(t, err)

	for _, want := range []string{"listening on :8080", "ready", audit.Redacted} {
		if !strings.Contains(string(everything), want) {
			t.Errorf("tool output lacks %q: %s", want, everything)
		}
	}
}
