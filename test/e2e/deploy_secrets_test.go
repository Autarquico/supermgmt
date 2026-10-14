//go:build e2e && fixtures

package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

const (
	secretsCommit = "8888888888888888888888888888888888888888"
	secretsName   = "apps/shop/token"
	secretsValue  = "m4-leak-probe-Zq8x91acB7"

	secretsCompose = `services:
  web:
    image: ` + m4RegistryHost + `/` + m4ImageRepo + `:placeholder
    environment:
      TOKEN: ${secret:token}
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
`
)

// secretsControlPlaneEvidence is everything on the server that a secret could leak into: the
// database and its write-ahead log, and the service journal.
func (w *m4World) secretsControlPlaneEvidence(server *harness.Container) map[string][]byte {
	w.t.Helper()
	evidence := map[string][]byte{}
	dir := w.t.TempDir()
	for _, name := range []string{"supermgmt.db", "supermgmt.db-wal"} {
		dst := filepath.Join(dir, name)
		if res, err := harness.Docker(w.ctx(), "", "cp", server.Name+":"+harness.ServerData+"/"+name, dst); err != nil || res.Code != 0 {
			continue // no write-ahead log right after a checkpoint
		}
		raw, err := os.ReadFile(dst)
		if err != nil {
			w.t.Fatal(err)
		}
		evidence["database file "+name] = raw
	}
	evidence["service journal"] = []byte(server.Exec(w.ctx(), "", "journalctl", "-u", "supermgmt", "--no-pager", "-o", "cat").Stdout)
	return evidence
}

// secretsBackupEvidence takes a backup and returns the concatenated content of the archive.
func (w *m4World) secretsBackupEvidence(server *harness.Container) []byte {
	w.t.Helper()
	submitted, err := w.api.CreateBackup(w.ctx())
	if err != nil {
		w.t.Fatalf("create the backup: %v", err)
	}
	w.settleJob(jobOf(w.t, submitted), m4SetupJobTimeout)
	listed, err := w.api.ListBackups(w.ctx())
	if err != nil || len(listed.Items) == 0 {
		w.t.Fatalf("list backups: %v %+v", err, listed)
	}
	_, content := server.ArchiveEvidence(w.ctx(), harness.ServerData+"/backups/"+listed.Items[0].Name)
	return content
}

// secretsAPIEvidence is every answer the API gives about the application, its deployments, their
// jobs and plans, and the event log.
func (w *m4World) secretsAPIEvidence(app wire.App) []byte {
	w.t.Helper()
	ctx := w.ctx()
	answers := map[string]any{}
	record := func(name string, v any, err error) {
		if err != nil {
			w.t.Fatalf("%s: %v", name, err)
		}
		answers[name] = v
	}
	page := wire.PageQuery{Limit: wire.MaxLimit}
	apps, err := w.api.ListApps(ctx, page)
	record("apps", apps, err)
	one, err := w.api.GetApp(ctx, app.ID)
	record("app", one, err)
	deps, err := w.api.ListDeployments(ctx, wire.DeploymentQuery{PageQuery: page})
	record("deployments", deps, err)
	for _, d := range deps.Items {
		full, err := w.api.GetDeployment(ctx, d.ID)
		record("deployment "+string(d.ID), full, err)
		if d.JobID != nil {
			job, err := w.api.GetJob(ctx, *d.JobID)
			record("job "+string(*d.JobID), job, err)
		}
	}
	jobs, err := w.api.ListJobs(ctx, wire.JobQuery{PageQuery: page})
	record("jobs", jobs, err)
	events, err := w.api.ListEvents(ctx, wire.EventQuery{PageQuery: page})
	record("events", events, err)
	approvals, err := w.api.ListApprovals(ctx, page)
	record("approvals", approvals, err)
	raw, err := json.Marshal(answers)
	if err != nil {
		w.t.Fatal(err)
	}
	return raw
}

// TestM4_SecretNeverOnControlPlane
//
// Secret handling (PLAN §9 secrets row): an application whose Compose file references a secret is
// deployed; the node's container receives the value, and neither the database, the service journal,
// a backup archive, nor any API answer or event holds it in plaintext.
func TestM4_SecretNeverOnControlPlane(t *testing.T) {
	w := newM4ServerWorld(t)
	provider, node := w.waitForStaticConfig()
	w.sim.addShopRepository()
	w.prepareNode(node)

	imported, err := w.api.ImportSecret(w.ctx(), wire.ImportSecretRequest{Name: secretsName, Value: secretsValue})
	if err != nil {
		t.Fatalf("import the secret: %v", err)
	}
	if imported.Pending != nil {
		w.settleJob(imported.Pending.Job.ID, m4SetupJobTimeout)
	}
	req := deployAppRequest(provider, m4AppName)
	req.ComposeContent, req.SecretRefs = secretsCompose, map[string]string{"token": "secret://" + secretsName}
	target := w.deployCreateApp(req, node, shopPolicy())

	digest := w.sim.pushImage(m4Image{Version: "secret"})
	w.sim.attest(digest, secretsCommit)
	d := w.deployShop(target, secretsCommit, digest)
	w.deployTellCIPassed(secretsCommit, 1)
	w.deploySucceeded(d)

	t.Run("the container on the node receives the secret", func(t *testing.T) {
		names := strings.Fields(w.node.c.MustExec(w.ctx(), "docker", "ps", "--filter", "label=com.docker.compose.project="+target.ComposeProject, "--format", "{{.Names}}"))
		if len(names) != 1 {
			t.Fatalf("containers of the project = %q, want exactly one", names)
		}
		env := w.node.c.MustExec(w.ctx(), "docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", names[0])
		if !slices.Contains(strings.Split(env, "\n"), "TOKEN="+secretsValue) {
			t.Fatal("the container's environment does not carry the secret as TOKEN")
		}
	})

	t.Run("no control-plane place holds the value in plaintext", func(t *testing.T) {
		server := w.deployServerContainer()
		evidence := w.secretsControlPlaneEvidence(server)
		evidence["backup archive"] = w.secretsBackupEvidence(server)
		evidence["API answers"] = w.secretsAPIEvidence(w.findApp(m4AppName))
		for place, content := range evidence {
			if len(content) == 0 {
				t.Errorf("no evidence collected from the %s", place)
			}
		}
		harness.AssertNoPlaintext(t, evidence, map[string]string{"the app secret": secretsValue})
	})
}
