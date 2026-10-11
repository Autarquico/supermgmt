//go:build e2e

package harness

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
)

// OIDCSecretName is where the IdP client secret lives (secret:// reference in the configuration).
const OIDCSecretName = "auth/oidc-client"

// AllowSelfApproval lets the single operator of a test server approve their own high-risk jobs
// (spec §11.4: off by default on a server) and restarts the service.
func (s *Server) AllowSelfApproval(ctx context.Context) {
	s.t.Helper()
	s.AppendConfig(ctx, "security:\n    allow_self_approval: true\n")
	s.Restart(ctx)
}

// WaitJob polls a job until it reaches state, or fails the test if it ends differently.
func WaitJob(ctx context.Context, t testing.TB, api *client.Client, id domain.ID, want domain.JobState) wire.JobDetail {
	t.Helper()
	deadline := Now().Add(2 * time.Minute)
	var last wire.JobDetail
	for Now().Before(deadline) {
		job, err := api.GetJob(ctx, id)
		if err != nil {
			t.Fatalf("get job %s: %v", id, err)
		}
		last = job
		switch {
		case job.Job.State == want:
			return job
		case job.Job.State.Terminal():
			t.Fatalf("job %s ended %s, want %s: %+v", id, job.Job.State, want, job.Job.Error)
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("job %s still %s after 2m, want %s", id, last.Job.State, want)
	return last
}

// ApproveJob approves a job awaiting approval, bound to the plan hash the approver reviewed.
func ApproveJob(ctx context.Context, t testing.TB, api *client.Client, id domain.ID) {
	t.Helper()
	job, err := api.GetJob(ctx, id)
	if err != nil {
		t.Fatalf("get job %s: %v", id, err)
	}
	if _, err := api.Approve(ctx, id, wire.DecisionRequest{PlanHash: job.Job.PlanHash}); err != nil {
		t.Fatalf("approve job %s: %v", id, err)
	}
}

// BootstrapAdmin makes the person at c the first administrator of a server without OIDC: the
// bootstrap code from the admin socket, exchanged with `sm login --bootstrap`. It returns the
// session the client stored.
func (s *Server) BootstrapAdmin(ctx context.Context, c *Client, displayName string) string {
	s.t.Helper()
	c.Must(ctx, s.IssueBootstrapCode(ctx)+"\n", "login", "--bootstrap", "--display-name", displayName)
	return c.StoredToken("ops")
}

// EnableOIDC points a server that has started once (so its master key exists) at the IdP: the
// service is stopped, the client secret is sealed into the database offline (there is no
// administrator yet to import it), auth.oidc is written and the service starts again.
func (s *Server) EnableOIDC(ctx context.Context, d *Dex) {
	s.t.Helper()
	s.C.MustExec(ctx, "systemctl", "stop", "supermgmt")
	res := s.C.Exec(ctx, d.ClientSecret+"\n", "runuser", "-u", "supermgmt", "--", ServerBinary, "secrets", "import", "--offline",
		"--name", OIDCSecretName, "--config", ServerConfig)
	if res.Code != 0 {
		s.t.Fatalf("sm secrets import --offline exited %d\n%s", res.Code, res.Output())
	}
	s.AppendConfig(ctx, fmt.Sprintf(`auth:
    oidc:
        enabled: true
        issuer: %s
        client_id: %s
        client_secret_ref: secret://%s
        allowed_domains:
            - example.com
`, d.Issuer, d.ClientID, OIDCSecretName))
	s.C.MustExec(ctx, "systemctl", "start", "supermgmt")
	s.WaitReady(ctx)
}
