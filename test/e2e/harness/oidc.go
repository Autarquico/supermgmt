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

// EnableOIDC makes the IdP the way people sign in: it imports the client secret as admin (a
// high-risk job that is approved), writes auth.oidc and restarts the service. Before this the
// server has no IdP configuration, because the secret can only be imported by an administrator and
// the first administrator needs the bootstrap code (BUG-3: there is no `sm secrets import
// --offline` to preload it).
func (s *Server) EnableOIDC(ctx context.Context, admin *Client, adminToken string, d *Dex) {
	s.t.Helper()
	api := s.Typed(adminToken)
	var imported wire.Direct[wire.SecretVersion]
	admin.JSON(ctx, d.ClientSecret+"\n", &imported, "secrets", "import", "--name", OIDCSecretName)
	if imported.Pending == nil {
		s.t.Fatalf("secrets import was not parked for approval: %+v", imported)
	}
	job := imported.Pending.Job.ID
	ApproveJob(ctx, s.t, api, job)
	WaitJob(ctx, s.t, api, job, domain.JobSucceeded)
	s.AppendConfig(ctx, fmt.Sprintf(`auth:
    oidc:
        enabled: true
        issuer: %s
        client_id: %s
        client_secret_ref: secret://%s
        allowed_domains:
            - example.com
`, d.Issuer, d.ClientID, OIDCSecretName))
	s.Restart(ctx)
}
