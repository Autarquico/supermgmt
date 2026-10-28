package tunnel

import (
	"context"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

// Scenario "secrets never leak": the API token, the service token secret and
// the tunnel credential appear in no plan, job payload, event, log, error,
// recorded command, backup archive or (with a node, see the fixtures suite)
// node file, unit or journal. The control-plane half runs without Docker: the
// node is unreachable, so the setup job provisions Cloudflare, then fails at
// the first node step, which is the failure path the scan most needs.

// scanControlPlane returns every place on the control plane a credential
// could have been written to.
func (s *stack) scanControlPlane() map[string][]byte {
	places := s.dumpDatabase()
	for name, data := range s.archive() {
		places[name] = data
	}
	places["engine log"] = s.logs.bytes()
	places["node commands and output"] = s.commands.bytes()
	return places
}

func TestNoCredentialLeaksFromTheControlPlaneThroughEnableAndFailure(t *testing.T) {
	s := newStack(t, stackOptions{poolConfig: &fastPool})
	node := s.addNode("web1", unreachable(t), "secret://ssh/default")
	creds := credentials{}

	// A fault after the third Cloudflare mutation and another after the fifth:
	// the job is retried and takes over its own record.
	s.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		switch m.Seq {
		case 3:
			return cffake.LostResponse
		case 5:
			return cffake.FailBefore
		}
		return cffake.NoFault
	})
	job := s.run("node.setup", nodeRef(node), map[string]any{"tunnel": "true", "docker_access": "false", "logs_mode": "journal-group"})
	t.Logf("setup --tunnel on an unreachable node: %s", outcome(job, nil))
	s.cf.ClearFaults()
	if job.State == domain.JobSucceeded {
		t.Fatal("setup --tunnel succeeded on a node nothing answers at")
	}
	snap := s.cf.Snapshot()
	t.Logf("cloudflare objects: %d tunnels, %d apps, %d dns, %d policies, %d tokens",
		len(snap.Tunnels), len(snap.Apps), len(snap.DNSRecords), len(snap.Policies), len(snap.ServiceTokens))
	s.collect(creds)
	if len(creds) < 2 {
		t.Fatalf("only %d credentials exist to scan for (%v): the run provisioned too little to be a meaningful scan", len(creds), names(creds))
	}

	assertNoLeaks(t, creds, s.scanControlPlane())
}

// The scan has to be able to fail: a planted credential is found in the
// database dump, the transcript and the archive, and a sealed one is not.
func TestTheLeakScanSeesWhatItLooksFor(t *testing.T) {
	s := newStack(t, stackOptions{poolConfig: &fastPool})
	node := s.addNode("web1", unreachable(t), "secret://ssh/default")
	const canary = "canary-0123456789-abcdef"
	creds := credentials{"canary": canary}

	if got := leaks(creds, s.scanControlPlane()); len(got) != 0 {
		t.Fatalf("a clean instance already leaks the canary: %v", got)
	}
	_, err := s.store.Put(context.Background(), "suite/canary", audit.Secret(canary), nil)
	must(t, err)
	if got := leaks(creds, s.scanControlPlane()); len(got) != 0 {
		t.Errorf("a sealed secret is readable in the scan places: %v", got)
	}
	if len(s.dumpDatabase()["db:secrets"]) == 0 {
		t.Error("the sealed secret is not in the dump: the scan does not read the secrets table")
	}

	must(t, s.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE nodes SET os = ? WHERE id = ?`, canary, node.ID)
		return err
	}))
	got := leaks(creds, s.scanControlPlane())
	want := []string{"canary in backup-db-text", "canary in backup:" + backup.DatabaseName, "canary in db:nodes"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("a planted credential was found in %v, want %v", got, want)
	}
	s.commands.add("cmd", "planted", canary)
	if got := leaks(creds, map[string][]byte{"node commands and output": s.commands.bytes()}); len(got) != 1 {
		t.Errorf("a planted command line was not found: %v", got)
	}
}

func assertNoLeaks(t *testing.T, creds credentials, places map[string][]byte) {
	t.Helper()
	if len(places) == 0 {
		t.Fatal("nothing was scanned")
	}
	for _, leak := range leaks(creds, places) {
		t.Errorf("leak: %s", leak)
	}
}

func names(c credentials) []string {
	out := make([]string, 0, len(c))
	for name := range c {
		out = append(out, name)
	}
	return out
}
