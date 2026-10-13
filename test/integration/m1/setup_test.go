//go:build fixtures

package m1

import (
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const stagedSudoers = "/etc/sudoers.d/supermgmt.new"

// Setup (ADR-0009 f): the job is idempotent, so a daemon killed in the middle
// of node.setup requeues it, and the re-run converges to exactly one user, one
// key line, the rendered sudoers lines, and one recorded capability.
func TestM1Setup_DaemonKilledMidSetupRequeuesAndConverges(t *testing.T) {
	n := startNodes(t, fixture.Options{})[0]
	in := newInstance(t, instanceOptions{})
	in.startDaemon()
	api := in.client()
	nd := addNode(t, api, in, n, "setup-node", "staging")
	waitDiscovered(t, api, nd.ID)

	// Slow the sudoers validation so the kill lands with the user, the key and
	// the staged drop-in on the node but the drop-in not yet committed.
	n.sh(t, `V=$(command -v visudo) && mv "$V" "$V.real" && printf '#!/bin/sh\nsleep 30\nexec %s.real "$@"\n' "$V" > "$V" && chmod 0755 "$V"`)

	sub := submitSetup(t, api, nd, false, allVerbs(demoUnit)...)
	approve(t, api, sub)
	eventually(t, time.Minute, "the staged sudoers drop-in to appear on the node", func() bool {
		_, err := n.trySh(t, "test -f "+stagedSudoers)
		return err == nil
	})
	if out, err := n.trySh(t, "test -f /etc/sudoers.d/supermgmt"); err == nil {
		t.Fatalf("the drop-in was already committed (%s); the kill would not interrupt setup", out)
	}
	in.killDaemon()
	n.sh(t, `V=$(command -v visudo) && mv "$V.real" "$V"`)

	in.startDaemon()
	api = in.client()
	job := waitJob(t, api, sub.Job.ID, domain.JobSucceeded, 5*time.Minute)
	if job.Attempts < 2 {
		t.Errorf("setup succeeded after %d attempt(s); an interrupted run should have been requeued", job.Attempts)
	}

	if got := n.sh(t, "getent passwd supermgmt | wc -l"); got != "1" {
		t.Errorf("%s passwd entries for supermgmt, want 1", got)
	}
	if got := n.sh(t, "grep -c . /var/lib/supermgmt/.ssh/authorized_keys"); got != "1" {
		t.Errorf("authorized_keys has %s lines, want 1", got)
	}
	if out, err := n.trySh(t, "test -e "+stagedSudoers); err == nil {
		t.Errorf("the staged drop-in was left behind: %s", out)
	}
	lines := strings.Split(n.sh(t, "grep -v '^#' /etc/sudoers.d/supermgmt"), "\n")
	if len(lines) != len(domain.AllServiceVerbs()) {
		t.Errorf("sudoers drop-in has %d lines, want one per granted verb (%d): %q", len(lines), len(domain.AllServiceVerbs()), lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "supermgmt ALL=(root) NOPASSWD: ") || !strings.HasSuffix(line, " "+demoUnit) {
			t.Errorf("unexpected sudoers line %q", line)
		}
	}
	n.sh(t, "visudo -cf /etc/sudoers.d/supermgmt")

	got, err := api.GetNode(t.Context(), nd.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Setup == nil || got.Setup.SetupVersion != 2 || got.Setup.LogsMode != "journal-group" || got.Setup.DockerAccess || len(got.Setup.Units) != 1 {
		t.Errorf("recorded setup = %+v, want version 2, journal-group, no docker access, 1 unit", got.Setup)
	}
	if got := count(eventActions(t, in), "node.setup.completed"); got != 1 {
		t.Errorf("%d node.setup.completed events, want exactly 1", got)
	}

	probe(t, api, nd.ID)
	if logins := n.sh(t, `journalctl -u ssh --no-pager | grep -c "Accepted publickey for supermgmt"`); logins == "0" {
		t.Errorf("after the converged setup no probe authenticated as supermgmt")
	}
}

// Secrets: after a full setup, a restart and a log read, no plaintext private
// key or KEK exists in the database, WAL, data dir, daemon log, events or API
// responses, nor on the node.
func TestM1Secrets_NoPlaintextKeyAfterSetupActionsAndLogs(t *testing.T) {
	l := newProvisionedLab(t, instanceOptions{}, allVerbs(demoUnit)...)
	svc := serviceNamed(t, l.api, l.node.ID, demoUnit)
	sub, err := l.api.ServiceAction(t.Context(), svc.ID, domain.VerbRestart)
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, l.api, sub.Job.ID, domain.JobSucceeded, 3*time.Minute)
	if _, err := l.api.ServiceLogs(t.Context(), svc.ID, wire.LogQuery{Lines: 50}); err != nil {
		t.Fatal(err)
	}

	paths := append(baseDumpPaths(),
		fmt.Sprintf("/api/v1/nodes/%s", l.node.ID), fmt.Sprintf("/api/v1/nodes/%s/services", l.node.ID),
		fmt.Sprintf("/api/v1/services/%s", svc.ID), fmt.Sprintf("/api/v1/services/%s/logs", svc.ID),
		fmt.Sprintf("/api/v1/nodes/%s/connect-info", l.node.ID), fmt.Sprintf("/api/v1/jobs/%s", sub.Job.ID))
	scanForSecrets(t, l.in, apiDump(t, l.in, paths...))

	l.in.stopDaemon(syscall.SIGTERM) // the WAL is checkpointed, the scan sees the final files
	scanForSecrets(t, l.in, nil)

	onNode := l.n.sh(t, `grep -rIl -e 'openssh-key-v1' -e 'PRIVATE KEY' /var/lib/supermgmt /home /etc/sudoers.d /tmp /root 2>/dev/null || true`)
	if onNode != "" {
		t.Errorf("a private key exists on the node: %s", onNode)
	}
}
