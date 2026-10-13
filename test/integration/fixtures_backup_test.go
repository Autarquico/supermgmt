//go:build fixtures

package integration

import (
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The pre-deploy backup step (spec §19.1, ADR-0029) against a real Postgres.

const (
	backupContainer = "t17b-pg"
	backupDatabase  = "appdb"
)

// startPostgres runs a Postgres container with one table and one row.
func (n *deployNode) startPostgres(t *testing.T) {
	t.Helper()
	n.shell(t, "docker run -d --name "+backupContainer+" -e POSTGRES_PASSWORD=pw -e POSTGRES_DB="+backupDatabase+" postgres:17-alpine")
	n.shell(t, "for i in $(seq 60); do docker exec "+backupContainer+" pg_isready -q -U postgres -d "+backupDatabase+
		" && docker exec "+backupContainer+" psql -q -U postgres -d "+backupDatabase+" -c 'select 1' >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1")
	n.psql(t, backupDatabase, "create table items (id int primary key, name text); insert into items values (7, 'kept');")
}

func (n *deployNode) psql(t *testing.T, database, statement string) string {
	t.Helper()
	return n.shell(t, "docker exec "+backupContainer+" psql -q -At -U postgres -d "+database+" -c \""+statement+"\"")
}

func (n *deployNode) dumpFiles(t *testing.T) string {
	t.Helper()
	return n.shell(t, "ls -A "+templates.BackupDir)
}

func TestFixtures_BackupStep(t *testing.T) {
	n := startDeployNode(t)
	n.startPostgres(t)
	dumpArgs := func(database string) map[string]string {
		return map[string]string{"container": backupContainer, "database": database}
	}

	var artifact string
	t.Run("a dump prints one path inside the backup directory and leaves done with exit 0", func(t *testing.T) {
		cmd, err := templates.RenderMutating("postgres-dump", "t17b-backup-1", dumpArgs(backupDatabase))
		if err != nil {
			t.Fatalf("render postgres-dump: %v", err)
		}
		res := n.asSupermgmt(t, cmd)
		if res.ExitStatus != 0 {
			t.Fatalf("postgres-dump exit %d: %s", res.ExitStatus, stderrOf(res))
		}
		artifact, err = templates.ParseBackupPath(res.Stdout)
		if err != nil {
			t.Fatalf("ParseBackupPath(%q): %v", res.Stdout, err)
		}
		if state := n.markerOf(t, "t17b-backup-1"); !state.CompletionProof() {
			t.Errorf("marker = %+v; want done with exit 0", state)
		}
		if got := n.shell(t, "stat -c '%a %U' "+artifact); got != "600 supermgmt" {
			t.Errorf("artifact mode and owner = %q; want 600 supermgmt", got)
		}
	})

	t.Run("the artifact restores the data it was taken from", func(t *testing.T) {
		if artifact == "" {
			t.Skip("no artifact from the previous step")
		}
		n.psql(t, "postgres", "create database restored")
		n.shell(t, "docker exec -i "+backupContainer+" pg_restore -U postgres -d restored < "+artifact)
		if got := n.psql(t, "restored", "select name from items where id = 7"); got != "kept" {
			t.Errorf("restored row = %q; want kept", got)
		}
	})

	t.Run("a database that does not exist fails and leaves no artifact behind", func(t *testing.T) {
		before := n.dumpFiles(t)
		cmd, err := templates.RenderMutating("postgres-dump", "t17b-backup-2", dumpArgs("nosuchdb"))
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		res := n.asSupermgmt(t, cmd)
		if res.ExitStatus == 0 {
			t.Fatalf("dump of a missing database succeeded: %s", res.Stdout)
		}
		if state := n.markerOf(t, "t17b-backup-2"); state.Kind != templates.MarkerDone || state.CompletionProof() {
			t.Errorf("marker = %+v; want done with a nonzero status", state)
		}
		if after := n.dumpFiles(t); after != before {
			t.Errorf("backup directory changed on a failed dump:\nbefore: %q\nafter:  %q", before, after)
		}
		if _, err := templates.ParseBackupPath(res.Stdout); err == nil {
			t.Errorf("a failed dump still printed an artifact path: %q", res.Stdout)
		}
	})

	t.Run("a container that does not exist fails", func(t *testing.T) {
		cmd, err := templates.RenderMutating("postgres-dump", "t17b-backup-3", map[string]string{"container": "t17b-absent", "database": backupDatabase})
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		if res := n.asSupermgmt(t, cmd); res.ExitStatus == 0 {
			t.Fatalf("dump of a missing container succeeded: %s", res.Stdout)
		}
	})

	t.Run("a container or database name is never parsed as shell text", func(t *testing.T) {
		for _, args := range []map[string]string{
			{"container": backupContainer + "; touch /tmp/pwned", "database": backupDatabase},
			{"container": backupContainer, "database": backupDatabase + "; touch /tmp/pwned"},
			{"container": backupContainer, "database": "$(touch /tmp/pwned)"},
		} {
			if _, err := templates.RenderMutating("postgres-dump", "t17b-backup-4", args); err == nil {
				t.Errorf("postgres-dump rendered for %v", args)
			}
		}
		if _, err := n.tryShell(t, "test -e /tmp/pwned"); err == nil {
			t.Error("an injected command ran on the node")
		}
	})

	t.Run("a backup directory that became a symlink is refused", func(t *testing.T) {
		victim := n.victimDir(t, "victim-backups")
		n.shell(t, "mv "+templates.BackupDir+" "+templates.BackupDir+".real && ln -s "+victim+" "+templates.BackupDir)
		cmd, err := templates.RenderMutating("postgres-dump", "t17b-backup-5", dumpArgs(backupDatabase))
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		res := n.asSupermgmt(t, cmd)
		if res.ExitStatus == 0 {
			t.Fatalf("dump through a symlinked backup directory succeeded: %s", res.Stdout)
		}
		if !strings.Contains(stderrOf(res), "symlink") {
			t.Errorf("stderr = %q; want the symlink refusal", stderrOf(res))
		}
		n.untouched(t, victim)
	})
}
