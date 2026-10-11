package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

// runRestore runs `sm backup restore` through a root that carries only what
// the command needs; the architect attaches the real one under `sm backup`.
func runRestore(env []string, args ...string) result {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("json", false, "")
	parent := &cobra.Command{Use: "backup"}
	parent.AddCommand(newBackupRestoreCmd(env))
	root.AddCommand(parent)
	root.SetArgs(append([]string{"backup"}, args...))
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	err := root.Execute()
	if err != nil {
		asJSON, _ := root.PersistentFlags().GetBool("json")
		reportError(&errOut, err, asJSON)
	}
	return result{exitCode(err), out.String(), errOut.String()}
}

// archiveOf builds a real archive of a migrated database holding marker.
func archiveOf(t *testing.T, dir string) string {
	t.Helper()
	ctx := context.Background()
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	db, err := database.Open(ctx, filepath.Join(dir, "source.db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := database.PutConfigSnapshot(ctx, tx, []byte("version: 1\n"), nil, clock.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secrets.OpenFileKeys(ctx, filepath.Join(dir, "source-keys"), secretstest.NewMemRepo(), domaintest.NewSequentialIDs())
	if err != nil {
		t.Fatal(err)
	}
	created, err := backup.Create(ctx, backup.CreateOptions{
		Dir: filepath.Join(dir, "backups"), Instance: "lab", SMVersion: "test", Clock: clock, Source: db, Keys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return created.Path
}

func TestRestoreCommandRestoresIntoAFreshDataDirectory(t *testing.T) {
	s := newSandbox(t)
	archive := archiveOf(t, s.dir)

	r := runRestore(s.env, "restore", "--offline", archive, "--config", s.configFile)

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"RESTORE HOLD", "restore-complete", backup.RestoredConfigDir} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
	db, err := database.Open(context.Background(), s.dbPath, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if held, err := database.GetRestoreHold(context.Background(), db.Reader()); err != nil || !held {
		t.Errorf("restore hold = %v, %v; want true", held, err)
	}
	if got, err := os.ReadFile(filepath.Join(filepath.Dir(s.dbPath), backup.RestoredConfigDir, "config.yaml")); err != nil || string(got) != "version: 1\n" {
		t.Errorf("restored config = %q, %v", got, err)
	}
}

func TestRestoreCommandJSONReport(t *testing.T) {
	s := newSandbox(t)
	archive := archiveOf(t, s.dir)

	r := runRestore(s.env, "restore", "--offline", archive, "--config", s.configFile, "--json")

	var report restoreReport
	if err := json.Unmarshal([]byte(r.stdout), &report); err != nil || r.code != 0 {
		t.Fatalf("exit %d, output %q: %v", r.code, r.stdout, err)
	}
	if !report.Restored || !report.RestoreHold || report.Archive != archive {
		t.Errorf("report = %+v", report)
	}
}

func TestRestoreCommandExitCodes(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, s sandbox, archive string) []string
		code  int
		said  string
	}{
		{
			name: "without --offline", code: 2, said: "--offline",
			setup: func(_ *testing.T, _ sandbox, archive string) []string { return []string{"restore", archive} },
		},
		{
			name: "no archive argument", code: 2, said: "exactly one archive",
			setup: func(*testing.T, sandbox, string) []string { return []string{"restore", "--offline"} },
		},
		{
			name: "archive missing", code: 2, said: "cannot read the archive",
			setup: func(_ *testing.T, s sandbox, _ string) []string {
				return []string{"restore", "--offline", filepath.Join(s.dir, "absent.tar.zst")}
			},
		},
		{
			name: "archive not readable by this user", code: 2, said: "readable by that user",
			setup: func(t *testing.T, _ sandbox, archive string) []string {
				if os.Geteuid() == 0 {
					t.Skip("root can read anything")
				}
				if err := os.Chmod(archive, 0); err != nil {
					t.Fatal(err)
				}
				return []string{"restore", "--offline", archive}
			},
		},
		{
			name: "a daemon holds the database lock", code: 4, said: "stop the daemon",
			setup: func(t *testing.T, s sandbox, archive string) []string {
				lock, err := database.AcquireDatabaseLock(s.dbPath)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = lock.Release() })
				return []string{"restore", "--offline", archive}
			},
		},
		{
			name: "the archive is rejected", code: 9, said: "nothing was changed",
			setup: func(t *testing.T, s sandbox, _ string) []string {
				junk := filepath.Join(s.dir, "junk.tar.zst")
				writeFile(t, junk, strings.Repeat("junk", 64))
				return []string{"restore", "--offline", junk}
			},
		},
		{
			name: "an earlier restore left an unreadable journal", code: 9, said: "restore refused",
			setup: func(t *testing.T, s sandbox, archive string) []string {
				dataDir := filepath.Dir(s.dbPath)
				writeFile(t, filepath.Join(dataDir, backup.JournalName), "{torn")
				return []string{"restore", "--offline", archive}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t)
			archive := archiveOf(t, s.dir)
			args := append(tc.setup(t, s, archive), "--config", s.configFile)

			r := runRestore(s.env, args...)

			if r.code != tc.code {
				t.Errorf("exit %d, want %d; stderr: %s", r.code, tc.code, r.stderr)
			}
			if !strings.Contains(r.stderr, tc.said) {
				t.Errorf("stderr %q does not say %q", r.stderr, tc.said)
			}
		})
	}
}

func TestRestoreCommandFinishesAnInterruptedRestoreFirst(t *testing.T) {
	s := newSandbox(t)
	archive := archiveOf(t, s.dir)
	dataDir := filepath.Dir(s.dbPath)
	staging := filepath.Join(dataDir, "restore-00000000-0001-7000-8000-000000000000")
	writeFile(t, filepath.Join(staging, "supermgmt.db"), "staged")

	r := runRestore(s.env, "restore", "--offline", archive, "--config", s.configFile)

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Errorf("a stale staging directory survived: %v", err)
	}
}
