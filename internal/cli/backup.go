package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/version"
)

// newBackupCmd is `sm backup`: create and list go through the API; restore is
// offline (backup_restore.go) and takes the database lock itself.
func newBackupCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create and list backups; restore one offline",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newBackupCreateCmd(env), newBackupListCmd(env), newBackupRestoreCmd(env))
	return cmd
}

func newBackupCreateCmd(env []string) *cobra.Command {
	var offline bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a backup now (a job; master keys are never included)",
		Long: "Create a backup archive. Online it is a job the server runs.\n\n" +
			"With --offline the service must be stopped: the database is opened read-only and copied as it is. Nothing\n" +
			"is migrated, no configuration is activated and nothing is audited or pruned, so the archive keeps the\n" +
			"schema version of the database (the upgrade relies on it). The archive belongs to the user running this.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if offline {
				return createBackupOffline(cmd, env)
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			submission, err := api.CreateBackup(cmd.Context())
			if err != nil {
				return err
			}
			return submissionOutput(cmd, submission)
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "back up a stopped control plane read-only, without migrating it")
	return cmd
}

// offlineBackupReport is the --json output of `sm backup create --offline`.
type offlineBackupReport struct {
	Name          string      `json:"name"`
	Path          string      `json:"path"`
	SizeBytes     int64       `json:"size_bytes"`
	SchemaVersion int         `json:"schema_version"`
	SMVersion     string      `json:"sm_version"`
	KEKIDs        []domain.ID `json:"kek_ids"`
}

func createBackupOffline(cmd *cobra.Command, env []string) error {
	session, err := openOffline(cmd, env)
	if err != nil {
		return err
	}
	defer session.close()
	repo, err := session.repo(cmd.Context())
	if err != nil {
		return err
	}
	if repo == nil {
		return usageErrorf("there is no initialized database at %s to back up", session.dbPath)
	}
	// The keys are only read: an instance without keys cannot be backed up here,
	// and the loader never creates a keys directory or a first key.
	keys, err := secrets.OpenFileKeysReadOnly(cmd.Context(), session.keysDir, repo)
	if err != nil {
		return err
	}
	instance, err := database.GetInstance(cmd.Context(), session.db.Querier())
	if err != nil {
		return fmt.Errorf("read the instance: %w", err)
	}
	created, err := backup.Create(cmd.Context(), backup.CreateOptions{
		Dir: session.cfg.Backup.Directory, Instance: instance.Name, KnownHostsPath: session.cfg.SSH.KnownHostsFile,
		SMVersion: version.Info().Version, Clock: domain.SystemClock{}, Source: session.db, Keys: keys,
	})
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	report := offlineBackupReport{
		Name: created.Name, Path: created.Path, SizeBytes: created.Size,
		SchemaVersion: created.Manifest.SchemaVersion, SMVersion: created.Manifest.SMVersion, KEKIDs: created.Manifest.KEKIDs,
	}
	return emit(cmd, report, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "created %s (schema %d)\n", created.Path, report.SchemaVersion)
		return err
	})
}

func newBackupListCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the backup archives with the master keys they need",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			page, err := api.ListBackups(cmd.Context())
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeBackups(w, page.Items) })
		},
	}
}

func writeBackups(w io.Writer, backups []wire.Backup) error {
	rows := make([][]string, len(backups))
	for i, b := range backups {
		keys := make([]string, len(b.KEKIDs))
		for j, id := range b.KEKIDs {
			keys[j] = string(id)
		}
		rows[i] = []string{b.Name, fmt.Sprint(b.SizeBytes), formatTime(b.CreatedAt), fmt.Sprint(b.SchemaVersion), b.SMVersion, orDash(strings.Join(keys, ","))}
	}
	return table(w, []string{"NAME", "BYTES", "CREATED", "SCHEMA", "SM", "KEYS"}, rows)
}
