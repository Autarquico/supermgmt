package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
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
	return &cobra.Command{
		Use:   "create",
		Short: "Create a backup now (a job; master keys are never included)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
