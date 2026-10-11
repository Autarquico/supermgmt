package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Exit codes of `sm backup restore` (spec §3.7, ADR-0020).
const (
	exitRestoreFailure = 9
)

// restoreReport is the --json output of a finished restore.
type restoreReport struct {
	Restored          bool   `json:"restored"`
	Archive           string `json:"archive"`
	DataDir           string `json:"data_dir"`
	RestoredConfigDir string `json:"restored_config_dir"`
	RestoreHold       bool   `json:"restore_hold"`
}

// newBackupRestoreCmd is `sm backup restore --offline ARCHIVE` (spec §29.2).
// The architect attaches it to the `backup` command next to create and list.
//
// It runs as whichever user owns the data directory (the service user on a
// server) and writes only inside the data directory and the keys directory:
// the configuration files of the archive are placed in
// <data_dir>/restored-config/ for the operator to review and copy, because
// the system configuration directory is not writable by the service user.
func newBackupRestoreCmd(env []string) *cobra.Command {
	var offline bool
	cmd := &cobra.Command{
		Use:   "restore ARCHIVE",
		Short: "Restore a backup archive into a stopped control plane",
		Long: "Restores a backup archive (.tar.zst) offline: the daemon must be stopped. The restored database " +
			"starts in restore hold until an admin runs `sm admin restore-complete`. Master keys are never part of an " +
			"archive: import them first with `sm secrets import-key --offline`.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("restore takes exactly one archive path")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if !offline {
				return usageErrorf("backup restore only runs offline: stop the daemon and add --offline")
			}
			configFlag, _ := cmd.Flags().GetString("config")
			asJSON, _ := cmd.Flags().GetBool("json")
			return restoreFailure(cmd, runBackupRestore(cmd, configPath(configFlag, env), env, args[0], asJSON))
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "restore without a running daemon (required)")
	return cmd
}

func runBackupRestore(cmd *cobra.Command, configFile string, env []string, archiveArg string, asJSON bool) error {
	result, err := config.Load(configFile, env)
	if err != nil {
		return usageErrorf("configuration %s is invalid: %s", configFile, joinProblems(configProblems(err)))
	}
	opts, err := restoreOptions(result.Config, archiveArg)
	if err != nil {
		return err
	}
	lock, err := database.AcquireDatabaseLock(opts.DBPath)
	if err != nil {
		return fmt.Errorf("%w (stop the daemon before restoring)", err)
	}
	defer func() { _ = lock.Release() }()

	if err := backup.Recover(opts.DataDir); err != nil {
		return fmt.Errorf("finish the interrupted restore first: %w", err)
	}
	if err := backup.Restore(cmd.Context(), opts); err != nil {
		return err
	}
	return writeRestoreReport(cmd.OutOrStdout(), opts, configFile, asJSON)
}

// restoreOptions resolves the paths of cfg and makes sure the archive can be
// read, which is the common way a restore run as the service user fails.
func restoreOptions(cfg *config.Config, archiveArg string) (backup.RestoreOptions, error) {
	archive, err := filepath.Abs(archiveArg)
	if err != nil {
		return backup.RestoreOptions{}, usageErrorf("archive path %q: %v", archiveArg, err)
	}
	if err := requireReadableFile(archive, "archive"); err != nil {
		return backup.RestoreOptions{}, err
	}
	dataDir, err := filepath.Abs(cfg.Instance.DataDir)
	if err != nil {
		return backup.RestoreOptions{}, usageErrorf("data_dir %q: %v", cfg.Instance.DataDir, err)
	}
	keysDir, err := filepath.Abs(cfg.Security.KeysDir)
	if err != nil {
		return backup.RestoreOptions{}, usageErrorf("security.keys_dir %q: %v", cfg.Security.KeysDir, err)
	}
	dbPath, err := filepath.Abs(cfg.Storage.SQLite.Path)
	if err != nil {
		return backup.RestoreOptions{}, usageErrorf("storage.sqlite.path %q: %v", cfg.Storage.SQLite.Path, err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return backup.RestoreOptions{}, usageErrorf("data directory %s cannot be created: %v", dataDir, err)
	}
	return backup.RestoreOptions{
		Archive: archive, DataDir: dataDir, KeysDir: keysDir, DBPath: dbPath,
		Clock: domain.SystemClock{}, IDs: domain.UUIDv7Generator{},
	}, nil
}

// requireReadableFile opens path to prove the current user can read it.
func requireReadableFile(path, what string) error {
	f, err := os.Open(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return usageErrorf("cannot read the %s %s: %v. The restore runs as the user who runs sm (on a server, the service user): "+
			"make the file readable by that user", what, path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return usageErrorf("the %s %s is not a regular file", what, path)
	}
	return nil
}

func joinProblems(problems []string) string {
	out := ""
	for i, p := range problems {
		if i > 0 {
			out += "; "
		}
		out += p
	}
	return out
}

func writeRestoreReport(w io.Writer, o backup.RestoreOptions, configFile string, asJSON bool) error {
	report := restoreReport{
		Restored: true, Archive: o.Archive, DataDir: o.DataDir,
		RestoredConfigDir: filepath.Join(o.DataDir, backup.RestoredConfigDir), RestoreHold: true,
	}
	if asJSON {
		return writeJSON(w, report)
	}
	_, err := fmt.Fprintf(w, `Restored %s.

The control plane starts in RESTORE HOLD: no job is claimed and every write except
job.resolve is refused until an admin runs "sm admin restore-complete".

  Previous files:      %s (pre-restore-*)
  Archived config:     %s
                       Review it and copy what you want to keep over %s;
                       this command does not write the system configuration directory.

Next: start the service, sign in again (OIDC, or an admin bootstrap code), review "sm doctor"
and the interrupted jobs, then run "sm admin restore-complete".
`, o.Archive, o.DataDir, report.RestoredConfigDir, configFile)
	return err
}

// restoreFailure prints a failure and gives it its §3.7 exit code: 2 for
// invalid input (left to the root command), 4 when a prerequisite is missing
// (the daemon holds the database lock), 9 for everything else.
func restoreFailure(cmd *cobra.Command, err error) error {
	var lockHeld *database.LockHeldError
	switch {
	case err == nil:
		return nil
	case smerr.CodeOf(err) == smerr.CodeInvalidArgument:
		return err
	case errors.As(err, &lockHeld):
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error: %v\n", err)
		return &childExitError{code: exitPrerequisite}
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error: %v\n", err)
	return &childExitError{code: exitRestoreFailure}
}
