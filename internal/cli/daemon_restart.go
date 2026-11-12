package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// stopMargin is added to the configured shutdown timeout: the daemon may use all of it to drain.
const stopMargin = 5 * time.Second

func newDaemonRestartCmd(env []string) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Stop the local daemon; the next command starts a fresh one",
		Long: "Stop the local daemon so the next command starts a fresh one. Only a local-mode daemon is stopped: a\n" +
			"server, or any other process holding the database, is refused. Jobs that are running or queued would be\n" +
			"interrupted, so they are listed and the restart is refused unless you pass --force.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configFlag, _ := cmd.Flags().GetString("config")
			loaded, err := loadDaemonConfig(configPath(configFlag, env), env)
			if err != nil {
				return err
			}
			cfg := loaded.Config
			if cfg.Instance.Mode != config.ModeLocal {
				return usageErrorf("sm daemon restart stops a local daemon; this configuration is a server (restart it with your service manager)")
			}
			dbPath := cfg.Storage.SQLite.Path
			pid, err := localDaemonPID(dbPath, socketPath(cfg, env))
			if err != nil {
				return err
			}
			if pid == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no daemon was running; the next command starts one")
				return err
			}
			if !force {
				if err := refuseWhileJobsRun(cmd, env, configFlag); err != nil {
					if now, _ := localDaemonPID(dbPath, socketPath(cfg, env)); now == 0 {
						_, err = fmt.Fprintln(cmd.OutOrStdout(), "the daemon exited by itself; the next command starts a fresh one")
						return err
					}
					return err
				}
			}
			if err := stopDaemon(dbPath, pid, cfg.Server.ShutdownTimeout+stopMargin); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "the daemon stopped; the next command starts a fresh one")
			return err
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "restart even though running or queued jobs will be interrupted")
	return cmd
}

// refuseWhileJobsRun lists the jobs a restart would interrupt, through the local daemon. It
// never autostarts one: a daemon that exited meanwhile must not be replaced by this binary's.
func refuseWhileJobsRun(cmd *cobra.Command, env []string, configFlag string) error {
	api, err := newLocalClient(append(slices.Clone(env), envNoAutostart+"=1"), configFlag)
	if err != nil {
		return err
	}
	page, err := api.ListJobs(cmd.Context(), wire.JobQuery{States: []domain.JobState{domain.JobRunning, domain.JobQueued}})
	if err != nil {
		return err
	}
	if len(page.Items) == 0 {
		return nil
	}
	lines := make([]string, len(page.Items))
	for i, j := range page.Items {
		lines[i] = fmt.Sprintf("%s %s (%s)", j.ID, j.Type, j.State)
	}
	more := ""
	if page.NextCursor != "" {
		more = " and more"
	}
	return usageErrorf("restarting would interrupt %d job(s): %s%s; wait for them or pass --force", len(page.Items), strings.Join(lines, ", "), more)
}

// lockHolder is the PID holding the lock for path; held is false when it is free.
func lockHolder(path string) (pid int, held bool, err error) {
	lock, err := database.AcquireDatabaseLock(path)
	if err == nil {
		_ = lock.Release()
		return 0, false, nil
	}
	var h *database.LockHeldError
	if errors.As(err, &h) {
		return h.PID, true, nil
	}
	return 0, false, err
}

// localDaemonPID is the PID of the running local daemon, 0 when none runs. Only a
// local daemon holds the database lock and the socket lock together; a holder of
// the database lock alone (a server, a restore, an offline session) is refused.
func localDaemonPID(dbPath, socket string) (int, error) {
	dbPID, dbHeld, err := lockHolder(dbPath)
	if err != nil || !dbHeld {
		return 0, err
	}
	sockPID, sockHeld, err := lockHolder(socket)
	if err != nil {
		return 0, err
	}
	if !sockHeld || dbPID <= 0 || sockPID != dbPID {
		return 0, fmt.Errorf("the database is held by PID %d, which is not the local daemon (it does not own %s); not stopping it", dbPID, socket)
	}
	return dbPID, nil
}

// stopDaemon asks the daemon to terminate and waits until it released the database.
func stopDaemon(dbPath string, pid int, timeout time.Duration) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("stop PID %d: %w", pid, err)
	}
	const poll = 100 * time.Millisecond
	for waited := time.Duration(0); waited < timeout; waited += poll {
		if _, held, err := lockHolder(dbPath); err == nil && !held {
			return nil
		}
		time.Sleep(poll)
	}
	return fmt.Errorf("PID %d did not stop within %s", pid, timeout)
}
