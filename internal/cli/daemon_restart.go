package cli

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/database"
)

const daemonStopTimeout = 10 * time.Second

func newDaemonRestartCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Stop the local daemon; the next command starts a fresh one",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configFlag, _ := cmd.Flags().GetString("config")
			loaded, err := loadDaemonConfig(configPath(configFlag, env), env)
			if err != nil {
				return err
			}
			stopped, err := stopLocalDaemon(loaded.Config.Storage.SQLite.Path, daemonStopTimeout)
			if err != nil {
				return err
			}
			if !stopped {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no daemon was running; the next command starts one")
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "the daemon stopped; the next command starts a fresh one")
			return err
		},
	}
}

// stopLocalDaemon asks the process holding the database lock to terminate and
// waits until the lock is free. It reports whether a daemon was running.
func stopLocalDaemon(dbPath string, timeout time.Duration) (bool, error) {
	var held *database.LockHeldError
	lock, err := database.AcquireDatabaseLock(dbPath)
	if err == nil {
		_ = lock.Release()
		return false, nil
	}
	if !errors.As(err, &held) {
		return false, err
	}
	if held.PID <= 0 {
		return false, fmt.Errorf("the database lock is held but its holder is unknown: %w", err)
	}
	if err := syscall.Kill(held.PID, syscall.SIGTERM); err != nil {
		return false, fmt.Errorf("stop PID %d: %w", held.PID, err)
	}
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if lock, err := database.AcquireDatabaseLock(dbPath); err == nil {
			_ = lock.Release()
			return true, nil
		}
	}
	return false, fmt.Errorf("PID %d did not stop within %s", held.PID, timeout)
}
