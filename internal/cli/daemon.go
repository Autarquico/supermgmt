package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// exitSecondDaemon is the exit code of a daemon that lost a lock (ADR-0014).
const exitSecondDaemon = 2

const minimalLocalConfig = "version: 1\ninstance:\n  mode: local\n"

// newDaemonCmd is `sm daemon`: the resident process of spec §2.1.1. Clients
// autostart it; it exits 2 when another daemon owns the database or the socket.
func newDaemonCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the SuperMgmt daemon (started on demand by the other commands)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configFlag, _ := cmd.Flags().GetString("config")
			level, _ := cmd.Flags().GetString("log-level")
			file := configPath(configFlag, env)
			cfg, err := loadDaemonConfig(file, env)
			if err != nil {
				return err
			}
			if !fileExists(file) {
				file = "" // built-in defaults: the snapshot stores the effective configuration
			}
			if cfg.Instance.Mode != config.ModeLocal {
				return smerr.New(smerr.CodeCapabilityUnavailable, "", "sm daemon runs local mode; this configuration is a server: run `sm server`")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			err = daemon.Run(ctx, daemon.Options{
				Config: cfg, ConfigFile: file, Socket: socketPath(cfg, env), Log: daemonLogger(cmd, level),
			})
			return daemonExit(cmd, err)
		},
	}
}

// loadDaemonConfig loads the file, or the built-in local-mode defaults when
// there is none: the client autostarts the daemon before anyone wrote a config.
func loadDaemonConfig(path string, env []string) (*config.Config, error) {
	if fileExists(path) {
		result, err := config.Load(path, env)
		return result.Config, err
	}
	result, err := config.LoadBytes([]byte(minimalLocalConfig), env)
	return result.Config, err
}

func daemonLogger(cmd *cobra.Command, level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: l}))
}

// daemonExit turns a lost lock into exit code 2 with the PID named.
func daemonExit(cmd *cobra.Command, err error) error {
	var held *database.LockHeldError
	var inUse *daemon.SocketInUseError
	if errors.As(err, &held) || errors.As(err, &inUse) {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), err)
		return &childExitError{code: exitSecondDaemon}
	}
	return err
}
