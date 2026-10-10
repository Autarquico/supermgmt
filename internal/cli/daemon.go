package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
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
			cfg, err := loadDaemonConfig(configPath(configFlag, env), env)
			if err != nil {
				return err
			}
			if cfg.Instance.Mode != config.ModeLocal {
				return smerr.New(smerr.CodeCapabilityUnavailable, "", "server mode arrives in milestone M2; set instance.mode to local")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			err = daemon.Run(ctx, daemon.Options{
				Config: cfg, Socket: socketPath(cfg, env), Log: daemonLogger(cmd, level),
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
	dir, err := os.MkdirTemp("", "sm-config")
	if err != nil {
		return nil, fmt.Errorf("prepare default configuration: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte(minimalLocalConfig), 0o600); err != nil {
		return nil, fmt.Errorf("prepare default configuration: %w", err)
	}
	result, err := config.Load(file, env)
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
