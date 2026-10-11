package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
)

// newServerCmd is `sm server`: the control plane in server mode (spec §2.2),
// the ExecStart of the systemd unit (Appendix A). It serves HTTPS and the admin
// socket until it is stopped, and re-reads the TLS certificate pair on SIGHUP.
func newServerCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Run the SuperMgmt server (the systemd service)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configFlag, _ := cmd.Flags().GetString("config")
			level, _ := cmd.Flags().GetString("log-level")
			file := configPath(configFlag, env)
			cfg, err := loadServerConfig(file, env)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			reload, stopReload := reloadOnHangup(ctx)
			defer stopReload()
			err = daemon.RunServer(ctx, daemon.Options{
				Config: cfg, ConfigFile: file, Log: daemonLogger(cmd, level), Reload: reload,
			})
			return daemonExit(cmd, err)
		},
	}
}

// loadServerConfig reads the configuration of a server. Unlike the local
// daemon, a server never runs on built-in defaults.
func loadServerConfig(file string, env []string) (*config.Config, error) {
	if !fileExists(file) {
		return nil, usageErrorf("no configuration file at %s: a server needs one with instance.mode: server (use --config)", file)
	}
	result, err := config.Load(file, env)
	if err != nil {
		return nil, usageErrorf("configuration %s is invalid: %s", file, joinProblems(configProblems(err)))
	}
	if result.Config.Instance.Mode != config.ModeServer {
		return nil, usageErrorf("%s sets instance.mode to %s: sm server needs server (sm daemon runs local mode)", file, result.Config.Instance.Mode)
	}
	return result.Config, nil
}

// reloadOnHangup turns SIGHUP into signals on the returned channel until ctx
// ends or stop is called.
func reloadOnHangup(ctx context.Context) (<-chan struct{}, func()) {
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	reload := make(chan struct{})
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-hangup:
				select {
				case reload <- struct{}{}:
				case <-ctx.Done():
					return
				case <-done:
					return
				}
			}
		}
	}()
	return reload, func() {
		signal.Stop(hangup)
		close(done)
	}
}
