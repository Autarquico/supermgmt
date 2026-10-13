package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/mcp"
	"github.com/autarquico/supermgmt/internal/version"
)

var _ mcp.API = (*client.Client)(nil)

// mcpBridgeDeps are the seams `sm mcp` serves through.
type mcpBridgeDeps struct {
	openNativeStore func() (client.CredentialStore, bool)
	// transport carries the JSON-RPC stream: stdio, unless a test says otherwise.
	transport func() sdk.Transport
}

func defaultMCPBridgeDeps(env []string) mcpBridgeDeps {
	return mcpBridgeDeps{
		openNativeStore: func() (client.CredentialStore, bool) { return client.OpenNativeCredentialStore(runtime.GOOS, env) },
		transport:       func() sdk.Transport { return &sdk.StdioTransport{} },
	}
}

type mcpBridgeFlags struct{ tokenFile, keychain string }

// newMCPCmd is `sm mcp` (spec §24, ADR-0031): the stdio MCP server of the
// local daemon, authenticated as a registered MCP client, never as the human.
func newMCPCmd(env []string) *cobra.Command {
	return newMCPCmdWith(env, defaultMCPBridgeDeps(env))
}

func newMCPCmdWith(env []string, deps mcpBridgeDeps) *cobra.Command {
	var flags mcpBridgeFlags
	cmd := &cobra.Command{
		Use:   "mcp (--token-file FILE | --keychain NAME)",
		Short: "Serve MCP over stdio as a registered MCP client",
		Long: "Serve the Model Context Protocol on stdin and stdout, for an MCP host to launch.\n\n" +
			"The server authenticates with the token that `sm mcp clients add` stored, read from\n" +
			"--token-file or the OS keychain (--keychain), never from arguments or the environment.\n" +
			"Standard output carries only JSON-RPC; diagnostics go to standard error.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runMCPBridge(cmd, env, deps, flags) },
	}
	cmd.Flags().StringVar(&flags.tokenFile, "token-file", "", "file holding the MCP client token (mode 0600, owned by you)")
	cmd.Flags().StringVar(&flags.keychain, "keychain", "", "OS keychain entry holding the MCP client token")
	cmd.AddCommand(newMCPClientsCmd(env))
	return cmd
}

func runMCPBridge(cmd *cobra.Command, env []string, deps mcpBridgeDeps, flags mcpBridgeFlags) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	token, err := bridgeToken(ctx, deps, flags)
	if err != nil {
		return err
	}
	configFlag, _ := cmd.Flags().GetString("config")
	settings, err := bridgeSettings(configFlag, env)
	if err != nil {
		return err
	}
	api, err := newLocalClientWith(env, configFlag, token)
	if err != nil {
		return err
	}
	if err := requireMCPIdentity(ctx, api); err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	server := mcp.NewServer(api, mcp.Options{
		WriteTools: settings.WriteToolsEnabled,
		Version:    version.Info().Version,
		Log:        logger,
	})
	return serveBridge(ctx, server, deps.transport())
}

func bridgeToken(ctx context.Context, deps mcpBridgeDeps, flags mcpBridgeFlags) (audit.Secret, error) {
	switch {
	case (flags.tokenFile == "") == (flags.keychain == ""):
		return "", usageErrorf("give exactly one of --token-file and --keychain")
	case flags.tokenFile != "":
		return readTokenFile(flags.tokenFile, os.Geteuid())
	}
	store, ok := deps.openNativeStore()
	if !ok {
		return "", usageErrorf("--keychain: this machine has no OS keychain; use --token-file")
	}
	return readKeychainToken(ctx, store, flags.keychain)
}

// bridgeSettings is the mcp section of the configuration; a configuration
// that disables MCP refuses the bridge.
func bridgeSettings(configFlag string, env []string) (config.MCP, error) {
	path := configPath(configFlag, env)
	if !fileExists(path) {
		return config.Defaults().MCP, nil
	}
	result, err := config.Load(path, env)
	if err != nil {
		return config.MCP{}, err
	}
	if !result.Config.MCP.Enabled {
		return config.MCP{}, usageErrorf("MCP is disabled (mcp.enabled: false)")
	}
	return result.Config.MCP, nil
}

// requireMCPIdentity refuses any token that is not an MCP client's: a human
// session or API token must never drive the MCP tools.
func requireMCPIdentity(ctx context.Context, api mcp.API) error {
	me, err := api.Me(ctx)
	if err != nil {
		return err
	}
	if me.Credential != domain.CredentialMCPToken {
		return usageErrorf("the token is a %s credential, not an MCP client token; register one with `sm mcp clients add`", me.Credential)
	}
	return nil
}

// serveBridge runs server until the host closes the stream or ctx ends.
func serveBridge(ctx context.Context, server *sdk.Server, transport sdk.Transport) error {
	err := server.Run(ctx, transport)
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
