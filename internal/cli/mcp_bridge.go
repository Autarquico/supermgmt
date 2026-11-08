package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
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

type mcpBridgeFlags struct{ tokenFile, keychain, profile string }

// newMCPCmd is `sm mcp` (spec §24, ADR-0031): the stdio MCP server of a
// daemon, local or remote, authenticated as a registered MCP client, never as
// the human.
func newMCPCmd(env []string) *cobra.Command {
	return newMCPCmdWith(env, defaultMCPBridgeDeps(env))
}

func newMCPCmdWith(env []string, deps mcpBridgeDeps) *cobra.Command {
	var flags mcpBridgeFlags
	cmd := &cobra.Command{
		Use:   "mcp (--token-file FILE | --keychain NAME) [--profile NAME]",
		Short: "Serve MCP over stdio as a registered MCP client",
		Long: "Serve the Model Context Protocol on stdin and stdout, for an MCP host to launch.\n\n" +
			"The server authenticates with the token that `sm mcp clients add` stored, read from\n" +
			"--token-file or the OS keychain (--keychain), never from arguments or the environment.\n" +
			"It talks to the local daemon, or to the server of --profile (or of the current profile);\n" +
			"a server accepts the token only if the client was added with --https. The profile's own\n" +
			"sign-in is never used. The chosen target is printed once on standard error.\n" +
			"Standard output carries only JSON-RPC; diagnostics go to standard error.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runMCPBridge(cmd, env, deps, flags) },
	}
	cmd.Flags().StringVar(&flags.tokenFile, "token-file", "", "file holding the MCP client token (mode 0600, owned by you)")
	cmd.Flags().StringVar(&flags.keychain, "keychain", "", "OS keychain entry holding the MCP client token")
	cmd.Flags().StringVar(&flags.profile, "profile", "", "profile of the server to serve (default: the current profile; exclusive with --config)")
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
	where, err := bridgeTarget(cmd, env, flags.profile)
	if err != nil {
		return err
	}
	api, err := bridgeClient(env, where, token)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "sm mcp: serving %s\n", where.describe())
	me, err := requireMCPIdentity(ctx, api)
	if err != nil {
		return explainBridgeRefusal(err, where)
	}
	logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	server := mcp.NewServer(api, mcp.Options{
		WriteTools: me.MCP != nil && me.MCP.WriteToolsEnabled,
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

// bridgeTarget is resolveTarget plus --profile, which names a profile
// explicitly and never combines with --config.
func bridgeTarget(cmd *cobra.Command, env []string, profileFlag string) (target, error) {
	if profileFlag == "" {
		return resolveTarget(cmd, env)
	}
	if configFlag, _ := cmd.Flags().GetString("config"); configFlag != "" {
		return target{}, usageErrorf("--profile and --config are mutually exclusive")
	}
	profiles, err := client.LoadProfiles(profilesFile(env))
	if err != nil {
		return target{}, err
	}
	profile, ok := profiles.Profiles[profileFlag]
	if !ok {
		return target{}, usageErrorf("--profile: no profile named %q", profileFlag)
	}
	return targetOf(profileFlag, profile), nil
}

// bridgeClient dials where with the MCP token as the only credential. A
// remote target never touches the credential store, so the human's sign-in
// cannot be sent, and never autostarts anything.
func bridgeClient(env []string, where target, token audit.Secret) (*client.Client, error) {
	if where.remote == nil {
		return newLocalClientWith(env, where.configFile, token)
	}
	return client.NewRemote(client.Remote{URL: where.remote.URL, CAFile: where.remote.CAFile, Token: token.Reveal()}, client.Options{})
}

// explainBridgeRefusal turns the daemon's bare "unauthenticated" into what the
// operator can act on.
func explainBridgeRefusal(err error, where target) error {
	var e *smerr.Error
	if !errors.As(err, &e) || e.Code != smerr.CodeUnauthenticated {
		return err
	}
	if e.Reason == smerr.ReasonMCPDisabled {
		return usageErrorf("MCP is disabled on this instance (mcp.enabled: false)")
	}
	if where.remote == nil {
		return err
	}
	return usageErrorf("the server did not accept the MCP token (%s); it may be revoked or expired, "+
		"the client may not have been added with --https, or the server may have MCP or mcp.token_over_https off", e.Message)
}

// requireMCPIdentity refuses any token that is not an MCP client's: a human
// session or API token must never drive the MCP tools.
func requireMCPIdentity(ctx context.Context, api mcp.API) (wire.Me, error) {
	me, err := api.Me(ctx)
	if err != nil {
		return wire.Me{}, err
	}
	if me.Credential != domain.CredentialMCPToken {
		return wire.Me{}, usageErrorf("the token is a %s credential, not an MCP client token; register one with `sm mcp clients add`", me.Credential)
	}
	return me, nil
}

// serveBridge runs server until the host closes the stream or ctx ends.
func serveBridge(ctx context.Context, server *sdk.Server, transport sdk.Transport) error {
	err := server.Run(ctx, transport)
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
