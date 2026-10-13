package cli

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// mcpClientsDeps are the seams `sm mcp clients add` stores a token through.
type mcpClientsDeps struct {
	openNativeStore func() (client.CredentialStore, bool)
	openFileSink    func(path string) (tokenSink, error)
}

func defaultMCPClientsDeps(env []string) mcpClientsDeps {
	return mcpClientsDeps{
		openNativeStore: func() (client.CredentialStore, bool) { return client.OpenNativeCredentialStore(runtime.GOOS, env) },
		openFileSink: func(path string) (tokenSink, error) {
			sink, err := openFileSink(path)
			if err != nil {
				return nil, err
			}
			return sink, nil
		},
	}
}

// newMCPClientsCmd is `sm mcp clients` (spec §24, ADR-0032); `sm mcp` mounts it.
func newMCPClientsCmd(env []string) *cobra.Command {
	return newMCPClientsCmdWith(env, defaultMCPClientsDeps(env))
}

func newMCPClientsCmdWith(env []string, deps mcpClientsDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clients",
		Short: "List, add and remove MCP clients",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newMCPClientsListCmd(env), newMCPClientsAddCmd(env, deps), newMCPClientsRemoveCmd(env))
	return cmd
}

func newMCPClientsListCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List MCP clients (their tokens are never shown)",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			page, err := api.ListMCPClients(cmd.Context())
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeMCPClients(w, page.Items) })
		},
	}
}

func writeMCPClients(w io.Writer, clients []wire.MCPClient) error {
	rows := make([][]string, len(clients))
	for i, c := range clients {
		rows[i] = []string{string(c.ID), c.Name, string(c.Origin), string(c.State), formatTimePtr(c.TokenExpiresAt)}
	}
	return table(w, []string{"ID", "NAME", "ORIGIN", "STATE", "TOKEN EXPIRES"}, rows)
}

// ---- add ----------------------------------------------------------------------

type mcpAddFlags struct {
	tokenFile, keychain, expires string
}

func newMCPClientsAddCmd(env []string, deps mcpClientsDeps) *cobra.Command {
	var f mcpAddFlags
	cmd := &cobra.Command{
		Use:   "add <name> (--token-file FILE | --keychain NAME)",
		Short: "Register a local MCP client and store its one-time token",
		Long: "Register a local MCP client. When policy requires approval, this prints the job to approve and stops;\n" +
			"run the same command again after `sm approvals approve <job>` to issue the token. The token goes straight\n" +
			"into --token-file (created exclusively, mode 0600) or the OS keychain (--keychain). It is never printed\n" +
			"and cannot be shown again.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			expiry, err := f.validate()
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			return (&mcpAdd{cmd: cmd, api: api, deps: deps, flags: f, expiry: expiry}).run(args[0])
		},
	}
	cmd.Flags().StringVar(&f.tokenFile, "token-file", "", "file that receives the token (must not exist)")
	cmd.Flags().StringVar(&f.keychain, "keychain", "", "OS keychain entry that receives the token (must not exist)")
	cmd.Flags().StringVar(&f.expires, "expires", defaultTokenTTL, "token lifetime, e.g. 90d (at most 365d)")
	return cmd
}

func (f mcpAddFlags) validate() (time.Time, error) {
	if (f.tokenFile == "") == (f.keychain == "") {
		return time.Time{}, usageErrorf("give exactly one of --token-file and --keychain")
	}
	return tokenExpiry(f.expires, "")
}

type mcpAdd struct {
	cmd    *cobra.Command
	api    *client.Client
	deps   mcpClientsDeps
	flags  mcpAddFlags
	expiry time.Time
}

func (a *mcpAdd) run(name string) error {
	existing, found, err := findMCPClient(a.cmd.Context(), a.api, name)
	if err != nil {
		return err
	}
	if !found {
		return a.register(name)
	}
	return a.resume(existing)
}

func (a *mcpAdd) register(name string) error {
	direct, err := a.api.RegisterMCPClient(a.cmd.Context(), wire.RegisterMCPClientRequest{Name: name, Origin: wire.MCPOriginLocal})
	if err != nil {
		return err
	}
	if direct.Applied != nil {
		return a.resume(*direct.Applied)
	}
	if direct.Pending == nil {
		return smerr.New(smerr.CodeInternal, "", "daemon answered neither applied nor pending")
	}
	return emit(a.cmd, direct, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "%s\napprove it with: sm approvals approve %s\nthen run this command again to receive the token\n",
			describeSubmission(*direct.Pending), direct.Pending.Job.ID)
		return err
	})
}

// resume continues a registered client: issue its token if it is waiting for one.
func (a *mcpAdd) resume(c wire.MCPClient) error {
	switch {
	case c.Origin != wire.MCPOriginLocal:
		return usageErrorf("%s is a remote client; it authenticates with OAuth and has no token to store", c.Name)
	case c.State == wire.MCPClientActive:
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
			"%s is already active; its token was issued at %s and is not re-issued. If you do not hold it, remove and add the client again.",
			c.Name, formatTimePtr(c.TokenIssuedAt)))
	case c.State != wire.MCPClientPendingToken:
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("%s is %s and cannot receive a token", c.Name, c.State))
	}
	ctx := a.cmd.Context()
	me, err := a.api.Me(ctx)
	if err != nil {
		return err
	}
	if c.RequestedBy != me.IdentityID {
		return smerr.New(smerr.CodePolicyDenied, smerr.ReasonNotPlanActor,
			fmt.Sprintf("%s was requested by another identity; only the requester can receive its token", c.Name))
	}
	sink, err := a.openSink(ctx)
	if err != nil {
		return err
	}
	issued, err := a.api.IssueMCPToken(ctx, c.ID, wire.IssueMCPTokenRequest{ExpiresAt: a.expiry})
	if err != nil {
		sink.Abandon()
		return err
	}
	location, err := sink.Store(ctx, issued.Token)
	if err != nil {
		return smerr.New(smerr.CodeInternal, "", fmt.Sprintf(
			"the token for %s (%s) was issued but could not be stored: %v; it cannot be shown again — run 'sm mcp clients remove %s' and add it again",
			c.Name, c.ID, err, c.ID))
	}
	return emit(a.cmd, issued.Client, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "stored the token for %s (%s) in %s; it expires %s and cannot be shown again\n",
			c.Name, c.ID, location, formatTimePtr(issued.Client.TokenExpiresAt))
		return err
	})
}

// openSink preflights the destination; nothing is issued if it fails.
func (a *mcpAdd) openSink(ctx context.Context) (tokenSink, error) {
	if a.flags.tokenFile != "" {
		return a.deps.openFileSink(a.flags.tokenFile)
	}
	store, ok := a.deps.openNativeStore()
	if !ok {
		return nil, usageErrorf("--keychain: this machine has no OS keychain; use --token-file")
	}
	return openKeychainSink(ctx, store, a.flags.keychain)
}

// ---- remove -------------------------------------------------------------------

func newMCPClientsRemoveCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name|id>",
		Short: "Remove an MCP client and revoke its token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveMCPClient(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			direct, err := api.DeleteMCPClient(cmd.Context(), id)
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(c wire.MCPClient) string {
				return fmt.Sprintf("removed MCP client %s (%s)", c.Name, c.ID)
			})
		},
	}
}

// resolveMCPClient accepts a client id or an exact client name.
func resolveMCPClient(ctx context.Context, api *client.Client, ref string) (domain.ID, error) {
	if id, err := domain.ParseID(ref); err == nil {
		return id, nil
	}
	c, found, err := findMCPClient(ctx, api, ref)
	if err != nil {
		return "", err
	}
	if !found {
		return "", smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no MCP client named %q", ref))
	}
	return c.ID, nil
}

// findMCPClient returns the live client with this name.
func findMCPClient(ctx context.Context, api *client.Client, name string) (wire.MCPClient, bool, error) {
	page, err := api.ListMCPClients(ctx)
	if err != nil {
		return wire.MCPClient{}, false, err
	}
	for _, c := range page.Items {
		if c.Name == name && c.State != wire.MCPClientDeleted {
			return c, true, nil
		}
	}
	return wire.MCPClient{}, false, nil
}
