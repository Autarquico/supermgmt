package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	defaultAssistantClient = "assistant"
	assistantKeychainEntry = "supermgmt-assistant"
	envAnthropicKey        = "ANTHROPIC_API_KEY"
	// keychainService is the service name the OS credential store files entries
	// under (internal/client/credstore.go); it is only used to print the command
	// that clears one.
	keychainService = "supermgmt"
)

// assistantAPI is the human client's side of `sm assistant`: it reads the
// registration and the jobs, and decides approvals. The model never touches it.
type assistantAPI interface {
	ListMCPClients(ctx context.Context) (wire.Page[wire.MCPClient], error)
	GetJob(ctx context.Context, id domain.ID) (wire.JobDetail, error)
	ListApprovals(ctx context.Context, q wire.PageQuery) (wire.Page[wire.Approval], error)
	Approve(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error)
	Reject(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error)
	GetService(ctx context.Context, id domain.ID) (wire.Service, error)
	GetNode(ctx context.Context, id domain.ID, focus bool) (wire.Node, error)
}

type assistantSession interface {
	Start(ctx context.Context) error
	Send(text string) error
	Events() <-chan assistant.Event
	Close() error
}

// assistantDeps are the seams `sm assistant` runs through.
type assistantDeps struct {
	connect     func(cmd *cobra.Command) (assistantAPI, target, error)
	nativeStore func() (client.CredentialStore, bool)
	executable  func() (string, error)
	newSession  func(assistant.Config) (assistantSession, error)
	interactive func(cmd *cobra.Command) bool
	// claudeAvailable fails with assistant.ErrClaudeNotFound before anything is registered.
	claudeAvailable func() error
	// flushInput drops what the terminal holds of what was typed so far.
	flushInput func(cmd *cobra.Command)
	// termWidth is the width of the output terminal, 0 when it is not one.
	termWidth func(cmd *cobra.Command) int
}

func defaultAssistantDeps(env []string) assistantDeps {
	return assistantDeps{
		connect: func(cmd *cobra.Command) (assistantAPI, target, error) {
			api, where, err := connect(cmd, env)
			if err != nil {
				return nil, target{}, err
			}
			return api, where, nil
		},
		nativeStore: func() (client.CredentialStore, bool) { return client.OpenNativeCredentialStore(runtime.GOOS, env) },
		executable:  os.Executable,
		newSession:  func(cfg assistant.Config) (assistantSession, error) { return assistant.New(cfg) },
		interactive: stdinIsTerminal,
		claudeAvailable: func() error {
			if _, err := exec.LookPath("claude"); err != nil {
				return assistant.ErrClaudeNotFound
			}
			return nil
		},
		flushInput: func(cmd *cobra.Command) {
			if f, ok := cmd.InOrStdin().(*os.File); ok && isTerminal(f) {
				flushTerminalInput(int(f.Fd()))
			}
		},
		termWidth: func(cmd *cobra.Command) int { return terminalWidth(cmd.OutOrStdout()) },
	}
}

type assistantFlags struct{ auth, client string }

func newAssistantCmd(env []string) *cobra.Command {
	return newAssistantCmdWith(env, defaultAssistantDeps(env))
}

func newAssistantCmdWith(env []string, deps assistantDeps) *cobra.Command {
	var f assistantFlags
	cmd := &cobra.Command{
		Use:   "assistant [--auth subscription|api-key] [--client NAME]",
		Short: "Talk to your own Claude Code, limited to SuperMgmt's MCP tools",
		Long: "Start a conversation with the `claude` CLI on this machine. It runs with no built-in tools, only the\n" +
			"MCP tools of SuperMgmt, as the registered MCP client (default name assistant), never as you.\n\n" +
			"The client must exist first: `sm mcp clients add assistant --keychain supermgmt-assistant` (with --https for a\n" +
			"remote profile; a token file replaces the keychain where there is none; a remote profile or another --client\n" +
			"name has an entry of its own, which sm assistant prints). Changes that need approval are\n" +
			"shown to you here as a card read from the API, and only you decide them. /exit or end of input (Ctrl-D)\n" +
			"ends the conversation; a blank line does nothing. Ctrl-C also ends it: a single request cannot be\n" +
			"cancelled, and the conversation is not saved.\n\n" +
			"--auth subscription uses the signed-in claude; --auth api-key runs it with ANTHROPIC_API_KEY from the\n" +
			"environment. Nothing is installed or signed in on your behalf.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runAssistant(cmd, env, deps, f) },
	}
	cmd.Flags().StringVar(&f.auth, "auth", string(assistant.AuthSubscription), "how claude signs in: subscription|api-key")
	cmd.Flags().StringVar(&f.client, "client", defaultAssistantClient, "name of the registered MCP client the assistant acts as")
	return cmd
}

func runAssistant(cmd *cobra.Command, env []string, deps assistantDeps, f assistantFlags) error {
	auth := assistant.Auth(f.auth)
	if auth != assistant.AuthSubscription && auth != assistant.AuthAPIKey {
		return usageErrorf("--auth must be subscription or api-key, not %q", f.auth)
	}
	if auth == assistant.AuthAPIKey && envMap(env)[envAnthropicKey] == "" {
		return usageErrorf("--auth api-key needs %s in the environment", envAnthropicKey)
	}
	if err := deps.claudeAvailable(); err != nil {
		return err
	}
	api, where, err := deps.connect(cmd)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	token := assistantTokenAt(env, deps, f.client, where)
	me, err := requireAssistantClient(ctx, api, f.client, token, where)
	if err != nil {
		return err
	}
	if err := token.exists(ctx, deps, f.client, where.remote != nil); err != nil {
		return err
	}
	exe, err := deps.executable()
	if err != nil {
		return fmt.Errorf("locate the sm executable: %w", err)
	}
	session, err := deps.newSession(assistant.Config{
		Auth: auth, SMBinary: exe, Token: token.location(), Target: assistantTarget(where, env), Env: env,
	})
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	if err := session.Start(ctx); err != nil {
		return err
	}
	lines, inputErr := readLines(cmd.InOrStdin())
	repl := &assistantRepl{
		out: cmd.OutOrStdout(), session: session, lines: lines, inputErr: inputErr, width: deps.termWidth(cmd),
		greeting: assistantGreeting(where, me.Name, auth),
		approver: &approver{
			api: api, out: cmd.OutOrStdout(), lines: lines, assistantID: me.IdentityID, clientName: me.Name,
			instance: instanceLabel(where), interactive: deps.interactive(cmd), discard: func() { deps.flushInput(cmd) },
		},
	}
	return repl.run(ctx)
}

func instanceLabel(where target) string {
	if where.name != "" {
		return "profile " + where.name
	}
	return "the local daemon"
}

func assistantGreeting(where target, client string, auth assistant.Auth) string {
	account := "your claude subscription"
	if auth == assistant.AuthAPIKey {
		account = "your Anthropic API key, billed per use"
	}
	return fmt.Sprintf("assistant on %s (client %s, %s). /exit or Ctrl-D to end.", textsafe.Line(instanceLabel(where)), textsafe.Line(client), account)
}

// assistantTarget names the instance explicitly so the child's `sm mcp`, whose
// environment is filtered, serves the daemon this command is connected to.
func assistantTarget(where target, env []string) assistant.Target {
	if where.name != "" {
		return assistant.Target{Profile: where.name}
	}
	path := configPath(where.configFile, env)
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return assistant.Target{ConfigPath: path}
}

// assistantToken is where one assistant client's token lives on one target:
// the keychain entry when this machine has one, else a file next to the
// configuration. The default client on a local daemon keeps the plain names;
// any other client, and any remote profile, gets a location of its own. The
// suffix is "-p<len>-<profile>" then "-c-<client>": the profile is length-marked
// so no client name can pass for one. Local daemons share the plain location
// (a local profile or --config is not told apart), so one machine holds one
// assistant token per client name.
type assistantToken struct{ keychain, file string }

func tokenSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, s)
}

func assistantTokenAt(env []string, deps assistantDeps, clientName string, where target) assistantToken {
	suffix := ""
	if where.remote != nil && where.name != "" {
		profile := tokenSafe(where.name)
		suffix += fmt.Sprintf("-p%d-%s", len(profile), profile)
	}
	if clientName != defaultAssistantClient {
		suffix += "-c-" + tokenSafe(clientName)
	}
	if _, ok := deps.nativeStore(); ok {
		return assistantToken{keychain: assistantKeychainEntry + suffix}
	}
	return assistantToken{file: filepath.Join(filepath.Dir(localPaths(env).Config), "assistant"+suffix+".token")}
}

func (t assistantToken) location() assistant.TokenLocation {
	return assistant.TokenLocation{Keychain: t.keychain, File: t.file}
}

func (t assistantToken) flag() string {
	if t.keychain != "" {
		return "--keychain " + t.keychain
	}
	return "--token-file " + shellQuoted(t.file)
}

// clear is the command that frees the location. `sm mcp clients remove` revokes
// the client on the server but leaves the token where it was, and `add` refuses
// an occupied location.
func (t assistantToken) clear() string {
	account := mcpKeychainAccount(t.keychain)
	switch {
	case t.keychain == "":
		return "rm -f " + shellQuoted(t.file)
	case runtime.GOOS == "darwin":
		return fmt.Sprintf("security delete-generic-password -s %s -a %s", keychainService, account)
	default:
		return fmt.Sprintf("secret-tool clear service %s account %s", keychainService, account)
	}
}

// replaceSteps are the commands that register the client again from scratch.
func (t assistantToken) replaceSteps(name, add string) string {
	return fmt.Sprintf("  sm mcp clients remove %s\n  %s\n  %s", name, t.clear(), add)
}

func (t assistantToken) exists(ctx context.Context, deps assistantDeps, name string, remote bool) error {
	if t.file != "" {
		if _, err := os.Stat(t.file); err != nil {
			return usageErrorf("no token at %s; remove the client and add it again:\n  sm mcp clients remove %s\n  %s",
				t.file, name, t.addLine(name, remote))
		}
		return nil
	}
	store, ok := deps.nativeStore()
	if !ok {
		return usageErrorf("this machine has no OS keychain")
	}
	if _, err := readKeychainToken(ctx, store, t.keychain); err != nil {
		return usageErrorf("the token of client %s cannot be read (%s); remove the client and add it again:\n%s",
			name, err, t.replaceSteps(name, t.addLine(name, remote)))
	}
	return nil
}

func (t assistantToken) addLine(name string, https bool) string {
	add := "sm mcp clients add " + name + " " + t.flag()
	if https {
		add += " --https"
	}
	return add
}

// requireAssistantClient finds the registered client through the human's
// connection. When it is missing or unusable it explains the command to run.
func requireAssistantClient(ctx context.Context, api assistantAPI, name string, token assistantToken, where target) (wire.MCPClient, error) {
	page, err := api.ListMCPClients(ctx)
	if err != nil {
		return wire.MCPClient{}, err
	}
	remote := where.remote != nil
	add := token.addLine(name, remote)
	for _, c := range page.Items {
		if c.Name != name || c.State == wire.MCPClientDeleted {
			continue
		}
		switch {
		case c.TokenExpiresAt != nil && !c.TokenExpiresAt.After(domain.SystemClock{}.Now()):
			return wire.MCPClient{}, usageErrorf("the token of MCP client %s expired on %s; replace it:\n%s", name, formatTime(*c.TokenExpiresAt), token.replaceSteps(name, add))
		case c.State != wire.MCPClientActive:
			return wire.MCPClient{}, usageErrorf("MCP client %s is not active yet (%s); finish it by running the same command again after its job is approved:\n  %s", name, c.State, add)
		case remote && !c.OverHTTPS:
			return wire.MCPClient{}, usageErrorf("MCP client %s was not added with --https, which a remote target needs; replace it:\n%s", name, token.replaceSteps(name, add))
		}
		return c, nil
	}
	return wire.MCPClient{}, usageErrorf("no MCP client named %s; register it (approval may be needed, then run the same line again):\n  %s", name, add)
}
