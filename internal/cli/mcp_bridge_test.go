package cli

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const bridgeTestToken = "smm_bridgetoken"

func meOf(kind domain.CredentialKind, writeTools bool) wire.Me {
	me := wire.Me{IdentityID: "id-1", Credential: kind}
	if kind == domain.CredentialMCPToken {
		me.MCP = &wire.MeMCP{WriteToolsEnabled: writeTools}
	}
	return me
}

// bridgeDaemon is a fake daemon whose /me answers with credential kind.
func bridgeDaemon(t *testing.T, kind domain.CredentialKind) *fakeAPI {
	t.Helper()
	return bridgeDaemonWith(t, meOf(kind, false))
}

func bridgeDaemonWith(t *testing.T, me wire.Me) *fakeAPI {
	t.Helper()
	return newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathMe: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, me) },
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{})
		},
	}))
}

// runBridge executes `sm <args>` with only the mcp command mounted.
func runBridge(f *fakeAPI, deps mcpBridgeDeps, args ...string) result {
	return runBridgeWith(f.Env, append(append([]string{}, f.Args...), args...), deps)
}

// runBridgeWith executes `sm <args>` in env, with only the mcp command mounted.
func runBridgeWith(env, args []string, deps mcpBridgeDeps) result {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true, Args: noArgs}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("json", false, "")
	root.AddCommand(newMCPCmdWith(env, deps))
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	if err != nil {
		reportError(&errOut, err, false)
	}
	return result{exitCode(err), out.String(), errOut.String()}
}

func bridgeDeps(store client.CredentialStore, transport sdk.Transport) mcpBridgeDeps {
	return mcpBridgeDeps{
		openNativeStore: func() (client.CredentialStore, bool) { return store, store != nil },
		transport:       func() sdk.Transport { return transport },
	}
}

func wantBridgeRefused(t *testing.T, r result, wantMessage string) {
	t.Helper()
	if r.code != 2 {
		t.Errorf("exit code = %d, want 2 (stderr %q)", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, wantMessage) {
		t.Errorf("stderr %q does not mention %q", r.stderr, wantMessage)
	}
	if strings.Contains(r.stderr+r.stdout, bridgeTestToken) {
		t.Errorf("output leaks the token: %q %q", r.stdout, r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("stdout = %q, want nothing", r.stdout)
	}
}

func wantDaemonUntouched(t *testing.T, f *fakeAPI) {
	t.Helper()
	if reqs := f.Requests(); len(reqs) != 0 {
		t.Errorf("the daemon was contacted: %v", reqs)
	}
}

func TestBridge_RefusesWithoutToken(t *testing.T) {
	f := bridgeDaemon(t, domain.CredentialMCPToken)
	tests := []struct {
		name  string
		store client.CredentialStore
		args  []string
		want  string
	}{
		{"no source", nil, []string{"mcp"}, "exactly one"},
		{"both sources", nil, []string{"mcp", "--token-file", "x", "--keychain", "y"}, "exactly one"},
		{"no keychain on this machine", nil, []string{"mcp", "--keychain", "agent"}, "no OS keychain"},
		{"missing keychain entry", &sinkMemCredentials{}, []string{"mcp", "--keychain", "agent"}, "entries created before this version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantBridgeRefused(t, runBridge(f, bridgeDeps(tt.store, nil), tt.args...), tt.want)
		})
	}
	wantDaemonUntouched(t, f)
}

func TestBridge_RefusesUnsafeTokenFiles(t *testing.T) {
	f := bridgeDaemon(t, domain.CredentialMCPToken)
	loose := tokenFileAt(t, bridgeTestToken, 0o644)
	target := tokenFileAt(t, bridgeTestToken, 0o600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"loose permissions": loose, "symlink": link} {
		t.Run(name, func(t *testing.T) {
			wantBridgeRefused(t, runBridge(f, bridgeDeps(nil, nil), "mcp", "--token-file", path), "--token-file")
		})
	}
	wantDaemonUntouched(t, f)
}

func TestBridge_ExplainsWhenMCPIsDisabled(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathMe: func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, http.StatusUnauthorized, smerr.CodeUnauthenticated, smerr.ReasonMCPDisabled, "mcp is disabled")
		},
	}))
	r := runBridge(f, bridgeDeps(nil, nil), "mcp", "--token-file", tokenFileAt(t, bridgeTestToken, 0o600))
	wantBridgeRefused(t, r, "mcp.enabled: false")
}

func TestBridge_RefusesNonMCPIdentity(t *testing.T) {
	for _, kind := range []domain.CredentialKind{domain.CredentialSession, domain.CredentialAPIToken, domain.CredentialLocalSocket} {
		t.Run(string(kind), func(t *testing.T) {
			f := bridgeDaemon(t, kind)
			r := runBridge(f, bridgeDeps(nil, nil), "mcp", "--token-file", tokenFileAt(t, bridgeTestToken, 0o600))
			wantBridgeRefused(t, r, "not an MCP client token")
			if reqs := f.Requests(); len(reqs) != 1 || reqs[0].Path != wire.PathMe {
				t.Errorf("requests = %v, want only /me", reqs)
			}
		})
	}
}

func TestBridge_ServesTheMCPToolsToAHost(t *testing.T) {
	f := bridgeDaemon(t, domain.CredentialMCPToken)
	serverSide, clientSide := sdk.NewInMemoryTransports()
	path := tokenFileAt(t, bridgeTestToken+"\n", 0o600)

	done := make(chan result, 1)
	go func() { done <- runBridge(f, bridgeDeps(nil, serverSide), "mcp", "--token-file", path) }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := sdk.NewClient(&sdk.Implementation{Name: "test-host", Version: "1"}, nil).Connect(ctx, clientSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasTool(tools.Tools, "infra_list_nodes") {
		t.Errorf("infra_list_nodes missing from %d tools", len(tools.Tools))
	}
	if hasTool(tools.Tools, "infra_restart_service") {
		t.Error("write tools are registered although mcp.write_tools_enabled is false")
	}
	called, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "infra_list_nodes"})
	if err != nil || called.IsError {
		t.Fatalf("infra_list_nodes: err=%v result=%+v", err, called)
	}
	_ = session.Close()

	r := <-done
	if r.code != 0 {
		t.Errorf("exit code = %d, stderr %q", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("stdout = %q: only the JSON-RPC stream may use it", r.stdout)
	}
	reqs := f.Requests()
	if len(reqs) < 2 {
		t.Errorf("requests = %v, want /me and /nodes", reqs)
	}
	for _, req := range reqs {
		if got := req.Header.Get("Authorization"); got != "Bearer "+bridgeTestToken {
			t.Errorf("%s %s sent Authorization %q", req.Method, req.Path, got)
		}
	}
}

func TestBridge_ReadsTheTokenFromTheKeychain(t *testing.T) {
	f := bridgeDaemon(t, domain.CredentialMCPToken)
	serverSide, clientSide := sdk.NewInMemoryTransports()
	store := &sinkMemCredentials{entries: map[string]string{"mcp/agent": bridgeTestToken}}
	done := make(chan result, 1)
	go func() { done <- runBridge(f, bridgeDeps(store, serverSide), "mcp", "--keychain", "agent") }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := sdk.NewClient(&sdk.Implementation{Name: "test-host", Version: "1"}, nil).Connect(ctx, clientSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = session.Close()
	if r := <-done; r.code != 0 {
		t.Errorf("exit code = %d, stderr %q", r.code, r.stderr)
	}
	if reqs := f.Requests(); len(reqs) == 0 || reqs[0].Header.Get("Authorization") != "Bearer "+bridgeTestToken {
		t.Errorf("requests = %v", reqs)
	}
}

func TestBridge_MountsTheClientsCommand(t *testing.T) {
	f := newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathMCPClients: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.MCPClient]{})
		},
	}))
	r := runBridge(f, bridgeDeps(nil, nil), "mcp", "clients", "list")
	if r.code != 0 {
		t.Fatalf("exit code = %d, stderr %q", r.code, r.stderr)
	}
}

func hasTool(tools []*sdk.Tool, name string) bool {
	for _, tool := range tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func TestBridge_TheKeychainEntryIsNamespacedAwayFromProfileCredentials(t *testing.T) {
	f := bridgeDaemon(t, domain.CredentialMCPToken)
	store := &sinkMemCredentials{entries: map[string]string{"ops": "smt_humancredential"}}
	r := runBridge(f, bridgeDeps(store, nil), "mcp", "--keychain", "ops")
	wantBridgeRefused(t, r, "sm mcp clients remove ops")
	wantDaemonUntouched(t, f)
}

func TestBridge_TakesTheWriteFlagFromTheWire(t *testing.T) {
	for _, writes := range []bool{false, true} {
		f := bridgeDaemonWith(t, meOf(domain.CredentialMCPToken, writes))
		serverSide, clientSide := sdk.NewInMemoryTransports()
		path := tokenFileAt(t, bridgeTestToken, 0o600)
		done := make(chan result, 1)
		go func() { done <- runBridge(f, bridgeDeps(nil, serverSide), "mcp", "--token-file", path) }()

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		session, err := sdk.NewClient(&sdk.Implementation{Name: "test-host", Version: "1"}, nil).Connect(ctx, clientSide, nil)
		if err != nil {
			t.Fatal(err)
		}
		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := hasTool(tools.Tools, "infra_restart_service"); got != writes {
			t.Errorf("write_tools_enabled=%v but the write tool is registered=%v", writes, got)
		}
		_ = session.Close()
		cancel()
		if r := <-done; r.code != 0 {
			t.Errorf("exit code = %d, stderr %q", r.code, r.stderr)
		}
	}
}

// remoteBridge is a profile "ops" pointing at a fake HTTPS server, plus a
// human credential for that profile that the bridge must never send.
type remoteBridge struct {
	*remoteBox
	token string
}

const humanCredential = "smt_humancredentialhumancredentialhumancred"

func newRemoteBridge(t *testing.T, writes bool) remoteBridge {
	t.Helper()
	b := newRemoteBox(t, routes{
		"GET " + wire.PathMe: func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+bridgeTestToken {
				replyError(w, http.StatusUnauthorized, smerr.CodeUnauthenticated, "", "invalid credential")
				return
			}
			reply(w, 200, meOf(domain.CredentialMCPToken, writes))
		},
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, wire.Page[wire.Node]{}) },
	})
	if r := b.run("", "profile", "add", "ops", "--url", b.srv.URL, "--ca-file", b.caFile, "--use"); r.code != 0 {
		t.Fatalf("profile add: %d %s", r.code, r.stderr)
	}
	if _, err := credentialStore(b.env).Set(context.Background(), "ops", humanCredential); err != nil {
		t.Fatal(err)
	}
	return remoteBridge{remoteBox: b, token: tokenFileAt(t, bridgeTestToken, 0o600)}
}

func (b remoteBridge) serve(t *testing.T, writes bool, args ...string) (result, *sdk.ClientSession) {
	t.Helper()
	serverSide, clientSide := sdk.NewInMemoryTransports()
	done := make(chan result, 1)
	go func() { done <- runBridgeWith(b.env, append([]string{"mcp"}, args...), bridgeDeps(nil, serverSide)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	session, err := sdk.NewClient(&sdk.Implementation{Name: "test-host", Version: "1"}, nil).Connect(ctx, clientSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hasTool(tools.Tools, "infra_restart_service"); got != writes {
		t.Errorf("write tool registered=%v, want %v", got, writes)
	}
	_ = session.Close()
	return <-done, session
}

func TestBridge_RemoteTargetSendsOnlyTheMCPToken(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"current profile", nil},
		{"explicit profile", []string{"--profile", "ops"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newRemoteBridge(t, true)
			r, _ := b.serve(t, true, append([]string{"--token-file", b.token}, tt.args...)...)
			if r.code != 0 {
				t.Fatalf("exit code = %d, stderr %q", r.code, r.stderr)
			}
			if !strings.Contains(r.stderr, "profile ops ("+b.srv.URL+")") {
				t.Errorf("stderr %q does not name the target", r.stderr)
			}
			reqs := b.requests()
			if len(reqs) == 0 {
				t.Fatal("the server saw no request")
			}
			for _, req := range reqs {
				if got := req.Header.Get("Authorization"); got != "Bearer "+bridgeTestToken {
					t.Errorf("%s %s sent Authorization %q", req.Method, req.Path, got)
				}
			}
		})
	}
}

func TestBridge_ProfileSelection(t *testing.T) {
	b := newRemoteBridge(t, false)
	if r := b.run("", "profile", "add", "other", "--url", b.srv.URL, "--ca-file", b.caFile); r.code != 0 {
		t.Fatal(r.stderr)
	}
	local := runBridgeWith(b.env, []string{"mcp", "--token-file", b.token, "--profile", "nope"}, bridgeDeps(nil, nil))
	wantBridgeRefused(t, local, `no profile named "nope"`)

	both := runBridgeWith(b.env, []string{"--config", "/nonexistent.yaml", "mcp", "--token-file", b.token, "--profile", "ops"}, bridgeDeps(nil, nil))
	wantBridgeRefused(t, both, "mutually exclusive")
	if reqs := b.requests(); len(reqs) != 0 {
		t.Errorf("the server was contacted: %v", reqs)
	}

	r, _ := b.serve(t, false, "--token-file", b.token, "--profile", "other")
	if r.code != 0 || !strings.Contains(r.stderr, "profile other (") {
		t.Errorf("exit=%d stderr=%q: --profile must win over the current profile", r.code, r.stderr)
	}
}

func TestBridge_RemoteRefusalsNameTheLikelyCauses(t *testing.T) {
	b := newRemoteBridge(t, false)
	wrong := tokenFileAt(t, "smm_notregistered", 0o600)
	r := runBridgeWith(b.env, []string{"mcp", "--token-file", wrong}, bridgeDeps(nil, nil))
	wantBridgeRefused(t, r, "--https")
	for _, req := range b.requests() {
		if strings.Contains(req.Header.Get("Authorization"), humanCredential) {
			t.Error("the human credential was sent")
		}
	}
}

func TestBridge_RemoteHumanTokenAsMCPTokenIsRefusedAfterMe(t *testing.T) {
	b := newRemoteBox(t, routes{
		"GET " + wire.PathMe: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, meOf(domain.CredentialAPIToken, false))
		},
	})
	if r := b.run("", "profile", "add", "ops", "--url", b.srv.URL, "--ca-file", b.caFile, "--use"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	r := runBridgeWith(b.env, []string{"mcp", "--token-file", tokenFileAt(t, bridgeTestToken, 0o600)}, bridgeDeps(nil, nil))
	wantBridgeRefused(t, r, "not an MCP client token")
}
