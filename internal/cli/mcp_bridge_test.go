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
)

const bridgeTestToken = "smm_bridgetoken"

// bridgeDaemon is a fake daemon whose /me answers with credential kind.
func bridgeDaemon(t *testing.T, kind domain.CredentialKind) *fakeAPI {
	t.Helper()
	return newFakeAPI(t, router(map[string]http.HandlerFunc{
		"GET " + wire.PathMe: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Me{IdentityID: "id-1", Credential: kind})
		},
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{})
		},
	}))
}

// runBridge executes `sm <args>` with only the mcp command mounted.
func runBridge(f *fakeAPI, deps mcpBridgeDeps, args ...string) result {
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true, Args: noArgs}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("json", false, "")
	root.AddCommand(newMCPCmdWith(f.Env, deps))
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append(append([]string{}, f.Args...), args...))
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
		{"missing keychain entry", &sinkMemCredentials{}, []string{"mcp", "--keychain", "agent"}, "cannot read entry"},
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

func TestBridge_RefusesWhenMCPIsDisabled(t *testing.T) {
	f := bridgeDaemon(t, domain.CredentialMCPToken)
	appendFile(t, f.Args[1], "mcp:\n  enabled: false\n")
	r := runBridge(f, bridgeDeps(nil, nil), "mcp", "--token-file", tokenFileAt(t, bridgeTestToken, 0o600))
	wantBridgeRefused(t, r, "mcp.enabled")
	wantDaemonUntouched(t, f)
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
	store := &sinkMemCredentials{entries: map[string]string{"agent": bridgeTestToken}}
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

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(text); err != nil {
		t.Fatal(err)
	}
}
