//go:build e2e && fixtures

package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// TestE2E_MCPHTTPSToken
//
// ADR-0044 and spec mcp-https-token: on a server with mcp.token_over_https, a client registered with
// --https gives a workstation `sm mcp --profile ... --token-file ...`, which lists the tools the
// server allows and reads its graph with that token alone. Removing the client stops the next start.
// A restart waiting for approval is covered by the route matrix, which needs a node and writes on.
func TestE2E_MCPHTTPSToken(t *testing.T) {
	ctx := context.Background()
	network, ca := harness.NewNetwork(t), harness.NewCA(t)
	srv := harness.StartServer(t, network, ca, harness.ServerOptions{Mode: harness.Direct})
	srv.WaitReady(ctx)
	srv.AppendConfig(ctx, "security:\n    allow_self_approval: true\nmcp:\n    token_over_https: true\n    write_tools_enabled: false\n")
	srv.Restart(ctx)

	operator := harness.NewClient(t)
	operator.AddProfile(ctx, "ops", srv.URL, srv.CAFile)
	human := srv.BootstrapAdmin(ctx, operator, "https token operator")
	admin := srv.Typed(human)

	tokenFile := filepath.Join(t.TempDir(), "agent.token")
	registerHTTPSClient(ctx, t, operator, admin, "agent", tokenFile)
	token := strings.TrimSpace(readFile(t, tokenFile))

	t.Run("registering without --https on a server is refused, naming why", func(t *testing.T) {
		res := operator.Run(ctx, "", "mcp", "clients", "add", "stuck", "--token-file", filepath.Join(t.TempDir(), "stuck.token"))
		if res.Code == 0 || !strings.Contains(res.Output(), "usable only over HTTPS") {
			t.Fatalf("add without --https exited %d: %s", res.Code, res.Output())
		}
	})

	t.Run("the bridge lists the tools of a server with writes off and reads its graph", func(t *testing.T) {
		session := httpsBridge(ctx, t, operator, tokenFile)
		names := m5ToolNames(t, session)
		if len(names) == 0 || slices.Contains(names, "infra_submit_plan") {
			t.Fatalf("tools = %v, want the read tools and no infra_submit_plan (the server has writes off)", names)
		}
		var outputs mcpOutputs
		var nodes m5Nodes
		if failure := m5Call(t, &outputs, session, "infra_list_nodes", nil, &nodes); failure != "" {
			t.Fatalf("infra_list_nodes failed: %s", failure)
		}
	})

	t.Run("the tool list follows the server when writes are turned on", func(t *testing.T) {
		srv.C.MustExec(ctx, "sed", "-i", "s/write_tools_enabled: false/write_tools_enabled: true/", harness.ServerConfig)
		srv.Restart(ctx)
		srv.WaitReady(ctx)
		if names := m5ToolNames(t, httpsBridge(ctx, t, operator, tokenFile)); !slices.Contains(names, "infra_submit_plan") {
			t.Fatalf("tools = %v, want infra_submit_plan once the server has writes on", names)
		}
	})

	t.Run("a removed client's token no longer starts the bridge", func(t *testing.T) {
		operator.Must(ctx, "", "mcp", "clients", "remove", "agent")
		res := operator.Run(ctx, "", "mcp", "--profile", "ops", "--token-file", tokenFile)
		if res.Code == 0 {
			t.Fatalf("the bridge started with a revoked token: %s", res.Output())
		}
	})

	t.Run("the token is in neither the database nor the journal", func(t *testing.T) {
		harness.AssertNoPlaintext(t, srv.Evidence(ctx), map[string]string{"the MCP client token": token})
	})
}

// registerHTTPSClient runs `sm mcp clients add --https` as a person does: when registration waits for
// approval, approve the job it names and run the command again.
func registerHTTPSClient(ctx context.Context, t *testing.T, operator *harness.Client, admin *client.Client, name, tokenFile string) {
	t.Helper()
	args := []string{"mcp", "clients", "add", name, "--https", "--token-file", tokenFile}
	res := operator.Must(ctx, "", args...)
	if m := approveHint.FindStringSubmatch(res.Stdout); m != nil {
		harness.ApproveJob(ctx, t, admin, domain.ID(m[1]))
		deadline := harness.Now().Add(time.Minute)
		for harness.Now().Before(deadline) {
			if res = operator.Run(ctx, "", args...); res.Code == 0 {
				break
			}
			time.Sleep(time.Second)
		}
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("no token file after `sm mcp clients add --https`: %v\n%s", err, res.Output())
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %o, want 600", info.Mode().Perm())
	}
}

// httpsBridge launches the real `sm mcp --profile ops` as a host would, with the operator's environment,
// which holds a human session for that same profile that the bridge must not use.
func httpsBridge(ctx context.Context, t *testing.T, operator *harness.Client, tokenFile string) *sdk.ClientSession {
	t.Helper()
	cmd := operator.Command(ctx, "mcp", "--profile", "ops", "--token-file", tokenFile)
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	session, err := sdk.NewClient(&sdk.Implementation{Name: "sm-e2e", Version: "0"}, nil).Connect(ctx, &sdk.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect to `sm mcp --profile ops`: %v\nstderr:\n%s", err, stderr.String())
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
