package specexamples

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/cli"
)

type mcpHostConfig struct {
	MCPServers map[string]mcpHostServer `json:"mcpServers"`
}

type mcpHostServer struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
}

func loadMCPExample(t *testing.T, name string) mcpHostServer {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "examples", "mcp", name))
	if err != nil {
		t.Fatal(err)
	}
	var cfg mcpHostConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	server, ok := cfg.MCPServers["supermgmt"]
	if !ok || len(cfg.MCPServers) != 1 {
		t.Fatalf("%s: want exactly one server named supermgmt, got %v", name, cfg.MCPServers)
	}
	return server
}

func TestMCPExamples_StdioHostsLaunchSmMcpWithRealFlags(t *testing.T) {
	for _, name := range []string{"claude-desktop.json", "claude-code.json"} {
		t.Run(name, func(t *testing.T) {
			server := loadMCPExample(t, name)
			if server.Command != "sm" {
				t.Fatalf("command = %q, want sm", server.Command)
			}
			var stdout, stderr bytes.Buffer
			args := append(append([]string{}, server.Args...), "--help")
			if code := cli.Execute(args, &stdout, &stderr); code != 0 {
				t.Fatalf("sm %v: exit %d: %s", server.Args, code, stderr.String())
			}
		})
	}
}

func TestMCPExamples_RemoteNamesTheMCPResourceOfAnOrigin(t *testing.T) {
	server := loadMCPExample(t, "remote.json")
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host == "" || u.Path != wire.MCPPath || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		t.Fatalf("url = %q, want https://<origin>%s", server.URL, wire.MCPPath)
	}
	if server.Command != "" || len(server.Args) != 0 {
		t.Errorf("a remote server launches nothing, got %q %v", server.Command, server.Args)
	}
}
