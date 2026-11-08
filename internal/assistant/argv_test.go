package assistant

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testConfig(auth Auth) Config {
	return Config{
		Auth:     auth,
		SMBinary: "/opt/sm/bin/sm",
		Token:    TokenLocation{Keychain: "supermgmt-assistant"},
		Target:   Target{Profile: "prod"},
	}
}

func TestClaudeArgs_Subscription(t *testing.T) {
	got := claudeArgs(testConfig(AuthSubscription), "/tmp/x/mcp.json")
	want := []string{
		"-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
		"--tools", "",
		"--strict-mcp-config", "--mcp-config", "/tmp/x/mcp.json",
		"--allowedTools", "mcp__sm",
		"--permission-prompts", "none",
		"--disable-slash-commands",
		"--no-session-persistence",
		"--setting-sources", "",
		"--system-prompt", DefaultSystemPrompt,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("argv =\n%q\nwant\n%q", got, want)
	}
}

func TestClaudeArgs_APIKeyAddsBareOnly(t *testing.T) {
	sub := claudeArgs(testConfig(AuthSubscription), "/m")
	key := claudeArgs(testConfig(AuthAPIKey), "/m")
	if !slices.Equal(key, append(slices.Clone(sub), "--bare")) {
		t.Fatalf("api-key argv = %q, want the subscription argv plus --bare", key)
	}
	if slices.Contains(sub, "--bare") {
		t.Fatal("subscription mode must not pass --bare")
	}
}

func TestClaudeArgs_NeverBypassesPermissions(t *testing.T) {
	for _, auth := range []Auth{AuthSubscription, AuthAPIKey} {
		for _, arg := range claudeArgs(testConfig(auth), "/m") {
			if strings.Contains(arg, "dangerously") || arg == "--permission-mode" || arg == "--safe-mode" {
				t.Fatalf("%s argv contains %q", auth, arg)
			}
		}
	}
}

func TestClaudeArgs_NoSecretInArgv(t *testing.T) {
	cfg := testConfig(AuthAPIKey)
	cfg.Env = []string{"ANTHROPIC_API_KEY=sk-ant-secret"}
	if strings.Contains(strings.Join(claudeArgs(cfg, "/m"), " "), "sk-ant-secret") {
		t.Fatal("the API key reached the argv")
	}
}

func TestSMMCPArgs_TargetIsExplicit(t *testing.T) {
	tests := map[string]struct {
		token  TokenLocation
		target Target
		want   []string
	}{
		"keychain and profile": {TokenLocation{Keychain: "k"}, Target{Profile: "prod"}, []string{"mcp", "--keychain", "k", "--profile", "prod"}},
		"file and config":      {TokenLocation{File: "/c/assistant.token"}, Target{ConfigPath: "/c/config.yaml"}, []string{"mcp", "--token-file", "/c/assistant.token", "--config", "/c/config.yaml"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(AuthSubscription)
			cfg.Token, cfg.Target = tc.token, tc.target
			if got := smMCPArgs(cfg); !slices.Equal(got, tc.want) {
				t.Fatalf("args = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteMCPConfig(t *testing.T) {
	dir := t.TempDir()
	path, err := writeMCPConfig(dir, testConfig(AuthSubscription))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || filepath.Dir(path) != dir {
		t.Fatalf("config mode %v at %s, want 0600 in %s", info.Mode().Perm(), path, dir)
	}
	raw, _ := os.ReadFile(path)
	var doc struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	server := doc.MCPServers["sm"]
	if len(doc.MCPServers) != 1 || server["command"] != "/opt/sm/bin/sm" {
		t.Fatalf("config = %s", raw)
	}
	if _, hasEnv := server["env"]; hasEnv {
		t.Fatal("the server entry must not carry an env block")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := map[string]func(*Config){
		"unknown auth": func(c *Config) { c.Auth = "oauth" },
		"no sm binary": func(c *Config) { c.SMBinary = "" },
		"no token":     func(c *Config) { c.Token = TokenLocation{} },
		"two tokens":   func(c *Config) { c.Token = TokenLocation{Keychain: "k", File: "f"} },
		"no target":    func(c *Config) { c.Target = Target{} },
		"two targets":  func(c *Config) { c.Target = Target{Profile: "p", ConfigPath: "/c"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(AuthSubscription)
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
