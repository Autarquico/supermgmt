package assistant

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// claudeArgs is the argument vector of the child: the security boundary of
// the assistant. No built-in tool (--tools ""), one MCP server, only its tools
// pre-approved, nothing that would prompt is allowed, no slash commands, no
// saved session. --setting-sources "" drops the operator's user settings,
// hooks and CLAUDE.md; --safe-mode is not used because it also drops
// --mcp-config (recorded run, claude 2.1.311).
func claudeArgs(cfg Config, mcpConfigPath string) []string {
	prompt := cfg.SystemPrompt
	if prompt == "" {
		prompt = DefaultSystemPrompt
	}
	args := []string{
		"-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
		"--tools", "",
		"--strict-mcp-config", "--mcp-config", mcpConfigPath,
		"--allowedTools", "mcp__" + mcpServerName,
		"--permission-prompts", "none",
		"--disable-slash-commands",
		"--no-session-persistence",
		"--setting-sources", "",
		"--system-prompt", prompt,
	}
	if cfg.Auth == AuthAPIKey {
		args = append(args, "--bare")
	}
	return args
}

// smMCPArgs is `sm mcp` with the token location and the target spelled out,
// because the child's environment no longer says which instance is meant.
func smMCPArgs(cfg Config) []string {
	args := []string{"mcp"}
	if cfg.Token.Keychain != "" {
		args = append(args, "--keychain", cfg.Token.Keychain)
	} else {
		args = append(args, "--token-file", cfg.Token.File)
	}
	if cfg.Target.Profile != "" {
		return append(args, "--profile", cfg.Target.Profile)
	}
	return append(args, "--config", cfg.Target.ConfigPath)
}

type mcpServerEntry struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// writeMCPConfig writes the child's MCP configuration with mode 0600. It holds
// the sm path and the token location, never a token and never an env block.
func writeMCPConfig(dir string, cfg Config) (string, error) {
	doc := map[string]map[string]mcpServerEntry{"mcpServers": {
		mcpServerName: {Type: "stdio", Command: cfg.SMBinary, Args: smMCPArgs(cfg)},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("assistant: encode mcp config: %w", err)
	}
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", fmt.Errorf("assistant: write mcp config: %w", err)
	}
	return path, nil
}
