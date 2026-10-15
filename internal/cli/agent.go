package cli

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh/agent"

	"github.com/autarquico/supermgmt/internal/config"
)

func usesAgent(adminCredentialRef string) bool {
	return adminCredentialRef == "" || adminCredentialRef == config.DefaultAdminCredentialRef
}

// isLocalMode: the daemon behind the local socket shares this shell's agent
// only in local mode; a server signs with the service's own environment.
func isLocalMode(configFlag string, env []string) bool {
	path := configPath(configFlag, env)
	if !fileExists(path) {
		return true
	}
	result, err := config.Load(path, env)
	return err == nil && result.Config.Instance.Mode == config.ModeLocal
}

// agentProblem says why the ssh-agent this shell shares with the local daemon
// cannot authenticate as a node's admin_user, or "" when it holds keys.
func agentProblem(ctx context.Context, env []string) string {
	socket := envMap(env)["SSH_AUTH_SOCK"]
	if socket == "" {
		return "SSH_AUTH_SOCK is not set: SuperMgmt signs in as admin-user with the keys in your ssh-agent"
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return "your ssh-agent does not answer at SSH_AUTH_SOCK"
	}
	defer func() { _ = conn.Close() }()
	if keys, err := agent.NewClient(conn).List(); err == nil && len(keys) == 0 {
		return "your ssh-agent holds no keys: load the key admin-user accepts with ssh-add"
	}
	return ""
}
