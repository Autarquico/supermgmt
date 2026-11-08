package assistant

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
)

var poisoned = []string{
	"HOME=/home/op", "USER=op", "LOGNAME=op", "PATH=/usr/bin:/opt/homebrew/bin", "TMPDIR=/var/tmp",
	"TERM=xterm", "LANG=en_US.UTF-8", "LC_ALL=C", "LC_TIME=es_ES.UTF-8", "TZ=UTC",
	"XDG_CONFIG_HOME=/x/c", "XDG_STATE_HOME=/x/s", "XDG_RUNTIME_DIR=/run/user/1",
	"CLAUDE_CONFIG_DIR=/x/claude", "HTTPS_PROXY=http://proxy:3128", "no_proxy=localhost",
	"SUPERMGMT_CONFIG_DIR=/elsewhere", "SUPERMGMT_NO_AUTOSTART=1", "SUPERMGMT_TOKEN=human",
	"SSH_AUTH_SOCK=/tmp/agent.sock", "ANTHROPIC_BASE_URL=http://evil", "ANTHROPIC_AUTH_TOKEN=t",
	"ANTHROPIC_API_KEY=sk-ant-key", "CLAUDE_CODE_USE_BEDROCK=1", "GITHUB_TOKEN=g", "AWS_SECRET_ACCESS_KEY=a",
	"LD_PRELOAD=/evil.so", "DYLD_INSERT_LIBRARIES=/evil.dylib", "NODE_OPTIONS=--require /evil.js", "malformed",
}

var allowedOnly = []string{
	"CLAUDE_CONFIG_DIR=/x/claude", "HOME=/home/op", "HTTPS_PROXY=http://proxy:3128", "LANG=en_US.UTF-8",
	"LC_ALL=C", "LC_TIME=es_ES.UTF-8", "LOGNAME=op", "PATH=/usr/bin:/opt/homebrew/bin", "TERM=xterm",
	"TMPDIR=/var/tmp", "TZ=UTC", "USER=op", "XDG_CONFIG_HOME=/x/c", "XDG_RUNTIME_DIR=/run/user/1", "XDG_STATE_HOME=/x/s", "no_proxy=localhost",
}

func TestChildEnv_SubscriptionPassesTheAllowlistOnly(t *testing.T) {
	got, err := childEnv(AuthSubscription, poisoned)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, allowedOnly) {
		t.Fatalf("env =\n%q\nwant\n%q", got, allowedOnly)
	}
}

func TestChildEnv_APIKeyPassesTheKeyAndNothingElseExtra(t *testing.T) {
	got, err := childEnv(AuthAPIKey, poisoned)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Sorted(slices.Values(append(slices.Clone(allowedOnly), "ANTHROPIC_API_KEY=sk-ant-key")))
	if !slices.Equal(got, want) {
		t.Fatalf("env =\n%q\nwant\n%q", got, want)
	}
}

func TestChildEnv_APIKeyModeRefusesWithoutKey(t *testing.T) {
	for _, environ := range [][]string{{"HOME=/h"}, {"HOME=/h", "ANTHROPIC_API_KEY="}} {
		if _, err := childEnv(AuthAPIKey, environ); !errors.Is(err, ErrNoAPIKey) {
			t.Fatalf("err = %v, want ErrNoAPIKey", err)
		}
	}
}

// sm mcp in the child must dial the socket sm assistant dials.
func TestChildEnv_ParentAndChildResolveTheSamePaths(t *testing.T) {
	got, err := childEnv(AuthSubscription, poisoned)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(environ []string) config.Paths {
		env := map[string]string{}
		for _, kv := range environ {
			if name, value, ok := strings.Cut(kv, "="); ok {
				env[name] = value
			}
		}
		return config.Resolve("linux", env, "/home/op")
	}
	if parent, child := resolve(poisoned), resolve(got); parent != child {
		t.Fatalf("parent paths %+v differ from child paths %+v", parent, child)
	}
}
