package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	localDoc  = "version: 1\ninstance:\n  mode: local\n"
	serverDoc = "version: 1\ninstance:\n  mode: server\n"
)

func writeConfig(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func load(t *testing.T, doc string, env ...string) (Result, error) {
	t.Helper()
	return Load(writeConfig(t, doc), env)
}

func mustLoad(t *testing.T, doc string, env ...string) Result {
	t.Helper()
	res, err := load(t, doc, env...)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return res
}

func TestLoadSelfApprovalDefaultFollowsMode(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want bool
	}{
		{"local defaults to true", localDoc, true},
		{"server defaults to false", serverDoc, false},
		{"explicit false wins in local", localDoc + "security:\n  allow_self_approval: false\n", false},
		{"explicit true wins in server", serverDoc + "security:\n  allow_self_approval: true\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustLoad(t, tt.doc).Config.Security.AllowSelfApproval
			if got == nil || *got != tt.want {
				t.Errorf("allow_self_approval = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadServerDefaults(t *testing.T) {
	c := mustLoad(t, serverDoc+"server:\n  public_url: https://mgmt.example.com\n").Config
	checks := map[string][2]string{
		"data_dir":      {c.Instance.DataDir, "/var/lib/supermgmt"},
		"sqlite path":   {c.Storage.SQLite.Path, "/var/lib/supermgmt/supermgmt.db"},
		"keys_dir":      {c.Security.KeysDir, "/var/lib/supermgmt/secrets/keys"},
		"known_hosts":   {c.SSH.KnownHostsFile, "/var/lib/supermgmt/known_hosts"},
		"backups":       {c.Backup.Directory, "/var/lib/supermgmt/backups"},
		"backup cron":   {c.Backup.Schedule, "0 3 * * *"},
		"oidc audience": {c.GitHub.OIDCAudience, "https://mgmt.example.com"},
	}
	for name, v := range checks {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", name, v[0], v[1])
		}
	}
}

func TestApplyModeDefaultsLocalUsesUserPaths(t *testing.T) {
	c := Defaults()
	c.Instance.Mode = ModeLocal
	c.applyModeDefaults(Paths{DataDir: "/u/data/supermgmt"})
	if c.Storage.SQLite.Path != "/u/data/supermgmt/supermgmt.db" || c.Security.KeysDir != "/u/data/supermgmt/secrets/keys" {
		t.Errorf("local paths not derived from the user data dir: %+v", c.Storage)
	}
	if c.Backup.Schedule != "" {
		t.Errorf("local mode must not schedule backups by default, got %q", c.Backup.Schedule)
	}
}

func TestApplyModeDefaultsKeepsExplicitValues(t *testing.T) {
	c := Defaults()
	c.Instance.Mode = ModeServer
	c.Instance.DataDir = "/srv/sm"
	c.Storage.SQLite.Path = "/elsewhere.db"
	c.applyModeDefaults(Paths{})
	if c.Storage.SQLite.Path != "/elsewhere.db" || c.Security.KeysDir != "/srv/sm/secrets/keys" {
		t.Errorf("explicit value lost or data_dir ignored: %+v %s", c.Storage, c.Security.KeysDir)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	c := mustLoad(t, serverDoc,
		"SUPERMGMT_SERVER_LISTEN=127.0.0.1:9000",
		"SUPERMGMT_SSH_MAX_DIALS_IN_FLIGHT=32",
		"SUPERMGMT_SSH_CONNECT_TIMEOUT=5s",
		"SUPERMGMT_SERVER_TRUSTED_PROXIES=10.0.0.0/8, 127.0.0.1/32",
		"SUPERMGMT_MCP_WRITE_TOOLS_ENABLED=true",
		"SUPERMGMT_SECURITY_ALLOW_SELF_APPROVAL=true",
	).Config
	if c.Server.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q", c.Server.Listen)
	}
	if c.SSH.MaxDialsInFlight != 32 {
		t.Errorf("max_dials_in_flight = %d", c.SSH.MaxDialsInFlight)
	}
	if c.SSH.ConnectTimeout.String() != "5s" {
		t.Errorf("connect_timeout = %s", c.SSH.ConnectTimeout)
	}
	if want := []string{"10.0.0.0/8", "127.0.0.1/32"}; !slices.Equal(c.Server.TrustedProxies, want) {
		t.Errorf("trusted_proxies = %v, want %v", c.Server.TrustedProxies, want)
	}
	if !c.MCP.WriteToolsEnabled {
		t.Error("write_tools_enabled override not applied")
	}
	if got := c.Security.AllowSelfApproval; got == nil || !*got {
		t.Errorf("allow_self_approval = %v, want true from env", got)
	}
}

func TestLoadEnvOverridesBeatTheFile(t *testing.T) {
	c := mustLoad(t, serverDoc+"server:\n  listen: 127.0.0.1:1\n", "SUPERMGMT_SERVER_LISTEN=127.0.0.1:2").Config
	if c.Server.Listen != "127.0.0.1:2" {
		t.Errorf("listen = %q, env must override the file", c.Server.Listen)
	}
}

func TestLoadEnvModeOverrideSelectsModeDefaults(t *testing.T) {
	c := mustLoad(t, localDoc, "SUPERMGMT_INSTANCE_MODE=server").Config
	if got := c.Security.AllowSelfApproval; got == nil || *got {
		t.Errorf("allow_self_approval = %v, want false once env switches to server", got)
	}
	if c.Instance.DataDir != "/var/lib/supermgmt" {
		t.Errorf("data_dir = %q, want server default", c.Instance.DataDir)
	}
}

func TestLoadEnvOverrideErrors(t *testing.T) {
	tests := []struct{ env, want string }{
		{"SUPERMGMT_SSH_MAX_CONNECTIONS=many", "SUPERMGMT_SSH_MAX_CONNECTIONS"},
		{"SUPERMGMT_SSH_CONNECT_TIMEOUT=soon", "SUPERMGMT_SSH_CONNECT_TIMEOUT"},
		{"SUPERMGMT_MCP_ENABLED=maybe", "SUPERMGMT_MCP_ENABLED"},
	}
	for _, tt := range tests {
		_, err := load(t, localDoc, tt.env)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want error naming the variable", tt.env, err)
		}
	}
}

func TestLoadWarnsAboutUnknownSupermgmtVariables(t *testing.T) {
	res := mustLoad(t, localDoc,
		"SUPERMGMT_SERVER_LISTNE=x",
		"SUPERMGMT_INSTALL_DIR=/opt/sm",
		"SUPERMGMT_VERSION=1.2.3",
		"HOME=/home/u",
		"UNRELATED=1",
	)
	want := []string{"unknown environment variable SUPERMGMT_SERVER_LISTNE ignored"}
	if !slices.Equal(res.Warnings, want) {
		t.Errorf("warnings = %v, want %v", res.Warnings, want)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Run("missing file is NOT_FOUND", func(t *testing.T) {
		_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"), nil)
		if smerr.CodeOf(err) != smerr.CodeNotFound {
			t.Errorf("code = %s, want NOT_FOUND (err: %v)", smerr.CodeOf(err), err)
		}
	})
	t.Run("unknown field names path and file", func(t *testing.T) {
		_, err := load(t, localDoc+"ssh:\n  max_conections: 3\n")
		if err == nil || !strings.Contains(err.Error(), "ssh.max_conections") || !strings.Contains(err.Error(), "config.yaml") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("validation failure is INVALID_ARGUMENT", func(t *testing.T) {
		_, err := load(t, "version: 2\ninstance:\n  mode: local\n")
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("code = %s, want INVALID_ARGUMENT", smerr.CodeOf(err))
		}
	})
}
