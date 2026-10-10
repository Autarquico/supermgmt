package config

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

func TestEnvVarNamesAreUniqueAndWellFormed(t *testing.T) {
	wellFormed := regexp.MustCompile(`^SUPERMGMT_[A-Z0-9_]+$`)
	seen := map[string]string{}
	for _, v := range EnvVars() {
		if !wellFormed.MatchString(v.Name) {
			t.Errorf("%s is not a well-formed variable name", v.Name)
		}
		if other, dup := seen[v.Name]; dup {
			t.Errorf("%s generated for both %s and %s", v.Name, other, v.YAMLPath)
		}
		seen[v.Name] = v.YAMLPath
		if slices.Contains(InstallerEnvVars, v.Name) {
			t.Errorf("%s collides with an installer variable", v.Name)
		}
	}
}

func TestEnvVarsFollowYAMLTags(t *testing.T) {
	got := map[string]string{}
	for _, v := range EnvVars() {
		got[v.Name] = v.YAMLPath + " " + v.Type
	}
	want := map[string]string{
		"SUPERMGMT_SERVER_LISTEN":                "server.listen string",
		"SUPERMGMT_SSH_MAX_DIALS_IN_FLIGHT":      "ssh.max_dials_in_flight int",
		"SUPERMGMT_SSH_CONNECT_TIMEOUT":          "ssh.connect_timeout duration",
		"SUPERMGMT_SERVER_TRUSTED_PROXIES":       "server.trusted_proxies list (comma-separated)",
		"SUPERMGMT_SECURITY_ALLOW_SELF_APPROVAL": "security.allow_self_approval bool",
	}
	for name, desc := range want {
		if got[name] != desc {
			t.Errorf("%s = %q, want %q", name, got[name], desc)
		}
	}
	for name := range got {
		if name == "SUPERMGMT_ENVIRONMENTS" || name == "SUPERMGMT_PROVIDERS" {
			t.Errorf("%s: lists of structs must not be overridable", name)
		}
	}
}

func TestDocsListEveryOverride(t *testing.T) {
	doc, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := ReplaceEnvTable(string(doc))
	if err != nil {
		t.Fatal(err)
	}
	if fresh != string(doc) {
		t.Error("docs/configuration.md is stale: run `go generate ./internal/config/`")
	}
}

func TestReplaceEnvTableNeedsMarkers(t *testing.T) {
	if _, err := ReplaceEnvTable("# no markers\n"); err == nil {
		t.Fatal("want error when markers are missing")
	}
}
