package runtimes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func TestSetupMetaGrantedOnlyListedUnitVerbPairs(t *testing.T) {
	meta := SetupMeta{Units: []UnitGrant{
		{Unit: "nginx.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}},
		{Unit: "app.service", Verbs: []domain.ServiceVerb{domain.VerbStart, domain.VerbStop}},
	}}
	tests := []struct {
		unit string
		verb domain.ServiceVerb
		want bool
	}{
		{"nginx.service", domain.VerbRestart, true},
		{"nginx.service", domain.VerbStop, false},
		{"app.service", domain.VerbStop, true},
		{"app.service", domain.VerbRestart, false},
		{"other.service", domain.VerbRestart, false},
	}
	for _, tt := range tests {
		if got := meta.Granted(tt.unit, tt.verb); got != tt.want {
			t.Errorf("Granted(%s, %s) = %v, want %v", tt.unit, tt.verb, got, tt.want)
		}
	}
}

// TestSetupMetaWireFormat pins the capability metadata keys of ADR-0009 (f):
// they are persisted in node_capabilities.metadata_json and must not drift.
func TestSetupMetaWireFormat(t *testing.T) {
	meta := SetupMeta{
		SetupVersion: SetupVersion, SystemctlPath: "/usr/bin/systemctl",
		Units:    []UnitGrant{{Unit: "nginx.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}}},
		LogsMode: LogsBroker, DockerAccess: true, DeployRoot: "/srv/supermgmt",
		KeyRef: "secret://ssh/default", KeyVersion: 1, KeyFingerprint: "SHA256:abc",
	}
	got, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"setup_version":2,"systemctl_path":"/usr/bin/systemctl","units":[{"unit":"nginx.service","verbs":["restart"]}],` +
		`"logs_mode":"broker","docker_access":true,"deploy_root":"/srv/supermgmt","key_ref":"secret://ssh/default","key_version":1,"key_fingerprint":"SHA256:abc"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestSetupMetaOmitsAnUnsetDeployRoot(t *testing.T) {
	got, err := json.Marshal(SetupMeta{SetupVersion: SetupVersion})
	if err != nil || strings.Contains(string(got), "deploy_root") {
		t.Errorf("got %s, %v", got, err)
	}
}

// TestComposeSupportedPinsTheShortVersionFormat: the node fixture's CLI prints
// "5.5.1" for `docker compose version --short` and "Docker Compose version
// v5.5.1" for the long form (measured on sm-fixture-node:local).
func TestComposeSupportedPinsTheShortVersionFormat(t *testing.T) {
	tests := []struct {
		output string
		want   bool
	}{
		{"5.5.1\n", true},
		{"5.5.1", true},
		{"v5.5.1", false},
		{"Docker Compose version v5.5.1", false},
		{"5.5.0", false},
		{"5.5.10", false},
		{"2.29.1", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ComposeSupported(tt.output); got != tt.want {
			t.Errorf("ComposeSupported(%q) = %v, want %v", tt.output, got, tt.want)
		}
	}
}
