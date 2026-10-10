package runtimes

import (
	"encoding/json"
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
		LogsMode: LogsBroker, DockerAccess: true,
		KeyRef: "secret://ssh/default", KeyVersion: 1, KeyFingerprint: "SHA256:abc",
	}
	got, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"setup_version":1,"systemctl_path":"/usr/bin/systemctl","units":[{"unit":"nginx.service","verbs":["restart"]}],` +
		`"logs_mode":"broker","docker_access":true,"key_ref":"secret://ssh/default","key_version":1,"key_fingerprint":"SHA256:abc"}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
