package compose

import "testing"

func TestCLIDefaults_EveryRowNamesItsEvidence(t *testing.T) {
	for _, d := range cliDefaults {
		if len(d.Path) == 0 || d.Evidence == "" {
			t.Errorf("row %v needs a path and evidence", d.Path)
		}
	}
}

func TestNormalizeIgnorable(t *testing.T) {
	tests := []struct {
		name  string
		path  []string
		value any
		want  bool
	}{
		{"project name", []string{"name"}, "sm-app-prod", true},
		{"implicit default network", []string{"networks", "default"}, map[string]any{"name": "x_default"}, true},
		{"network name", []string{"networks", "back", "name"}, "x_back", true},
		{"network ipam empty", []string{"networks", "back", "ipam"}, map[string]any{}, true},
		{"network ipam configured", []string{"networks", "back", "ipam"}, map[string]any{"driver": "d"}, false},
		{"volume name", []string{"volumes", "data", "name"}, "x_data", true},
		{"null command", []string{"services", "db", "command"}, nil, true},
		{"set command", []string{"services", "db", "command"}, []any{"sh"}, false},
		{"null entrypoint", []string{"services", "db", "entrypoint"}, nil, true},
		{"default service network", []string{"services", "db", "networks", "default"}, nil, true},
		{"depends_on required true", []string{"services", "api", "depends_on", "db", "required"}, true, true},
		{"depends_on required false", []string{"services", "api", "depends_on", "db", "required"}, false, false},
		{"port mode ingress", []string{"services", "api", "ports", "0", "mode"}, "ingress", true},
		{"port mode host", []string{"services", "api", "ports", "0", "mode"}, "host", false},
		{"privileged is never a default", []string{"services", "api", "privileged"}, true, false},
		{"wrong depth", []string{"services", "api", "name"}, "x", false},
		{"top-level unknown", []string{"configs"}, map[string]any{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeIgnorable(tc.path, tc.value); got != tc.want {
				t.Errorf("normalizeIgnorable(%v, %v) = %v, want %v", tc.path, tc.value, got, tc.want)
			}
		})
	}
}
