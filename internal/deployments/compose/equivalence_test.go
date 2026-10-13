package compose

import (
	"reflect"
	"strings"
	"testing"
)

const equivalenceExpected = `{
  "services": {
    "api": {
      "command": ["run", "$$x"],
      "environment": {"A": "sha256:aaa", "S": "sha256:bbb"},
      "image": "ghcr.io/acme/api@sha256:1",
      "ports": [{"host_ip": "127.0.0.1", "protocol": "tcp", "published": "8080", "target": 80}]
    },
    "db": {"image": "docker.io/library/redis@sha256:2", "volumes": [{"type": "volume", "source": "data", "target": "/d"}]}
  },
  "volumes": {"data": {"labels": {"dev.supermgmt.owner": "o1"}}}
}`

// equivalenceCLI is the model the pinned CLI (v5.5.1) prints for the expected
// one: identical, since the loader's model already carries every field the CLI
// adds.
const equivalenceCLI = equivalenceExpected

func equivalenceDiffsOf(t *testing.T, expected, cli string) []string {
	t.Helper()
	diffs, err := Equivalent([]byte(expected), []byte(cli))
	if err != nil {
		t.Fatal(err)
	}
	return diffs
}

func TestEquivalent_IdenticalModelsAreEquivalent(t *testing.T) {
	if diffs := equivalenceDiffsOf(t, equivalenceExpected, equivalenceCLI); len(diffs) != 0 {
		t.Errorf("diffs = %v, want none", diffs)
	}
}

func TestEquivalent_KeyOrderDoesNotMatter(t *testing.T) {
	reordered := `{"volumes": {"data": {"labels": {"dev.supermgmt.owner": "o1"}}}, "services": {"db": {"volumes": [{"target": "/d", "source": "data", "type": "volume"}], "image": "docker.io/library/redis@sha256:2"}, "api": {"image": "ghcr.io/acme/api@sha256:1", "environment": {"S": "sha256:bbb", "A": "sha256:aaa"}, "command": ["run", "$$x"], "ports": [{"target": 80, "published": "8080", "protocol": "tcp", "host_ip": "127.0.0.1"}]}}}`
	if diffs := equivalenceDiffsOf(t, equivalenceExpected, reordered); len(diffs) != 0 {
		t.Errorf("diffs = %v, want none", diffs)
	}
}

func TestEquivalent_DetectsChangedEnvironmentValueWithoutExposingIt(t *testing.T) {
	const leaked = "deadbeefcafe"
	tampered := strings.Replace(equivalenceCLI, `"A": "sha256:aaa"`, `"A": "sha256:`+leaked+`"`, 1)

	diffs := equivalenceDiffsOf(t, equivalenceExpected, tampered)

	want := []string{"services.api.environment.A: differs"}
	if !reflect.DeepEqual(diffs, want) {
		t.Errorf("diffs = %v, want %v", diffs, want)
	}
	for _, d := range diffs {
		if strings.Contains(d, leaked) || strings.Contains(d, "aaa") {
			t.Errorf("diff exposes a value: %q", d)
		}
	}
}

func TestEquivalent_Differences(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		want []string
	}{
		{"extra environment name", func(s string) string {
			return strings.Replace(s, `"S": "sha256:bbb"`, `"S": "sha256:bbb", "X": "sha256:c"`, 1)
		}, []string{"services.api.environment.X: unexpected in node output"}},
		{"missing environment name", func(s string) string {
			return strings.Replace(s, `, "S": "sha256:bbb"`, ``, 1)
		}, []string{"services.api.environment.S: missing from node output"}},
		{"smuggled privileged", func(s string) string {
			return strings.Replace(s, `"image": "ghcr.io/acme/api@sha256:1",`, `"image": "ghcr.io/acme/api@sha256:1", "privileged": true,`, 1)
		}, []string{"services.api.privileged: unexpected in node output"}},
		{
			"command changed", func(s string) string { return strings.Replace(s, `"run"`, `"walk"`, 1) },
			[]string{"services.api.command.0: differs"},
		},
		{
			"command longer", func(s string) string { return strings.Replace(s, `["run", "$$x"]`, `["run", "$$x", "y"]`, 1) },
			[]string{"services.api.command: length differs"},
		},
		{
			"port published changed", func(s string) string { return strings.Replace(s, `"8080"`, `"9090"`, 1) },
			[]string{"services.api.ports.0.published: differs"},
		},
		{
			"image changed", func(s string) string { return strings.Replace(s, `redis@sha256:2`, `redis@sha256:3`, 1) },
			[]string{"services.db.image: differs"},
		},
		{
			"type changed", func(s string) string { return strings.Replace(s, `"target": 80`, `"target": "80"`, 1) },
			[]string{"services.api.ports.0.target: differs"},
		},
		{"service dropped", func(s string) string {
			return strings.Replace(s, `"db": {"image": "docker.io/library/redis@sha256:2", "volumes": [{"type": "volume", "source": "data", "target": "/d"}]}`, `"x": {}`, 1)
		}, []string{"services.db: missing from node output", "services.x: unexpected in node output"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := equivalenceDiffsOf(t, equivalenceExpected, tc.edit(equivalenceCLI))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("diffs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEquivalent_CLIOmitsNetworksAndVolumesNoServiceUses(t *testing.T) {
	expected := strings.Replace(equivalenceExpected, `"volumes": {"data": {`,
		`"networks": {"idle": {"name": "p_idle"}}, "volumes": {"idle": {}, "data": {`, 1)

	if diffs := equivalenceDiffsOf(t, expected, equivalenceCLI); len(diffs) != 0 {
		t.Errorf("diffs = %v, want none", diffs)
	}
}

func TestEquivalent_ACLIOnlyNetworkIsNamed(t *testing.T) {
	cli := strings.Replace(equivalenceCLI, `"services"`, `"networks": {"extra": {"driver": "host"}}, "services"`, 1)

	got := equivalenceDiffsOf(t, equivalenceExpected, cli)

	want := []string{"networks.extra.driver: unexpected in node output"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diffs = %v, want %v", got, want)
	}
}

func TestEquivalent_RejectsUnreadableInput(t *testing.T) {
	tests := map[string][2]string{
		"expected not JSON":    {`nope`, `{}`},
		"cli not JSON":         {`{}`, `nope`},
		"cli not an object":    {`{}`, `[1]`},
		"expected not object":  {`"x"`, `{}`},
		"trailing data":        {`{}`, `{} {}`},
		"cli empty":            {`{}`, ``},
		"expected empty bytes": {``, `{}`},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Equivalent([]byte(in[0]), []byte(in[1])); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestEquivalent_EmptyModelsAreEquivalent(t *testing.T) {
	if diffs := equivalenceDiffsOf(t, `{}`, `{}`); len(diffs) != 0 {
		t.Errorf("diffs = %v", diffs)
	}
}
