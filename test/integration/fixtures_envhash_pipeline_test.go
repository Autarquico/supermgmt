//go:build fixtures

package integration

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The resolved-environment check of ADR-0010 through the whole pipeline:
// Freeze and Materialize on the control plane, compose.materialize and
// compose.verify (real templates, over SSH, as the dedicated user) on the
// node, then the comparison the verify step makes. TestEnvFile_* covers the
// value corpus and the spike covers the jq program; this covers the seams.

const envHashProject = "t17b-envhash"

// shadowApiToken puts API_TOKEN into the environment mapping of compose.yaml,
// in front of the DOLLAR entry the materialized file carries.
const shadowApiToken = `s/^\( *\)"DOLLAR":/\1"API_TOKEN": shadow\n\1"DOLLAR":/`

// envHashVerified is one compose.verify run.
type envHashVerified struct {
	raw    string
	stderr string
	result verifyResult
}

func (n *deployNode) verify(t *testing.T, app stagedApp) envHashVerified {
	t.Helper()
	res := n.readTemplate(t, "compose.verify", app.args())
	if res.ExitStatus != 0 {
		t.Fatalf("compose.verify exit %d: %s", res.ExitStatus, stderrOf(res))
	}
	out := envHashVerified{raw: strings.TrimSpace(string(res.Stdout)), stderr: stderrOf(res)}
	if err := json.Unmarshal([]byte(out.raw), &out.result); err != nil {
		t.Fatalf("compose.verify output is not one JSON document: %v\n%s", err, out.raw)
	}
	return out
}

// envHashDiffs compares the control plane's expected hashes with the node's
// report: a missing, extra or different entry is a difference.
func envHashDiffs(expected []compose.EnvHash, reported []envHash) []string {
	want := map[string]string{}
	for _, h := range expected {
		want[h.Service+"/"+h.EnvName] = h.SHA256
	}
	got := map[string]string{}
	for _, h := range reported {
		hash := "null"
		if h.SHA256 != nil {
			hash = *h.SHA256
		}
		got[h.Service+"/"+h.EnvName] = hash
	}
	var diffs []string
	for key, w := range want {
		switch g, ok := got[key]; {
		case !ok:
			diffs = append(diffs, key+": missing on the node")
		case g != w:
			diffs = append(diffs, key+": hash differs")
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			diffs = append(diffs, key+": unexpected on the node")
		}
	}
	slices.Sort(diffs)
	return diffs
}

func TestFixtures_EnvHashThroughThePipeline(t *testing.T) {
	n := startDeployNode(t)
	owner := domain.UUIDv7Generator{}.NewID()
	frozen, err := compose.Freeze(composeEqSource(t, "secrets_envfile"), compose.Target{Project: envHashProject, Owner: owner})
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	values := composeEqResolved(frozen)
	expected := compose.ExpectedEnvHashes(frozen, values, nil)

	// check stages a fresh deployment, lets tamper change it on the node, and
	// reports how the node's report differs from the control plane's expectation.
	check := func(t *testing.T, tamper func(app stagedApp)) (envHashVerified, []string, []string) {
		t.Helper()
		app := n.stage(t, owner, envHashProject, frozen, values)
		if tamper != nil {
			tamper(app)
		}
		v := n.verify(t, app)
		modelDiffs, err := compose.Equivalent(composeEqExpected(t, frozen, app.deployment, expected), v.result.Model)
		if err != nil {
			t.Fatalf("Equivalent: %v", err)
		}
		return v, envHashDiffs(expected, v.result.Set), modelDiffs
	}
	// rewrite edits a staged file as root and gives it back to the dedicated user.
	rewrite := func(app stagedApp, file, sedScript string) {
		n.shell(t, fmt.Sprintf("sed -i '%s' %s/%s && chown %s:%s %s/%s", sedScript, app.dir(), file, dedicatedUser, dedicatedUser, app.dir(), file))
	}

	t.Run("the node resolves exactly the values the control plane materialized", func(t *testing.T) {
		v, hashDiffs, modelDiffs := check(t, nil)
		if len(hashDiffs) > 0 || len(modelDiffs) > 0 {
			t.Errorf("hash differences: %v\nmodel differences: %v\nnode report: %s", hashDiffs, modelDiffs, v.raw)
		}
		if len(v.result.Set) != len(expected) {
			t.Errorf("node reported %d entries; the control plane expects %d", len(v.result.Set), len(expected))
		}
	})

	t.Run("no secret value leaves the node, and compose prints nothing on stderr", func(t *testing.T) {
		v, _, _ := check(t, nil)
		for ref, value := range composeEqSecretValues {
			if strings.Contains(v.raw, strings.TrimSpace(value)) || strings.Contains(v.stderr, strings.TrimSpace(value)) {
				t.Errorf("the verify output carries the value of %s", ref)
			}
		}
		if v.stderr != "" {
			t.Errorf("compose.verify stderr = %q; want it empty", v.stderr)
		}
	})

	t.Run("config resolves env_file into environment and drops the wiring", func(t *testing.T) {
		v, _, _ := check(t, nil)
		var model struct {
			Services map[string]map[string]any `json:"services"`
		}
		if err := json.Unmarshal(v.result.Model, &model); err != nil {
			t.Fatalf("model: %v", err)
		}
		for service, fields := range model.Services {
			if _, kept := fields["env_file"]; kept {
				t.Errorf("service %s still carries env_file", service)
			}
		}
		env, _ := model.Services["app"]["environment"].(map[string]any)
		for _, name := range []string{"DATABASE_URL", "API_TOKEN"} {
			if got, _ := env[name].(string); !strings.HasPrefix(got, "sha256:") {
				t.Errorf("app environment %s = %q; want a masked sha256 entry", name, got)
			}
		}
	})

	for _, c := range []struct {
		name   string
		tamper func(rewrite func(stagedApp, string, string), app stagedApp)
	}{
		{"a changed value in the env file", func(rewrite func(stagedApp, string, string), app stagedApp) {
			rewrite(app, "secrets/app.env", "s/^API_TOKEN=.*/API_TOKEN=tampered/")
		}},
		{"an entry added to the env file", func(rewrite func(stagedApp, string, string), app stagedApp) {
			rewrite(app, "secrets/app.env", "$a EXTRA=injected")
		}},
		{"an entry removed from the env file", func(rewrite func(stagedApp, string, string), app stagedApp) {
			rewrite(app, "secrets/app.env", "/^API_TOKEN=/d")
		}},
		{"an environment entry in compose.yaml that shadows an env_file value", func(rewrite func(stagedApp, string, string), app stagedApp) {
			rewrite(app, "compose.yaml", shadowApiToken)
		}},
	} {
		t.Run(c.name+" is detected", func(t *testing.T) {
			_, hashDiffs, modelDiffs := check(t, func(app stagedApp) { c.tamper(rewrite, app) })
			if len(hashDiffs) == 0 {
				t.Error("the hash sets still agree; the tampering went unnoticed")
			}
			if len(modelDiffs) == 0 {
				t.Error("the masked models still agree; the tampering went unnoticed")
			}
		})
	}

	t.Run("a shadowing environment entry wins over the env file, so the report reflects it", func(t *testing.T) {
		_, hashDiffs, _ := check(t, func(app stagedApp) {
			rewrite(app, "compose.yaml", shadowApiToken)
		})
		if want := []string{"app/API_TOKEN: hash differs"}; !slices.Equal(hashDiffs, want) {
			t.Errorf("hash differences = %v; want exactly %v (the env file is intact; only the resolved value moved)", hashDiffs, want)
		}
	})
}
