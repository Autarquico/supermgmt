//go:build fixtures

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// The equivalence corpus (spec §20.3 step 10, ADR-0006): every file under
// internal/deployments/compose/testdata/equivalence goes through the pinned
// loader (Freeze, Materialize) and through the fixture node's Compose CLI
// (the compose.verify template); the two masked models must be equivalent
// within the CLI-defaults table.

const (
	composeEqCorpusDir = "../../internal/deployments/compose/testdata/equivalence"
	composeEqRoot      = "/srv/equivalence"
	composeEqArtifact  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	composeEqDeployed  = "ghcr.io/acme/app"
	composeEqRedis     = "docker.io/library/redis"
	composeEqRedisRef  = composeEqRedis + "@sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

var composeEqFiles = []string{"basic", "ports_long", "healthcheck", "volumes_networks", "secrets_envfile", "unused_resources"}

var composeEqSecretValues = map[string]string{
	"apps/eq/database_url":   `postgres://u:p$w${X}@db/app?x=1`,
	"apps/eq/api_token":      `  padded "token" # not a comment  `,
	"apps/eq/cache_password": `a=b=c`,
}

func composeEqSource(t *testing.T, name string) compose.Source {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(composeEqCorpusDir, name+".yaml"))
	if err != nil {
		t.Fatalf("read corpus file: %v", err)
	}
	return compose.Source{
		Raw:       raw,
		Variables: map[string]string{"REGION": "eu-west-1"},
		SecretRefs: map[string]string{
			"db_url":         "secret://apps/eq/database_url",
			"api_token":      "secret://apps/eq/api_token",
			"cache_password": "secret://apps/eq/cache_password",
		},
		Images:          compose.ImagePolicy{Deployed: composeEqDeployed, Sidecars: map[string]string{"cache": composeEqRedis}},
		DeployedService: "app",
		ArtifactDigest:  composeEqArtifact,
		BoundDigests: map[string]string{
			composeEqDeployed + "@" + composeEqArtifact: compose.BindingAttestation,
			composeEqRedisRef: compose.BindingPinned,
		},
	}
}

// composeEqResolved binds every frozen secret to its fixed test value.
func composeEqResolved(f compose.Frozen) []compose.ResolvedSecret {
	var out []compose.ResolvedSecret
	for _, u := range f.Secrets {
		out = append(out, compose.ResolvedSecret{Ref: u.Ref, Version: u.Version, Value: audit.Secret(composeEqSecretValues[u.Ref])})
	}
	return out
}

// composeEqExpected is the verify step's expected model: the freeze-time
// effective model plus what materialization adds (deployment label, secret
// environment names), masked like the node masks them. Same construction as
// app.expectedMaskedModel, which is unexported.
func composeEqExpected(t *testing.T, f compose.Frozen, deployment domain.ID, hashes []compose.EnvHash) json.RawMessage {
	t.Helper()
	var model map[string]any
	if err := json.Unmarshal(f.Effective, &model); err != nil {
		t.Fatalf("decode effective model: %v", err)
	}
	services, _ := model["services"].(map[string]any)
	object := func(svc map[string]any, key string) map[string]any {
		obj, ok := svc[key].(map[string]any)
		if !ok {
			obj = map[string]any{}
			svc[key] = obj
		}
		return obj
	}
	for _, raw := range services {
		object(raw.(map[string]any), "labels")[compose.LabelDeployment] = deployment.String()
	}
	byName := map[string]string{}
	for _, h := range hashes {
		byName[h.Service+"/"+h.EnvName] = h.SHA256
	}
	for _, u := range f.Secrets {
		object(services[u.Service].(map[string]any), "environment")[u.EnvName] = "sha256:" + byName[u.Service+"/"+u.EnvName]
	}
	out, err := json.Marshal(model)
	if err != nil {
		t.Fatalf("encode expected model: %v", err)
	}
	return out
}

// composeEqStage writes the bundle where compose.verify reads it and returns
// the model the node's CLI printed.
func composeEqStage(t *testing.T, n *fixtureNode, project string, deployment domain.ID, b compose.Bundle) (model []byte, set []envHash) {
	t.Helper()
	dir := composeEqRoot + "/" + project + "/" + deployment.String()
	writeNodeFile(t, n, dir+"/compose.yaml", b.ComposeYAML)
	for path, content := range b.EnvFiles {
		writeNodeFile(t, n, dir+"/"+path, []byte(content.Reveal()))
	}
	cmd, err := templates.Render("compose.verify", map[string]string{"root": composeEqRoot, "project": project, "deployment": deployment.String()})
	if err != nil {
		t.Fatalf("render compose.verify: %v", err)
	}
	out, err := n.Exec(t.Context(), "sh", "-c", cmd.Line)
	if err != nil {
		t.Fatalf("compose.verify: %v\n%s", err, out)
	}
	var got verifyResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("compose.verify output is not JSON: %v\n%s", err, out)
	}
	return got.Model, got.Set
}

// composeEqCLIOnly lists the generalized paths (array indexes and service,
// network and volume names replaced by "*") that only the CLI model carries.
func composeEqCLIOnly(expected, cli any, path []string, found map[string]bool) {
	switch c := cli.(type) {
	case map[string]any:
		e, _ := expected.(map[string]any)
		for key, v := range c {
			next := append(append([]string(nil), path...), key)
			if ev, ok := e[key]; ok {
				composeEqCLIOnly(ev, v, next, found)
				continue
			}
			value, _ := json.Marshal(v)
			found[strings.Join(composeEqGeneralize(next), ".")+" = "+string(value)] = true
		}
	case []any:
		e, _ := expected.([]any)
		for i, v := range c {
			if i < len(e) {
				composeEqCLIOnly(e[i], v, append(append([]string(nil), path...), "*"), found)
			}
		}
	}
}

func composeEqGeneralize(path []string) []string {
	out := append([]string(nil), path...)
	if len(out) >= 2 && (out[0] == "services" || out[0] == "networks" || out[0] == "volumes") {
		out[1] = "*"
		if len(out) == 2 {
			out[1] = path[1]
		}
	}
	if len(out) >= 4 && out[0] == "services" && out[2] == "depends_on" {
		out[3] = "*"
	}
	if len(out) >= 4 && out[0] == "services" && out[2] == "networks" && out[3] != "default" {
		out[3] = "*"
	}
	return out
}

// composeEqCompare freezes src for a fresh target, stages it on the node and
// returns both masked models with the differences Equivalent reports.
func composeEqCompare(t *testing.T, n *fixtureNode, project string, src compose.Source) (expected, cliModel json.RawMessage, diffs []string) {
	t.Helper()
	ids := domain.UUIDv7Generator{}
	deployment := ids.NewID()
	frozen, err := compose.Freeze(src, compose.Target{Project: project, Owner: ids.NewID()})
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	values := composeEqResolved(frozen)
	bundle, err := compose.Materialize(frozen, deployment, values)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	cliModel, cliSet := composeEqStage(t, n, project, deployment, bundle)
	hashes := compose.ExpectedEnvHashes(frozen, values, nil)
	if len(cliSet) != len(hashes) {
		t.Errorf("node reported %d environment entries; the loader expects %d", len(cliSet), len(hashes))
	}
	expected = composeEqExpected(t, frozen, deployment, hashes)
	diffs, err = compose.Equivalent(expected, cliModel)
	if err != nil {
		t.Fatalf("Equivalent: %v", err)
	}
	return expected, cliModel, diffs
}

func TestComposeEquivalence_Corpus(t *testing.T) {
	n := startNode(t, fixture.Options{})

	t.Run("the node runs the pinned Compose CLI", func(t *testing.T) {
		out := n.shell(t, "docker compose version --short")
		if out != "5.5.1" && out != "v5.5.1" {
			t.Fatalf("docker compose version --short = %q; want 5.5.1", out)
		}
		t.Logf("docker compose version --short = %q", out)
	})

	for _, name := range composeEqFiles {
		t.Run(name+" is equivalent between the loader and the CLI", func(t *testing.T) {
			expected, cliModel, diffs := composeEqCompare(t, n, "eq-"+strings.ReplaceAll(name, "_", "-"), composeEqSource(t, name))
			if len(diffs) > 0 {
				t.Errorf("loader and CLI differ beyond the CLI-defaults table:\n  %s\nCLI model: %s\nexpected:  %s",
					strings.Join(diffs, "\n  "), cliModel, expected)
			}

			var e, c any
			_ = json.Unmarshal(expected, &e)
			_ = json.Unmarshal(cliModel, &c)
			found := map[string]bool{}
			composeEqCLIOnly(e, c, nil, found)
			var lines []string
			for k := range found {
				lines = append(lines, k)
			}
			sort.Strings(lines)
			t.Logf("CLI-only fields in %s.yaml:\n  %s", name, strings.Join(lines, "\n  "))
		})
	}

	t.Run("a declared network or volume no service uses is omitted by the CLI and pruned from the expected model", func(t *testing.T) {
		_, cliModel, diffs := composeEqCompare(t, n, "eq-unused", composeEqSource(t, "unused_resources"))
		var cli struct {
			Networks map[string]any `json:"networks"`
			Volumes  map[string]any `json:"volumes"`
		}
		if err := json.Unmarshal(cliModel, &cli); err != nil {
			t.Fatalf("model: %v", err)
		}
		if _, ok := cli.Networks["idle"]; ok {
			t.Error("the CLI kept the unused network; the premise of the pruning is gone")
		}
		if _, ok := cli.Volumes["idle"]; ok {
			t.Error("the CLI kept the unused volume; the premise of the pruning is gone")
		}
		if _, ok := cli.Volumes["used"]; !ok {
			t.Error("the CLI dropped the used volume")
		}
		if len(diffs) > 0 {
			t.Errorf("unused resources still diverge:\n  %s", strings.Join(diffs, "\n  "))
		}
	})

	t.Run("config drops env_file wiring and resolves its names into environment", func(t *testing.T) {
		ids := domain.UUIDv7Generator{}
		deployment := ids.NewID()
		frozen, err := compose.Freeze(composeEqSource(t, "secrets_envfile"), compose.Target{Project: "eq-envfile", Owner: ids.NewID()})
		if err != nil {
			t.Fatalf("Freeze: %v", err)
		}
		bundle, err := compose.Materialize(frozen, deployment, composeEqResolved(frozen))
		if err != nil {
			t.Fatalf("Materialize: %v", err)
		}
		if !bytes.Contains(bundle.ComposeYAML, []byte("env_file")) {
			t.Fatal("the materialized compose.yaml has no env_file; the premise of this test is gone")
		}
		model, _ := composeEqStage(t, n, "eq-envfile", deployment, bundle)
		var cli struct {
			Services map[string]map[string]any `json:"services"`
		}
		if err := json.Unmarshal(model, &cli); err != nil {
			t.Fatalf("model: %v", err)
		}
		for service, fields := range cli.Services {
			if _, kept := fields["env_file"]; kept {
				t.Errorf("service %s: config output still carries env_file", service)
			}
		}
		env, _ := cli.Services["app"]["environment"].(map[string]any)
		if _, ok := env["DATABASE_URL"]; !ok {
			t.Errorf("app environment lacks DATABASE_URL after env_file resolution: %s", fmt.Sprint(env))
		}
	})
}
