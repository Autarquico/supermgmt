package compose

import (
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
)

const materializePublic = `services:
  api:
    environment:
      GREETING: a$$b
    image: ghcr.io/acme/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    labels:
      dev.supermgmt.owner: owner-1
      dev.supermgmt.project: sm-app-prod
  db:
    image: docker.io/library/redis@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    labels:
      dev.supermgmt.owner: owner-1
      dev.supermgmt.project: sm-app-prod
volumes:
  data:
    labels:
      dev.supermgmt.owner: owner-1
`

func materializeFrozen(secrets ...SecretUse) Frozen {
	return Frozen{Public: []byte(materializePublic), Secrets: secrets}
}

func materializeValue(ref string, version int64, value string) ResolvedSecret {
	return ResolvedSecret{Ref: ref, Version: version, Value: audit.Secret(value)}
}

func materializeDeploymentID() domain.ID { return domain.UUIDv7Generator{}.NewID() }

func materializeDecode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not YAML: %v\n%s", err, data)
	}
	return out
}

func materializeService(t *testing.T, model map[string]any, name string) map[string]any {
	t.Helper()
	svc, ok := model["services"].(map[string]any)[name].(map[string]any)
	if !ok {
		t.Fatalf("service %q missing from %v", name, model)
	}
	return svc
}

func TestMaterialize_AddsDeploymentLabelAndRawEnvFile(t *testing.T) {
	id := materializeDeploymentID()
	f := materializeFrozen(SecretUse{Service: "api", EnvName: "DATABASE_URL", Ref: "apps/app/db", Version: 3})

	b, err := Materialize(f, id, []ResolvedSecret{materializeValue("apps/app/db", 3, "postgres://u:p@h/db")})
	if err != nil {
		t.Fatal(err)
	}

	model := materializeDecode(t, b.ComposeYAML)
	api, db := materializeService(t, model, "api"), materializeService(t, model, "db")
	labels := api["labels"].(map[string]any)
	if labels[LabelDeployment] != id.String() || labels[LabelOwner] != "owner-1" || labels[LabelProject] != "sm-app-prod" {
		t.Errorf("api labels = %v", labels)
	}
	if db["labels"].(map[string]any)[LabelDeployment] != id.String() {
		t.Errorf("db lacks the deployment label: %v", db["labels"])
	}
	wantEnvFile := []any{map[string]any{"path": "secrets/api.env", "format": "raw", "required": true}}
	if !reflect.DeepEqual(api["env_file"], wantEnvFile) {
		t.Errorf("api env_file = %v, want %v", api["env_file"], wantEnvFile)
	}
	if _, has := db["env_file"]; has {
		t.Error("service without secrets got an env_file")
	}
	if _, has := model["volumes"].(map[string]any)["data"].(map[string]any)["labels"].(map[string]any)[LabelDeployment]; has {
		t.Error("volumes must not carry the deployment label")
	}
	if got := b.EnvFiles["secrets/api.env"].Reveal(); got != "DATABASE_URL=postgres://u:p@h/db\n" {
		t.Errorf("secrets/api.env = %q", got)
	}
	if len(b.EnvFiles) != 1 {
		t.Errorf("env files = %d, want 1", len(b.EnvFiles))
	}
	if strings.Contains(string(b.ComposeYAML), "postgres://") {
		t.Error("secret value leaked into compose.yaml")
	}
}

func TestMaterialize_KeepsPublicModelAndIsDeterministic(t *testing.T) {
	f := materializeFrozen(
		SecretUse{Service: "api", EnvName: "B_KEY", Ref: "apps/app/b", Version: 1},
		SecretUse{Service: "api", EnvName: "A_KEY", Ref: "apps/app/a", Version: 1},
	)
	values := []ResolvedSecret{materializeValue("apps/app/a", 1, "one"), materializeValue("apps/app/b", 1, "two")}
	id := materializeDeploymentID()
	before := string(f.Public)

	first, err := Materialize(f, id, values)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Materialize(f, id, values)
	if err != nil {
		t.Fatal(err)
	}

	if string(f.Public) != before {
		t.Error("Materialize modified Frozen.Public")
	}
	if string(first.ComposeYAML) != string(second.ComposeYAML) {
		t.Error("compose.yaml differs between identical runs")
	}
	if got := first.EnvFiles["secrets/api.env"].Reveal(); got != "A_KEY=one\nB_KEY=two\n" {
		t.Errorf("env file lines not sorted by name: %q", got)
	}
	api := materializeService(t, materializeDecode(t, first.ComposeYAML), "api")
	if api["environment"].(map[string]any)["GREETING"] != "a$$b" {
		t.Errorf("public environment changed: %v", api["environment"])
	}
}

func TestMaterialize_WritesEveryCorpusValueVerbatim(t *testing.T) {
	corpus := []string{
		"plain", "a$b", "${C}", "$$", `say "hi"`, "it's", "#hash", " lead", "trail ", "  ", "a=b=c",
		`back\slash`, `\n`, "ünï€😀", "tab\there", "`cmd`", "100%", "",
	}
	var uses []SecretUse
	var values []ResolvedSecret
	for i, v := range corpus {
		name := "V" + string(rune('A'+i))
		uses = append(uses, SecretUse{Service: "api", EnvName: name, Ref: "apps/app/" + name, Version: 1})
		values = append(values, materializeValue("apps/app/"+name, 1, v))
	}

	b, err := Materialize(materializeFrozen(uses...), materializeDeploymentID(), values)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(b.EnvFiles["secrets/api.env"].Reveal(), "\n"), "\n")
	if len(lines) != len(corpus) {
		t.Fatalf("lines = %d, want %d", len(lines), len(corpus))
	}
	for i, v := range corpus {
		if want := "V" + string(rune('A'+i)) + "=" + v; lines[i] != want {
			t.Errorf("line %d = %q, want %q", i, lines[i], want)
		}
	}
}

func TestMaterialize_Rejects(t *testing.T) {
	use := SecretUse{Service: "api", EnvName: "TOKEN", Ref: "apps/app/t", Version: 1}
	good := []ResolvedSecret{materializeValue("apps/app/t", 1, "v")}
	tests := []struct {
		name    string
		frozen  Frozen
		id      domain.ID
		values  []ResolvedSecret
		leakage string
	}{
		{"NUL in value", materializeFrozen(use), materializeDeploymentID(), []ResolvedSecret{materializeValue("apps/app/t", 1, "a\x00b")}, "a\x00b"},
		{"newline in value", materializeFrozen(use), materializeDeploymentID(), []ResolvedSecret{materializeValue("apps/app/t", 1, "line1\nline2")}, "line2"},
		{"carriage return in value", materializeFrozen(use), materializeDeploymentID(), []ResolvedSecret{materializeValue("apps/app/t", 1, "a\rb")}, "a\rb"},
		{"invalid UTF-8", materializeFrozen(use), materializeDeploymentID(), []ResolvedSecret{materializeValue("apps/app/t", 1, "\xff\xfe")}, "\xff"},
		{"no resolved value", materializeFrozen(use), materializeDeploymentID(), nil, ""},
		{"wrong version resolved", materializeFrozen(use), materializeDeploymentID(), []ResolvedSecret{materializeValue("apps/app/t", 2, "v")}, ""},
		{"unknown service", materializeFrozen(SecretUse{Service: "ghost", EnvName: "TOKEN", Ref: "apps/app/t", Version: 1}), materializeDeploymentID(), good, ""},
		{"path-like service", materializeFrozen(SecretUse{Service: "../etc", EnvName: "TOKEN", Ref: "apps/app/t", Version: 1}), materializeDeploymentID(), good, ""},
		{"invalid env name", materializeFrozen(SecretUse{Service: "api", EnvName: "A=B", Ref: "apps/app/t", Version: 1}), materializeDeploymentID(), good, ""},
		{"duplicate env name", materializeFrozen(use, use), materializeDeploymentID(), good, ""},
		{"secret shadowed by environment", materializeFrozen(SecretUse{Service: "api", EnvName: "GREETING", Ref: "apps/app/t", Version: 1}), materializeDeploymentID(), good, ""},
		{"invalid deployment id", materializeFrozen(use), "not-an-id", good, ""},
		{"public is not a mapping", Frozen{Public: []byte("- a\n")}, materializeDeploymentID(), nil, ""},
		{"public without services", Frozen{Public: []byte("volumes: {}\n")}, materializeDeploymentID(), nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Materialize(tc.frozen, tc.id, tc.values)
			if err == nil {
				t.Fatal("want an error")
			}
			if tc.leakage != "" && strings.Contains(err.Error(), tc.leakage) {
				t.Errorf("error leaks the value: %v", err)
			}
		})
	}
}

func TestMaterialize_RefusesExistingEnvFileAndDeploymentLabel(t *testing.T) {
	use := SecretUse{Service: "api", EnvName: "TOKEN", Ref: "apps/app/t", Version: 1}
	values := []ResolvedSecret{materializeValue("apps/app/t", 1, "v")}
	tests := map[string]string{
		"env_file":         "services:\n  api:\n    env_file: [x.env]\n    image: i\n",
		"deployment label": "services:\n  api:\n    image: i\n    labels:\n      dev.supermgmt.deployment: forged\n",
		"labels not a map": "services:\n  api:\n    image: i\n    labels: [a]\n",
	}
	for name, public := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Materialize(Frozen{Public: []byte(public), Secrets: []SecretUse{use}}, materializeDeploymentID(), values); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestFrozen_EmptyEnvInterpolationIsIdentity(t *testing.T) {
	raw := []byte(`services:
  api:
    image: ghcr.io/acme/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    command: ["run", "$$HOME", "${GREETING}"]
    environment:
      PRICE: "5$$ and ${GREETING}"
      TOKEN: ${secret:token}
    labels:
      note: "$$$$"
`)
	source := Source{Variables: map[string]string{"GREETING": "h$llo"}, SecretRefs: map[string]string{"token": "secret://apps/app/t"}}
	frozen, err := Interpolate(raw, source)
	if err != nil {
		t.Fatal(err)
	}

	again, err := Interpolate(frozen, Source{})
	if err != nil {
		t.Fatalf("frozen text is not stable under an empty environment: %v", err)
	}
	if string(again) != string(frozen) {
		t.Errorf("interpolation is not the identity:\nfirst:  %s\nsecond: %s", frozen, again)
	}

	b, err := Materialize(Frozen{Public: frozen, Secrets: []SecretUse{{Service: "api", EnvName: "TOKEN", Ref: "apps/app/t", Version: 1}}},
		materializeDeploymentID(), []ResolvedSecret{materializeValue("apps/app/t", 1, "v")})
	if err != nil {
		t.Fatal(err)
	}
	reinterpolated, err := Interpolate(b.ComposeYAML, Source{})
	if err != nil {
		t.Fatalf("materialized file is not stable under an empty environment: %v", err)
	}
	if !reflect.DeepEqual(materializeDecode(t, reinterpolated), materializeDecode(t, b.ComposeYAML)) {
		t.Errorf("materialized file changes under empty-environment interpolation:\n%s\nvs\n%s", b.ComposeYAML, reinterpolated)
	}
}
