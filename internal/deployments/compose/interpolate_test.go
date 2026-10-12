package compose

import (
	"reflect"
	"strings"
	"testing"
)

var testSource = Source{
	Variables: map[string]string{
		"REGION": "eu-west-1",
		"PRICE":  "5$",
		"EMPTY":  "",
	},
	SecretRefs: map[string]string{
		"db_url": "secret://apps/myapp/database_url",
		"api":    "secret://apps/myapp/api_key",
	},
}

func interpolateOK(t *testing.T, doc string) *node {
	t.Helper()
	out, err := Interpolate([]byte(doc), testSource)
	if err != nil {
		t.Fatalf("Interpolate: %v", err)
	}
	root, err := parseMerged(out)
	if err != nil {
		t.Fatalf("output does not parse: %v\n%s", err, out)
	}
	return root
}

func envOf(root *node, svc string) map[string]string {
	out := map[string]string{}
	env := root.get("services").get(svc).get("environment")
	if env == nil {
		return out
	}
	for _, e := range env.entries {
		out[e.key] = e.val.value
	}
	return out
}

func TestInterpolate_SubstitutesRecognizedForms(t *testing.T) {
	doc := service(`    environment:
      A: $REGION
      B: ${REGION}
      C: "x-$REGION-y"
      D: "${REGION}${REGION}"
      E: "$$HOME"
      F: "$EMPTY"
    labels:
      region: $REGION
    command: ["serve", "--region=$REGION", "$$literal"]
    entrypoint: ["/bin/$REGION"]
`)
	root := interpolateOK(t, doc)
	wantEnv := map[string]string{
		"A": "eu-west-1", "B": "eu-west-1", "C": "x-eu-west-1-y", "D": "eu-west-1eu-west-1",
		"E": "$$HOME", "F": "",
	}
	if got := envOf(root, "web"); !reflect.DeepEqual(got, wantEnv) {
		t.Errorf("environment = %v, want %v", got, wantEnv)
	}
	web := root.get("services").get("web")
	if got := web.get("labels").get("region").value; got != "eu-west-1" {
		t.Errorf("label = %q", got)
	}
	var cmd []string
	for _, it := range web.get("command").items {
		cmd = append(cmd, it.value)
	}
	if want := []string{"serve", "--region=eu-west-1", "$$literal"}; !reflect.DeepEqual(cmd, want) {
		t.Errorf("command = %v, want %v", cmd, want)
	}
	if got := web.get("entrypoint").items[0].value; got != "/bin/eu-west-1" {
		t.Errorf("entrypoint = %q", got)
	}
}

func TestInterpolate_EscapesEveryLiteralDollar(t *testing.T) {
	root := interpolateOK(t, service("    environment:\n      PRICE: $PRICE\n      RAW: \"cost: $$5\"\n"))
	env := envOf(root, "web")
	if env["PRICE"] != "5$$" {
		t.Errorf("a variable value containing $ must be escaped, got %q", env["PRICE"])
	}
	if env["RAW"] != "cost: $$5" {
		t.Errorf("$$ must stay escaped, got %q", env["RAW"])
	}
}

// The frozen file interpolated again with no variables is unchanged: nothing
// left in it needs a variable.
func TestInterpolate_OutputIsAFixedPoint(t *testing.T) {
	doc := service(`    environment: {A: $REGION, B: "$$x", C: "p$PRICE", D: "${secret:db_url}"}
    labels: {k: "v $REGION"}
    command: ["a$$", "$REGION"]
`)
	once, err := Interpolate([]byte(doc), testSource)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Interpolate(once, Source{})
	if err != nil {
		t.Fatalf("second pass with an empty environment: %v", err)
	}
	if string(once) != string(twice) {
		t.Errorf("not a fixed point:\n%s\n---\n%s", once, twice)
	}
}

func TestInterpolate_Rejects(t *testing.T) {
	tests := []struct{ name, doc, want string }{
		{"default form", service("    environment: {A: \"${REGION:-x}\"}\n"), "unsupported"},
		{"error form", service("    environment: {A: \"${REGION?err}\"}\n"), "unsupported"},
		{"dash form", service("    environment: {A: \"${REGION-x}\"}\n"), "unsupported"},
		{"nested form", service("    environment: {A: \"${${REGION}}\"}\n"), "unsupported"},
		{"unterminated", service("    environment: {A: \"${REGION\"}\n"), "unsupported"},
		{"empty braces", service("    environment: {A: \"${}\"}\n"), "unsupported"},
		{"lone dollar before space", service("    environment: {A: \"a $ b\"}\n"), "lone $"},
		{"trailing dollar", service("    environment: {A: \"a$\"}\n"), "lone $"},
		{"dollar before digit", service("    environment: {A: \"$1\"}\n"), "lone $"},
		{"unknown variable", service("    environment: {A: $NOPE}\n"), `"NOPE"`},
		{"unknown braced variable", service("    environment: {A: \"${NOPE}\"}\n"), `"NOPE"`},
		{"dollar in image", "services:\n  web:\n    image: \"x:$REGION\"\n", "interpolation is not allowed here"},
		{"dollar in healthcheck", service("    healthcheck: {test: [CMD-SHELL, \"curl $REGION\"]}\n"), "services.web.healthcheck.test"},
		{"dollar in port", service("    ports: [{target: 80, published: \"$PORT\", host_ip: 127.0.0.1}]\n"), "interpolation is not allowed here"},
		{"dollar in extension block", "x-note: $REGION\nservices: {}\n", "x-note"},
		{"dollar in top-level volume label", "services: {}\nvolumes:\n  v:\n    labels: {a: $REGION}\n", "volumes.v.labels.a"},
		{"dollar in mapping key", service("    environment: {\"A$B\": c}\n"), "interpolation is not allowed here"},
		{"dollar in label key", service("    labels: {\"a.$REGION\": c}\n"), "interpolation is not allowed here"},
		{"dollar in tmpfs", service("    tmpfs: [\"/$REGION\"]\n"), "interpolation is not allowed here"},
		{"secret in command", service("    command: [\"${secret:db_url}\"]\n"), "unsupported"},
		{"secret in label", service("    labels: {a: \"${secret:db_url}\"}\n"), "unsupported"},
		{"secret mixed with text", service("    environment: {A: \"x${secret:db_url}\"}\n"), "unsupported"},
		{"secret with suffix", service("    environment: {A: \"${secret:db_url}x\"}\n"), "exactly ${secret:<ref-name>}"},
		{"secret unknown ref", service("    environment: {A: \"${secret:nope}\"}\n"), "not defined in the app's secret_refs"},
		{"secret ref without scheme", service("    environment: {A: \"${secret:bad}\"}\n"), "not defined"},
		{"secret malformed name", service("    environment: {A: \"${secret:}\"}\n"), "exactly ${secret:<ref-name>}"},
	}
	src := testSource
	src.SecretRefs = map[string]string{"db_url": "secret://apps/myapp/database_url", "bad": "apps/no-scheme"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Interpolate([]byte(tt.doc), src)
			wantRejected(t, err, tt.want)
		})
	}
}

func TestInterpolate_RemovesSecretReferencesAndRecordsThem(t *testing.T) {
	doc := `
services:
  worker:
    image: x
    environment: {Z_LAST: "${secret:api}", PLAIN: v}
  web:
    image: x
    environment:
      DATABASE_URL: "${secret:db_url}"
      API_KEY: "${secret:api}"
      LOG: info
`
	out, err := Interpolate([]byte(doc), testSource)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "secret") {
		t.Errorf("a secret placeholder or path leaked into the public model:\n%s", out)
	}
	root, _ := parseMerged(out)
	if got, want := envOf(root, "web"), map[string]string{"LOG": "info"}; !reflect.DeepEqual(got, want) {
		t.Errorf("web environment = %v, want %v", got, want)
	}

	uses, err := SecretUses([]byte(doc), testSource)
	if err != nil {
		t.Fatal(err)
	}
	want := []SecretUse{
		{Service: "web", EnvName: "API_KEY", Ref: "apps/myapp/api_key"},
		{Service: "web", EnvName: "DATABASE_URL", Ref: "apps/myapp/database_url"},
		{Service: "worker", EnvName: "Z_LAST", Ref: "apps/myapp/api_key"},
	}
	if !reflect.DeepEqual(uses, want) {
		t.Errorf("uses = %+v, want %+v", uses, want)
	}
}

// Pins the conservative reading of §20.3 step 2: an extension block is not an
// interpolation site, so a variable inside an anchor is rejected even when a
// service merges it into an allowed location. Escaped dollars merge fine.
func TestInterpolate_ExtensionBlocksAreNotInterpolationSites(t *testing.T) {
	withVariable := "x-env: &env\n  environment: {A: $REGION}\nservices:\n  web:\n    <<: *env\n    image: x\n"
	_, err := Interpolate([]byte(withVariable), testSource)
	wantRejected(t, err, "x-env.environment.A")

	escaped := "x-env: &env\n  environment: {A: \"$$REGION\"}\nservices:\n  web:\n    <<: *env\n    image: x\n"
	root := interpolateOK(t, escaped)
	if got := envOf(root, "web")["A"]; got != "$$REGION" {
		t.Errorf("merged escaped dollar = %q, want $$REGION", got)
	}
}

func TestInterpolate_PreservesStringTypes(t *testing.T) {
	doc := service("    user: \"1000\"\n    read_only: true\n    pids_limit: 5\n    environment: {FLAG: \"true\", N: \"007\", NIL: \"null\"}\n")
	root := interpolateOK(t, doc)
	web := root.get("services").get("web")
	for key, tag := range map[string]string{"user": "!!str", "read_only": "!!bool", "pids_limit": "!!int"} {
		if got := web.get(key).tag; got != tag {
			t.Errorf("%s tag = %s, want %s", key, got, tag)
		}
	}
	for _, name := range []string{"FLAG", "N", "NIL"} {
		if got := web.get("environment").get(name).tag; got != "!!str" {
			t.Errorf("environment %s tag = %s, want !!str", name, got)
		}
	}
}

func TestInterpolate_OutputStillPassesCheckRaw(t *testing.T) {
	out, err := Interpolate([]byte(validCompose), testSource)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRaw(out, testTarget); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestInterpolate_PropagatesRawFailures(t *testing.T) {
	_, err := Interpolate([]byte("a: [\n"), testSource)
	wantRejected(t, err, "invalid YAML")
}
