package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func goldenPlan(t testing.TB) *Plan {
	t.Helper()
	p, err := Parse(readFile(t, "testdata/golden/plan.json"))
	if err != nil {
		t.Fatalf("parse golden plan: %v", err)
	}
	return p
}

func mustHash(t testing.TB, p *Plan) string {
	t.Helper()
	h, err := Hash(p)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	return h
}

func ptr[T any](v T) *T { return &v }

// The golden files are NOT produced by this package: plan.canonical.json comes
// from an independent implementation of the Appendix C rules and plan.sha256
// from shasum(1). plan.json is the same plan with shuffled sets and keys.
func TestGoldenPlanCanonicalBytesAndHash(t *testing.T) {
	p := goldenPlan(t)

	got, err := Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := readFile(t, "testdata/golden/plan.canonical.json"); !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes differ\n got: %s\nwant: %s", got, want)
	}

	wantHash := strings.TrimSpace(string(readFile(t, "testdata/golden/plan.sha256")))
	if got := mustHash(t, p); got != wantHash {
		t.Fatalf("Hash = %s, want %s", got, wantHash)
	}
}

func TestCanonicalFormIsAFixedPoint(t *testing.T) {
	reparsed, err := Parse(readFile(t, "testdata/golden/plan.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := mustHash(t, reparsed), mustHash(t, goldenPlan(t)); got != want {
		t.Fatalf("hash of canonical form %s != %s", got, want)
	}
}

func TestShuffledSetsKeepTheHash(t *testing.T) {
	base := goldenPlan(t)
	want := mustHash(t, base)
	for seed := uint64(1); seed <= 25; seed++ {
		rng := rand.New(rand.NewPCG(seed, seed))
		p := goldenPlan(t)
		shuffle(rng, p.Targets)
		shuffle(rng, p.Inputs)
		shuffle(rng, p.SubActions)
		shuffle(rng, p.Content.Images)
		shuffle(rng, p.Content.HostPorts)
		shuffle(rng, p.Content.SecretBindings)
		if got := mustHash(t, p); got != want {
			t.Fatalf("seed %d: hash %s != %s", seed, got, want)
		}
	}
}

func shuffle[T any](rng *rand.Rand, s []T) {
	rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

func TestSetOrderingFollowsAppendixC(t *testing.T) {
	p := &Plan{
		Version: Version, Risk: domain.RiskRead,
		Targets: []Target{{Type: "node", ID: "b"}, {Type: "app_target", ID: "z"}, {Type: "node", ID: "a"}},
		Inputs:  []Input{{Type: "secret", ID: "1"}, {Type: "app", ID: "2"}, {Type: "app", ID: "1"}},
		SubActions: []SubAction{
			{Action: "b.run", Target: SubTarget{Type: "node", ID: "1"}},
			{Action: "a.run", Target: SubTarget{Type: "node", ID: "9"}},
			{Action: "a.run", Target: SubTarget{Type: "node", ID: "2"}},
		},
		Content: Content{
			Images:         []Image{{Service: "web"}, {Service: "db"}},
			HostPorts:      []string{"127.0.0.1:9090", "0.0.0.0:80", "127.0.0.1:8080"},
			SecretBindings: []SecretBinding{{Service: "web", EnvName: "B"}, {Service: "db", EnvName: "Z"}, {Service: "web", EnvName: "A"}},
		},
		Steps: []string{"z", "a", "m"},
	}
	n, err := normalize(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range n.Targets {
		got = append(got, x.Type+"/"+x.ID)
	}
	for _, x := range n.Inputs {
		got = append(got, x.Type+"/"+x.ID)
	}
	for _, x := range n.SubActions {
		got = append(got, x.Action+"/"+x.Target.ID)
	}
	for _, x := range n.Content.Images {
		got = append(got, x.Service)
	}
	got = append(got, n.Content.HostPorts...)
	for _, x := range n.Content.SecretBindings {
		got = append(got, x.Service+"/"+x.EnvName)
	}
	got = append(got, n.Steps...) // execution order is preserved, not sorted
	want := []string{
		"app_target/z", "node/a", "node/b",
		"app/1", "app/2", "secret/1",
		"a.run/2", "a.run/9", "b.run/1",
		"db", "web",
		"0.0.0.0:80", "127.0.0.1:8080", "127.0.0.1:9090",
		"db/Z", "web/A", "web/B",
		"z", "a", "m",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order\n got: %v\nwant: %v", got, want)
	}
}

func TestHashDoesNotModifyThePlan(t *testing.T) {
	p := goldenPlan(t)
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	mustHash(t, p)
	after, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Hash reordered or rewrote the caller's plan")
	}
}

func TestEveryExecutionInputChangesTheHash(t *testing.T) {
	base := mustHash(t, goldenPlan(t))
	mutations := map[string]func(*Plan){
		"action":                       func(p *Plan) { p.Action = "deployment.rollback" },
		"actor":                        func(p *Plan) { p.Actor = "identity/other" },
		"risk":                         func(p *Plan) { p.Risk = domain.RiskDestructive },
		"target spec_revision":         func(p *Plan) { *p.Targets[0].SpecRevision++ },
		"input spec_revision":          func(p *Plan) { *findInput(p, "app").SpecRevision++ },
		"secret version":               func(p *Plan) { *findInput(p, "secret").Version++ },
		"node endpoint port":           func(p *Plan) { findInput(p, "node").Endpoint.Port = 2222 },
		"node endpoint address":        func(p *Plan) { findInput(p, "node").Endpoint.Address = "10.42.0.11" },
		"node host key":                func(p *Plan) { findInput(p, "node").HostPublicKeySHA256 = ptr("SHA256:other") },
		"extra input":                  func(p *Plan) { p.Inputs = append(p.Inputs, Input{Type: "volume", ID: "v"}) },
		"commit_sha":                   func(p *Plan) { p.Content.CommitSHA = ptr("0000") },
		"manifest_blob_sha to null":    func(p *Plan) { p.Content.ManifestBlobSHA = nil },
		"compose_hash":                 func(p *Plan) { p.Content.ComposeHash = ptr("sha256:00") },
		"image digest":                 func(p *Plan) { redis := findImage(p, "redis"); redis.Ref = strings.Replace(redis.Ref, "1", "9", 1) },
		"image binding":                func(p *Plan) { findImage(p, "redis").Binding = "attestation" },
		"exceptions_hash":              func(p *Plan) { p.Content.ExceptionsHash = ptr("sha256:00") },
		"health_hash":                  func(p *Plan) { p.Content.HealthHash = ptr("sha256:00") },
		"deployment_policy_hash":       func(p *Plan) { p.Content.DeploymentPolicyHash = ptr("sha256:00") },
		"host port":                    func(p *Plan) { p.Content.HostPorts = append(p.Content.HostPorts, "127.0.0.1:7000") },
		"rollback target":              func(p *Plan) { p.Content.RollbackTarget = &RollbackTarget{DeploymentID: "d", ComposeHash: "c"} },
		"secret binding version":       func(p *Plan) { findBinding(p, "API_KEY").Version++ },
		"secret binding secret id":     func(p *Plan) { findBinding(p, "API_KEY").SecretID = "other" },
		"sub-action target":            func(p *Plan) { p.SubActions[0].Target.ID = "other" },
		"sub-action added":             func(p *Plan) { p.SubActions = p.SubActions[:1] },
		"parameter value":              func(p *Plan) { p.Parameters["replicas"] = json.Number("4") },
		"parameter added":              func(p *Plan) { p.Parameters["extra"] = true },
		"step order":                   func(p *Plan) { p.Steps[0], p.Steps[1] = p.Steps[1], p.Steps[0] },
		"step removed":                 func(p *Plan) { p.Steps = p.Steps[:len(p.Steps)-1] },
		"step renamed":                 func(p *Plan) { p.Steps[2] = "pre-deploy-backup2" },
		"nested parameter order-aware": func(p *Plan) { p.Parameters["labels"] = []any{"a", "b"} },
	}
	seen := map[string]string{}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := goldenPlan(t)
			mutate(p)
			got := mustHash(t, p)
			if got == base {
				t.Fatal("hash did not change")
			}
			if other, dup := seen[got]; dup {
				t.Fatalf("collides with mutation %q", other)
			}
			seen[got] = name
		})
	}
}

func findBinding(p *Plan, envName string) *SecretBinding {
	for i := range p.Content.SecretBindings {
		if p.Content.SecretBindings[i].EnvName == envName {
			return &p.Content.SecretBindings[i]
		}
	}
	panic("no secret binding for " + envName)
}

func findImage(p *Plan, service string) *Image {
	for i := range p.Content.Images {
		if p.Content.Images[i].Service == service {
			return &p.Content.Images[i]
		}
	}
	panic("no image for service " + service)
}

func findInput(p *Plan, typ string) *Input {
	for i := range p.Inputs {
		if p.Inputs[i].Type == typ {
			return &p.Inputs[i]
		}
	}
	panic("no input of type " + typ)
}

func TestNullIsExplicitAndDistinctFromEmptyOrMissingData(t *testing.T) {
	minimal := func() *Plan { return &Plan{Version: Version, Risk: domain.RiskRead} }

	canonical, err := Canonical(minimal())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"commit_sha":null`, `"manifest_blob_sha":null`, `"compose_hash":null`, `"exceptions_hash":null`,
		`"health_hash":null`, `"deployment_policy_hash":null`, `"rollback_target":null`,
	} {
		if !bytes.Contains(canonical, []byte(field)) {
			t.Errorf("canonical plan lacks %s: %s", field, canonical)
		}
	}
	for _, empty := range []string{
		`"targets":[]`, `"inputs":[]`, `"sub_actions":[]`, `"steps":[]`, `"parameters":{}`,
		`"images":[]`, `"host_ports":[]`, `"secret_bindings":[]`,
	} {
		if !bytes.Contains(canonical, []byte(empty)) {
			t.Errorf("canonical plan lacks %s: %s", empty, canonical)
		}
	}

	withEmpty := minimal()
	withEmpty.Content.CommitSHA = ptr("")
	if mustHash(t, withEmpty) == mustHash(t, minimal()) {
		t.Error(`"" and null hash identically`)
	}

	// Go's nil and empty slices/maps are one value, so they cannot split a hash.
	allocated := minimal()
	allocated.Targets, allocated.Steps, allocated.Parameters = []Target{}, []string{}, map[string]any{}
	if mustHash(t, allocated) != mustHash(t, minimal()) {
		t.Error("nil and empty collections hash differently")
	}
}

func TestMissingJSONFieldEqualsExplicitNull(t *testing.T) {
	const withNull = `{"version":3,"risk":"read","content":{"commit_sha":null,"rollback_target":null}}`
	const missing = `{"version":3,"risk":"read","content":{}}`
	a, err := Parse([]byte(withNull))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(missing))
	if err != nil {
		t.Fatal(err)
	}
	if mustHash(t, a) != mustHash(t, b) {
		t.Fatal("missing and null optional fields hash differently")
	}
}

func TestIntegersAreCheckedAgainstTheSafeRange(t *testing.T) {
	withRevision := func(rev int64) *Plan {
		return &Plan{Version: Version, Risk: domain.RiskRead, Targets: []Target{{Type: "t", ID: "i", SpecRevision: &rev}}}
	}
	for _, ok := range []int64{0, 1, maxSafeInteger} {
		if _, err := Hash(withRevision(ok)); err != nil {
			t.Errorf("spec_revision %d rejected: %v", ok, err)
		}
	}
	for _, bad := range []int64{-1, maxSafeInteger + 1, math.MaxInt64, math.MinInt64} {
		wantInvalid(t, withRevision(bad), "spec_revision "+itoa(bad))
	}
}

func itoa(v int64) string { b, _ := json.Marshal(v); return string(b) }

func TestInvalidPlansAreRejected(t *testing.T) {
	valid := func() *Plan { return &Plan{Version: Version, Risk: domain.RiskRead} }
	cases := map[string]func(*Plan){
		"wrong version":              func(p *Plan) { p.Version = 2 },
		"unknown risk":               func(p *Plan) { p.Risk = "extreme" },
		"empty risk":                 func(p *Plan) { p.Risk = "" },
		"negative port":              func(p *Plan) { p.Inputs = []Input{{Type: "node", ID: "n", Endpoint: &Endpoint{Port: -1}}} },
		"port too large":             func(p *Plan) { p.Inputs = []Input{{Type: "node", ID: "n", Endpoint: &Endpoint{Port: 1 << 53}}} },
		"negative secret version":    func(p *Plan) { p.Inputs = []Input{{Type: "secret", ID: "s", Version: ptr(int64(-4))}} },
		"binding version too large":  func(p *Plan) { p.Content.SecretBindings = []SecretBinding{{Version: 1 << 60}} },
		"invalid UTF-8 action":       func(p *Plan) { p.Action = "a\xffb" },
		"invalid UTF-8 in step":      func(p *Plan) { p.Steps = []string{"ok", "\xc3\x28"} },
		"invalid UTF-8 in pointer":   func(p *Plan) { p.Content.CommitSHA = ptr("\xff") },
		"invalid UTF-8 in param key": func(p *Plan) { p.Parameters = map[string]any{"k\xff": "v"} },
		"invalid UTF-8 in param":     func(p *Plan) { p.Parameters = map[string]any{"k": []any{"\xff"}} },
		"float64 parameter":          func(p *Plan) { p.Parameters = map[string]any{"f": 1.5} },
		"integral float64 parameter": func(p *Plan) { p.Parameters = map[string]any{"f": float64(3)} },
		"float32 parameter":          func(p *Plan) { p.Parameters = map[string]any{"f": float32(1)} },
		"NaN parameter":              func(p *Plan) { p.Parameters = map[string]any{"f": math.NaN()} },
		"Inf parameter":              func(p *Plan) { p.Parameters = map[string]any{"f": math.Inf(1)} },
		"fractional json.Number":     func(p *Plan) { p.Parameters = map[string]any{"f": json.Number("1.5")} },
		"exponent json.Number":       func(p *Plan) { p.Parameters = map[string]any{"f": json.Number("1e3")} },
		"negative int parameter":     func(p *Plan) { p.Parameters = map[string]any{"n": -1} },
		"negative json.Number":       func(p *Plan) { p.Parameters = map[string]any{"n": json.Number("-1")} },
		"json.Number above range":    func(p *Plan) { p.Parameters = map[string]any{"n": json.Number("9007199254740992")} },
		"uint64 above range":         func(p *Plan) { p.Parameters = map[string]any{"n": uint64(1) << 53} },
		"float nested in array":      func(p *Plan) { p.Parameters = map[string]any{"a": []any{1, []any{2.5}}} },
		"float nested in object":     func(p *Plan) { p.Parameters = map[string]any{"a": map[string]any{"b": map[string]any{"c": 0.1}}} },
		"unsupported type":           func(p *Plan) { p.Parameters = map[string]any{"s": struct{}{}} },
		"unsupported slice type":     func(p *Plan) { p.Parameters = map[string]any{"s": []string{"a"}} },
		"duplicate target":           func(p *Plan) { p.Targets = []Target{{Type: "a", ID: "1"}, {Type: "a", ID: "1"}} },
		"duplicate input": func(p *Plan) {
			p.Inputs = []Input{{Type: "a", ID: "1"}, {Type: "a", ID: "1", SpecRevision: ptr(int64(2))}}
		},
		"duplicate image service": func(p *Plan) { p.Content.Images = []Image{{Service: "web"}, {Service: "web", Ref: "x"}} },
		"duplicate host port":     func(p *Plan) { p.Content.HostPorts = []string{"1.1.1.1:80", "1.1.1.1:80"} },
		"duplicate secret binding": func(p *Plan) {
			p.Content.SecretBindings = []SecretBinding{{Service: "w", EnvName: "E"}, {Service: "w", EnvName: "E"}}
		},
		"duplicate sub-action":       func(p *Plan) { p.SubActions = []SubAction{{Action: "a"}, {Action: "a"}} },
		"parameters nested too deep": func(p *Plan) { p.Parameters = map[string]any{"d": nest(maxDepth + 1)} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := valid()
			mutate(p)
			wantInvalid(t, p, name)
		})
	}
	t.Run("nil plan", func(t *testing.T) { wantInvalid(t, nil, "nil") })
}

func nest(depth int) any {
	var v any = json.Number("1")
	for range depth {
		v = []any{v}
	}
	return v
}

func wantInvalid(t *testing.T, p *Plan, what string) {
	t.Helper()
	out, err := Hash(p)
	if err == nil {
		t.Fatalf("%s: accepted, hash %s", what, out)
	}
	if !errors.Is(err, smerr.New(smerr.CodeInvalidArgument, "", "")) {
		t.Fatalf("%s: error %v is not INVALID_ARGUMENT", what, err)
	}
}

func TestParametersAcceptAnyIntegerRepresentationEqually(t *testing.T) {
	hashWith := func(v any) string {
		return mustHash(t, &Plan{Version: Version, Risk: domain.RiskRead, Parameters: map[string]any{"n": v}})
	}
	want := hashWith(json.Number("42"))
	for _, v := range []any{42, int8(42), int64(42), uint(42), uint64(42)} {
		if got := hashWith(v); got != want {
			t.Errorf("%T(42) hashes differently from json.Number", v)
		}
	}
	if hashWith(json.Number("42")) == hashWith(json.Number("43")) {
		t.Error("distinct integers collide")
	}
	if hashWith(json.Number("9007199254740991")) == "" {
		t.Error("max safe integer rejected")
	}
}

func TestParse(t *testing.T) {
	for name, in := range map[string]string{
		"unknown field":    `{"version":3,"risk":"read","surprise":1}`,
		"unknown nested":   `{"version":3,"risk":"read","content":{"nope":1}}`,
		"trailing data":    `{"version":3,"risk":"read"} {}`,
		"not an object":    `[]`,
		"wrong field type": `{"version":"3"}`,
		"empty":            ``,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Floats survive Parse as exact text and are then rejected when hashing.
	p, err := Parse([]byte(`{"version":3,"risk":"read","parameters":{"f":1.5}}`))
	if err != nil {
		t.Fatal(err)
	}
	wantInvalid(t, p, "float parsed from JSON")
}

// Appendix C: "Absent optional values are null, never omitted." A reflection
// test keeps omitempty (and untagged fields) out of every plan type.
func TestNoPlanFieldIsOmittedOrUntagged(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := range typ.NumField() {
			field := typ.Field(i)
			tag, ok := field.Tag.Lookup("json")
			if !ok || tag == "" || tag == "-" {
				t.Errorf("%s.%s has no json name", typ.Name(), field.Name)
			}
			if strings.Contains(tag, "omitempty") || strings.Contains(tag, "omitzero") || strings.Contains(tag, ",") {
				t.Errorf("%s.%s json tag %q has options; plans never omit fields", typ.Name(), field.Name, tag)
			}
			walk(field.Type)
		}
	}
	walk(reflect.TypeOf(Plan{}))
	if len(seen) < 10 {
		t.Fatalf("walked only %d struct types; reflection walk is broken", len(seen))
	}
}
