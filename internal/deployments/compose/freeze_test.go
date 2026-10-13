package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	freezeArtifact = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	freezeRedis    = "docker.io/library/redis@sha256:3333333333333333333333333333333333333333333333333333333333333333"
	freezeAPIRef   = "ghcr.io/acme/api@" + freezeArtifact
)

const freezeDocument = `
services:
  api:
    image: ghcr.io/acme/api:placeholder
    environment:
      REGION: $REGION
      PRICE: $PRICE
      DATABASE_URL: ${secret:db_url}
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
  redis:
    image: ` + freezeRedis + `
    volumes:
      - {type: volume, source: data, target: /data}
volumes:
  data:
`

func freezeSource() Source {
	return Source{
		Raw:        []byte(freezeDocument),
		Variables:  map[string]string{"REGION": "eu-west-1", "PRICE": "5$"},
		SecretRefs: map[string]string{"db_url": "secret://apps/myapp/database_url"},
		Images: ImagePolicy{
			Deployed: "ghcr.io/acme/api",
			Sidecars: map[string]string{"redis": "docker.io/library/redis"},
		},
		DeployedService: "api",
		ArtifactDigest:  freezeArtifact,
		BoundDigests: map[string]string{
			freezeAPIRef: BindingAttestation,
			freezeRedis:  BindingOIDCClaims,
		},
	}
}

func freezeTarget(env string, bind ...string) Target {
	t := Target{Project: "sm-myapp-" + env, Owner: domain.ID("tgt_" + env)}
	for _, b := range bind {
		t.AllowedBind = append(t.AllowedBind, netip.MustParseAddr(b))
	}
	return t
}

func freezeOK(t *testing.T, s Source, target Target) Frozen {
	t.Helper()
	f, err := Freeze(s, target)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return f
}

func freezeReasonOf(err error) smerr.Reason {
	var e *smerr.Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func TestFreeze_RewritesDeployedImageAndRecordsBindings(t *testing.T) {
	f := freezeOK(t, freezeSource(), freezeTarget("prod"))
	want := []ImageUse{
		{Service: "api", Ref: freezeAPIRef, Binding: BindingAttestation},
		{Service: "redis", Ref: freezeRedis, Binding: BindingOIDCClaims},
	}
	if len(f.Images) != 2 || f.Images[0] != want[0] || f.Images[1] != want[1] {
		t.Fatalf("Images = %+v, want %+v", f.Images, want)
	}
	if !strings.Contains(string(f.Public), freezeAPIRef) || strings.Contains(string(f.Public), "placeholder") {
		t.Fatalf("deployed image not rewritten:\n%s", f.Public)
	}
}

func TestFreeze_TwoTargetsDistinctHashes(t *testing.T) {
	staging := freezeTarget("staging", "10.0.0.5")
	production := freezeTarget("prod")

	loopback := freezeOK(t, freezeSource(), staging)
	other := freezeOK(t, freezeSource(), production)
	if loopback.Hash == other.Hash {
		t.Fatalf("one source, two targets, same hash %s", loopback.Hash)
	}
	for _, c := range []struct {
		f Frozen
		t Target
	}{{loopback, staging}, {other, production}} {
		if !strings.Contains(string(c.f.Public), string(c.t.Owner)) || !strings.Contains(string(c.f.Public), c.t.Project) {
			t.Fatalf("public model lacks the owner labels of %s:\n%s", c.t.Project, c.f.Public)
		}
	}
}

func TestFreeze_BindPolicyIsPerTarget(t *testing.T) {
	s := freezeSource()
	s.Raw = []byte(strings.Replace(freezeDocument, "host_ip: 127.0.0.1", "host_ip: 10.0.0.5", 1))

	f := freezeOK(t, s, freezeTarget("staging", "10.0.0.5"))
	if want := netip.MustParseAddr("10.0.0.5"); f.HostPorts[0].Addr != want {
		t.Fatalf("HostPorts = %+v", f.HostPorts)
	}
	if _, err := Freeze(s, freezeTarget("prod")); freezeReasonOf(err) != smerr.ReasonComposeRejected {
		t.Fatalf("production does not allow 10.0.0.5, got %v", err)
	}
}

func TestFreeze_HashIsSHA256OfPublic(t *testing.T) {
	f := freezeOK(t, freezeSource(), freezeTarget("prod"))
	sum := sha256.Sum256(f.Public)
	if f.Hash != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("Hash %s does not cover Public", f.Hash)
	}
	if again := freezeOK(t, freezeSource(), freezeTarget("prod")); again.Hash != f.Hash {
		t.Fatalf("freeze is not deterministic: %s vs %s", again.Hash, f.Hash)
	}
}

func TestFreeze_SecretsNeverInPublicOrEffective(t *testing.T) {
	f := freezeOK(t, freezeSource(), freezeTarget("prod"))
	want := SecretUse{Service: "api", EnvName: "DATABASE_URL", Ref: "apps/myapp/database_url"}
	if len(f.Secrets) != 1 || f.Secrets[0] != want {
		t.Fatalf("Secrets = %+v, want [%+v]", f.Secrets, want)
	}
	for name, doc := range map[string][]byte{"Public": f.Public, "Effective": f.Effective} {
		for _, leak := range []string{"DATABASE_URL", "database_url", "secret:"} {
			if bytes.Contains(doc, []byte(leak)) {
				t.Errorf("%s contains %q", name, leak)
			}
		}
	}
}

func TestFreeze_EffectiveMasksEnvironmentValues(t *testing.T) {
	f := freezeOK(t, freezeSource(), freezeTarget("prod"))
	if bytes.Contains(f.Effective, []byte("eu-west-1")) {
		t.Fatalf("Effective exposes a value: %s", f.Effective)
	}
	var model struct {
		Services map[string]struct {
			Environment map[string]string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(f.Effective, &model); err != nil {
		t.Fatalf("Effective is not JSON: %v", err)
	}
	masked := func(v string) string { sum := sha256.Sum256([]byte(v)); return "sha256:" + hex.EncodeToString(sum[:]) }
	env := model.Services["api"].Environment
	if env["REGION"] != masked("eu-west-1") {
		t.Errorf("REGION = %q", env["REGION"])
	}
	if env["PRICE"] != masked("5$") {
		t.Errorf("PRICE = %q, want the hash of the resolved value 5$", env["PRICE"])
	}
}

func TestFreeze_PublicIsEscapedAndLoadsWithoutChange(t *testing.T) {
	f := freezeOK(t, freezeSource(), freezeTarget("prod"))
	if !strings.Contains(string(f.Public), `"5$$"`) {
		t.Fatalf("literal $ must be re-escaped:\n%s", f.Public)
	}
	if _, err := Load(f.Public, "sm-myapp-prod"); err != nil {
		t.Fatalf("public model does not load: %v", err)
	}
}

func TestFreeze_HostPorts(t *testing.T) {
	f := freezeOK(t, freezeSource(), freezeTarget("prod"))
	want := HostPort{Service: "api", Addr: netip.MustParseAddr("127.0.0.1"), Port: 8080, Proto: "tcp"}
	if len(f.HostPorts) != 1 || f.HostPorts[0] != want {
		t.Fatalf("HostPorts = %+v, want [%+v]", f.HostPorts, want)
	}
}

func TestFreeze_ValidatesBeforeBindingImages(t *testing.T) {
	s := freezeSource()
	s.Raw = []byte(strings.Replace(freezeDocument, "    ports:", "    privileged: true\n    ports:", 1))
	s.BoundDigests = nil // would be DIGEST_UNBOUND if images were looked at first
	_, err := Freeze(s, freezeTarget("prod"))
	if freezeReasonOf(err) != smerr.ReasonComposeRejected {
		t.Fatalf("err = %v, want COMPOSE_REJECTED", err)
	}
}

func TestFreeze_ValidatesAfterRewrite(t *testing.T) {
	root, err := parseMerged([]byte(freezeDocument))
	if err != nil {
		t.Fatal(err)
	}
	api := root.get("services").get("api")
	api.entries = append(api.entries, entry{key: "privileged", val: &node{kind: scalarNode, tag: "!!bool", value: "true"}})
	if err := checkRewritten(root, freezeSource(), freezeTarget("prod")); freezeReasonOf(err) != smerr.ReasonComposeRejected {
		t.Fatalf("err = %v, want COMPOSE_REJECTED", err)
	}
}

func TestFreeze_RequiresTargetProjectAndOwner(t *testing.T) {
	for name, target := range map[string]Target{
		"no project": {Owner: "tgt_x"},
		"no owner":   {Project: "sm-x"},
	} {
		if _, err := Freeze(freezeSource(), target); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: err = %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestFreeze_SurfacesImageErrors(t *testing.T) {
	s := freezeSource()
	s.BoundDigests = map[string]string{freezeAPIRef: BindingAttestation}
	if _, err := Freeze(s, freezeTarget("prod")); freezeReasonOf(err) != smerr.ReasonDigestUnbound {
		t.Fatalf("unbound sidecar: err = %v", err)
	}
}

func TestValidateSource_IsTargetIndependent(t *testing.T) {
	s := freezeSource()
	s.Raw = []byte(strings.Replace(freezeDocument, "host_ip: 127.0.0.1", "host_ip: 10.0.0.5", 1))
	s.BoundDigests, s.ArtifactDigest = nil, "" // no CI artifact exists when an app is edited
	if err := ValidateSource(s); err != nil {
		t.Fatalf("ValidateSource: %v", err)
	}
}

func TestValidateSource_RejectsWhatEveryTargetWould(t *testing.T) {
	tests := map[string]string{
		"privileged":     strings.Replace(freezeDocument, "    ports:", "    privileged: true\n    ports:", 1),
		"unknown secret": strings.Replace(freezeDocument, "${secret:db_url}", "${secret:nope}", 1),
		"unknown var":    strings.Replace(freezeDocument, "$REGION", "$NOPE", 1),
	}
	for name, doc := range tests {
		s := freezeSource()
		s.Raw = []byte(doc)
		if err := ValidateSource(s); freezeReasonOf(err) != smerr.ReasonComposeRejected {
			t.Errorf("%s: err = %v, want COMPOSE_REJECTED", name, err)
		}
	}
}
