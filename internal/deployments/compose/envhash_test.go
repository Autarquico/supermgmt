package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"
)

func envhashOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestExpectedEnvHashes_CoversPublicAndSecretValues(t *testing.T) {
	public := `services:
  api:
    environment:
      EMPTY: ""
      PRICE: 5$$ a$$$$b
      SPACED: "  padded  "
    image: i
  worker:
    image: i
`
	f := Frozen{Public: []byte(public), Secrets: []SecretUse{
		{Service: "api", EnvName: "DB", Ref: "apps/a/db", Version: 2},
		{Service: "worker", EnvName: "KEY", Ref: "apps/a/key", Version: 1},
	}}
	values := []ResolvedSecret{
		materializeValue("apps/a/db", 2, "p=a ${x} $$"),
		materializeValue("apps/a/key", 1, ""),
	}

	got := ExpectedEnvHashes(f, values, nil)

	want := []EnvHash{
		{"api", "DB", envhashOf("p=a ${x} $$")},
		{"api", "EMPTY", envhashOf("")},
		{"api", "PRICE", envhashOf("5$ a$$b")},
		{"api", "SPACED", envhashOf("  padded  ")},
		{"worker", "KEY", envhashOf("")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestExpectedEnvHashes_EnvironmentWinsOverEnvFile(t *testing.T) {
	f := Frozen{
		Public:  []byte("services:\n  api:\n    environment:\n      MODE: from-environment\n    image: i\n"),
		Secrets: []SecretUse{{Service: "api", EnvName: "MODE", Ref: "apps/a/m", Version: 1}},
	}

	got := ExpectedEnvHashes(f, []ResolvedSecret{materializeValue("apps/a/m", 1, "from-secret")}, nil)

	want := []EnvHash{{"api", "MODE", envhashOf("from-environment")}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExpectedEnvHashes_OmitsWhatCannotBeResolved(t *testing.T) {
	f := Frozen{
		Public:  []byte("services:\n  api:\n    environment:\n      NAMEONLY:\n      SET: v\n    image: i\n"),
		Secrets: []SecretUse{{Service: "api", EnvName: "LOST", Ref: "apps/a/l", Version: 1}},
	}

	got := ExpectedEnvHashes(f, nil, nil)

	want := []EnvHash{{"api", "SET", envhashOf("v")}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExpectedEnvHashes_UnparsablePublicYieldsNoHashes(t *testing.T) {
	if got := ExpectedEnvHashes(Frozen{Public: []byte("{{{")}, nil, nil); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestExpectedEnvHashes_ServicesWithoutEnvironmentAddNothing(t *testing.T) {
	f := Frozen{Public: []byte("services:\n  db:\n    image: i\n")}
	if got := ExpectedEnvHashes(f, nil, nil); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestExpectedEnvHashes_KnownDigest(t *testing.T) {
	f := Frozen{Public: []byte("services:\n  a:\n    environment:\n      E: \"\"\n    image: i\n")}
	got := ExpectedEnvHashes(f, nil, nil)
	if len(got) != 1 || got[0].SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("got %v", got)
	}
}
