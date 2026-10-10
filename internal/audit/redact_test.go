package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const plaintext = "hunter2-plaintext"

func TestSecretNeverRevealsItself(t *testing.T) {
	s := Secret(plaintext)
	formats := map[string]string{
		"%v":            fmt.Sprintf("%v", s),
		"%+v":           fmt.Sprintf("%+v", s),
		"%#v":           fmt.Sprintf("%#v", s),
		"%q":            fmt.Sprintf("%q", s),
		"%x":            fmt.Sprintf("%x", s),
		"Sprint":        fmt.Sprint(s),
		"pointer":       fmt.Sprintf("%v", &s),
		"in struct %+v": fmt.Sprintf("%+v", struct{ Password Secret }{s}),
		"in struct %#v": fmt.Sprintf("%#v", struct{ Password Secret }{s}),
		"in slice":      fmt.Sprintf("%v", []Secret{s}),
		"in map":        fmt.Sprintf("%v", map[string]Secret{"k": s}),
		"error wrap":    fmt.Errorf("login: %v", s).Error(),
	}
	for name, got := range formats {
		if strings.Contains(got, plaintext) {
			t.Errorf("%s leaked the secret: %s", name, got)
		}
		if name != "%x" && !strings.Contains(got, Redacted) {
			t.Errorf("%s = %q, want it to contain %s", name, got, Redacted)
		}
	}
}

func TestSecretMarshaling(t *testing.T) {
	s := Secret(plaintext)
	asJSON, err := json.Marshal(map[string]any{"direct": s, "ptr": &s, "list": []Secret{s}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(asJSON), plaintext) {
		t.Errorf("JSON leaked the secret: %s", asJSON)
	}
	text, err := s.MarshalText()
	if err != nil || string(text) != Redacted {
		t.Errorf("MarshalText = %q, %v", text, err)
	}
	if got := s.LogValue().String(); got != Redacted {
		t.Errorf("LogValue = %q", got)
	}
	if got := s.Reveal(); got != plaintext {
		t.Errorf("Reveal = %q, want the plaintext", got)
	}
}

func TestScrubString(t *testing.T) {
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
	tests := []struct {
		name, in, want string
	}{
		{"bearer", "Authorization: Bearer abc.DEF-123_x~+/=", "Authorization: Bearer " + Redacted},
		{"bearer lowercase", "got bearer tok123 back", "got Bearer " + Redacted + " back"},
		{"basic", "Authorization: Basic dXNlcjpwYXNzd29yZA==", "Authorization: Basic " + Redacted},
		{"short word after basic is prose", "a basic idea", "a basic idea"},
		{"pem block", "key=" + pem + " end", "key=" + Redacted + " end"},
		{"rsa pem block", "-----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY-----", Redacted},
		{"truncated pem block", "log: -----BEGIN PRIVATE KEY-----\nAAAA\nBBBB", "log: " + Redacted},
		{"public key is not secret", "ssh-ed25519 AAAAC3Nza host", "ssh-ed25519 AAAAC3Nza host"},
		{"secret reference is kept", "credential_ref=secret://providers/home-pve/token", "credential_ref=secret://providers/home-pve/token"},
		{"two tokens", "Bearer a1 and Bearer b2", "Bearer " + Redacted + " and Bearer " + Redacted},
		{"nothing to scrub", "service restarted", "service restarted"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScrubString(tt.in); got != tt.want {
				t.Errorf("ScrubString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

type credentials struct {
	User     string
	Password string
	Token    Secret `json:"api"`
	Note     string
}

func TestRedactMap(t *testing.T) {
	in := map[string]any{
		"deployment_id": "d1",
		"count":         3,
		"ratio":         0.5,
		"ok":            true,
		"nothing":       nil,
		"Password":      plaintext,
		"db_PASSWD":     plaintext,
		"client_secret": plaintext,
		"X-Api-Key":     plaintext,
		"apikey":        plaintext,
		"Authorization": "Bearer " + plaintext,
		"private_key":   plaintext,
		"privateKey":    plaintext,
		"Credential":    plaintext,
		"Cookie":        plaintext,
		"session_id":    plaintext,
		"nested": map[string]any{
			"token": plaintext,
			"safe":  "Bearer " + plaintext,
			"deeper": map[string]any{
				"password": plaintext,
				"list":     []any{"ok", map[string]any{"secret": plaintext}, "Basic " + plaintext + "=="},
			},
		},
		"typed_secret":  Secret(plaintext),
		"err":           errors.New("dial failed: Bearer " + plaintext),
		"strings":       []string{"fine", "Bearer " + plaintext},
		"maps":          []map[string]any{{"cookie": plaintext}, {"id": "x"}},
		"struct":        credentials{User: "alice", Password: plaintext, Token: Secret(plaintext), Note: "Bearer " + plaintext},
		"struct_ptr":    &credentials{User: "bob", Password: plaintext},
		"string_map":    map[string]string{"user": "carol", "token": plaintext},
		"unmarshalable": make(chan int),
	}
	out := RedactMap(in)

	asJSON, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(asJSON), plaintext) {
		t.Fatalf("redacted map still contains the plaintext: %s", asJSON)
	}
	for _, key := range []string{"deployment_id", "count", "ratio", "ok", "nothing"} {
		if !reflect.DeepEqual(out[key], in[key]) {
			t.Errorf("%s = %v, want it untouched (%v)", key, out[key], in[key])
		}
	}
	nested := out["nested"].(map[string]any)
	if nested["token"] != Redacted || nested["safe"] != "Bearer "+Redacted {
		t.Errorf("nested = %v", nested)
	}
	list := nested["deeper"].(map[string]any)["list"].([]any)
	if list[0] != "ok" || list[1].(map[string]any)["secret"] != Redacted || list[2] != "Basic "+Redacted {
		t.Errorf("list inside nested maps = %v", list)
	}
	user := out["struct"].(map[string]any)
	if user["User"] != "alice" || user["Password"] != Redacted || user["api"] != Redacted {
		t.Errorf("struct = %v", user)
	}
	if out["string_map"].(map[string]any)["user"] != "carol" {
		t.Errorf("string_map = %v", out["string_map"])
	}
	if out["unmarshalable"] != Redacted {
		t.Errorf("a value JSON cannot represent must be masked, got %v", out["unmarshalable"])
	}
}

func TestRedactMapDoesNotMutateItsInput(t *testing.T) {
	inner := map[string]any{"password": plaintext}
	list := []any{map[string]any{"token": plaintext}}
	in := map[string]any{"inner": inner, "list": list, "msg": "Bearer " + plaintext}

	_ = RedactMap(in)

	if inner["password"] != plaintext || list[0].(map[string]any)["token"] != plaintext || in["msg"] != "Bearer "+plaintext {
		t.Error("RedactMap modified its input")
	}
}

func TestRedactMapNil(t *testing.T) {
	if got := RedactMap(nil); got != nil {
		t.Errorf("RedactMap(nil) = %v, want nil", got)
	}
}

func TestRedactMapKeepsOnlyCompleteReferencesInReferenceFields(t *testing.T) {
	kept := map[string]any{
		"credential_ref":    "secret://providers/home-pve/token",
		"client_secret_ref": "secret://oidc/client",
		"key_ref":           "file:///etc/supermgmt/id_ed25519",
		"agent_ref":         "ssh-agent://default",
	}
	for key, value := range RedactMap(kept) {
		if value != kept[key] {
			t.Errorf("%s = %v, a complete reference in a *_ref field must be kept", key, value)
		}
	}

	masked := map[string]any{
		"password":       "secret://x",
		"agent_password": "ssh-agent://default",
		"credential":     "secret://x",
		"api_key_ref":    "secret://x y",
		"cookie_ref":     "secret://" + plaintext + " trailing",
		"secret_ref":     "file://relative",
		"token_ref":      "ssh-agent://other",
		"passphrase":     plaintext,
		"dsn":            "postgres://u:" + plaintext + "@h/db",
		"credential_ref": plaintext,
	}
	for key, value := range RedactMap(masked) {
		if value != Redacted {
			t.Errorf("%s = %v, want it masked", key, value)
		}
	}
}
