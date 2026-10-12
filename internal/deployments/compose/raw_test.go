package compose

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const validCompose = `
services:
  web:
    image: ghcr.io/acme/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    command: ["serve", "--port=8080"]
    environment:
      LOG_LEVEL: info
    ports:
      - target: 8080
        published: 8080
        host_ip: 127.0.0.1
        protocol: tcp
    volumes:
      - type: volume
        source: data
        target: /var/lib/data
    networks:
      backend:
        aliases: [api]
volumes:
  data:
networks:
  backend:
    internal: true
`

var testTarget = Target{
	Project:     "myapp",
	Owner:       "0198f3a0-0000-7000-8000-000000000001",
	AllowedBind: []netip.Addr{netip.MustParseAddr("10.0.0.5")},
}

func wantRejected(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted, want COMPOSE_REJECTED containing %q", contains)
	}
	var e *smerr.Error
	if !errors.As(err, &e) || e.Reason != smerr.ReasonComposeRejected || e.Code != smerr.CodeInvalidArgument {
		t.Fatalf("error = %v, want INVALID_ARGUMENT/COMPOSE_REJECTED", err)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error = %q, want it to contain %q", err, contains)
	}
	if e.Details["path"] == nil || e.Details["line"] == nil {
		t.Fatalf("details = %v, want path and line", e.Details)
	}
}

func TestCheckRaw_AcceptsAValidDocument(t *testing.T) {
	if err := CheckRaw([]byte(validCompose), testTarget); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRaw_Step1(t *testing.T) {
	tests := []struct{ name, doc, want string }{
		{"include", "include: [other.yaml]\nservices: {}\n", `"include"`},
		{"secrets", "secrets: {}\nservices: {}\n", `"secrets"`},
		{"configs", "configs: {}\nservices: {}\n", `"configs"`},
		{"name", "name: x\nservices: {}\n", `"name"`},
		{"extends", "services:\n  web:\n    image: x\n    extends: {service: base}\n", "extends"},
		{"extends in extension block", "x-base:\n  extends: {service: base}\nservices: {}\n", "extends"},
		{"env_file", "services:\n  web:\n    image: x\n    env_file: [.env]\n", "env_file"},
		{"env_file in list item", "x-a:\n  - env_file: x\nservices: {}\n", "env_file"},
		{"two documents", validCompose + "\n---\nservices: {}\n", "exactly one"},
		{"empty", "", "empty"},
		{"comment only", "# nothing\n", "empty"},
		{"scalar document", "just text\n", "mapping"},
		{"explicit tag", "x-a: !!binary aGk=\nservices: {}\n", "tags"},
		{"duplicate key", "services: {}\nservices: {}\n", "duplicate"},
		{"non-string key", "1: a\nservices: {}\n", "keys must be strings"},
		{"invalid yaml", "services: [\n", "invalid YAML"},
		{"oversize", "x-pad: " + strings.Repeat("a", MaxRawBytes) + "\nservices: {}\n", "limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantRejected(t, CheckRaw([]byte(tt.doc), testTarget), tt.want)
		})
	}
}

func TestCheckRaw_AliasExpansionBombIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("x-a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 8; i++ {
		fmt.Fprintf(&b, "x-a%d: &a%d [", i, i)
		for j := 0; j < 10; j++ {
			fmt.Fprintf(&b, "*a%d,", i-1)
		}
		b.WriteString("]\n")
	}
	b.WriteString("services: {}\n")
	wantRejected(t, CheckRaw([]byte(b.String()), testTarget), "expands to more than")
}

func TestCheckRaw_SelfReferencingAliasIsRejected(t *testing.T) {
	if err := CheckRaw([]byte("x-a: &a [*a]\nservices: {}\n"), testTarget); err == nil {
		t.Fatal("accepted a cyclic alias")
	}
}

func TestParseMerged_MergeKeySemantics(t *testing.T) {
	doc := `
x-base: &base
  restart: always
  user: "1000"
x-other: &other
  restart: "no"
  init: true
services:
  web:
    <<: [*base, *other]
    image: x
    user: "2000"
`
	root, err := parseMerged([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range root.get("services").get("web").entries {
		got[e.key] = e.val.value
	}
	want := map[string]string{"restart": "always", "user": "2000", "init": "true", "image": "x"}
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (earlier merge source wins, explicit key wins over merge)", k, got[k], v)
		}
	}
}

func TestParseMerged_MergeKeyNeedsAMapping(t *testing.T) {
	_, err := parseMerged([]byte("services:\n  web:\n    <<: [1, 2]\n"))
	wantRejected(t, err, "merge key needs a mapping")
}
