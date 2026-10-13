package compose

import (
	"strings"
	"testing"
)

func canonicalHashOfSource(t *testing.T, document string) string {
	t.Helper()
	s := freezeSource()
	s.Raw = []byte(document)
	return freezeOK(t, s, freezeTarget("prod")).Hash
}

func TestCanonical_HashIgnoresKeyOrderAndAnchors(t *testing.T) {
	reordered := `
volumes:
  data:
services:
  redis:
    volumes:
      - {target: /data, source: data, type: volume}
    image: ` + freezeRedis + `
  api:
    ports:
      - {host_ip: 127.0.0.1, published: 8080, target: 8080}
    environment:
      DATABASE_URL: ${secret:db_url}
      PRICE: $PRICE
      REGION: $REGION
    image: ghcr.io/acme/api:placeholder
`
	withLabels := func(second string) string {
		return strings.Replace(freezeDocument, "    volumes:\n      - {type", "    labels: "+second+"\n    volumes:\n      - {type", 1)
	}
	inline := strings.Replace(withLabels("{tier: backend}"), "    ports:", "    labels: {tier: backend}\n    ports:", 1)
	anchored := strings.Replace(withLabels("*tier"), "    ports:", "    labels: &tier {tier: backend}\n    ports:", 1)
	want := canonicalHashOfSource(t, freezeDocument)
	if got := canonicalHashOfSource(t, reordered); got != want {
		t.Errorf("reordered: hash %s, want %s", got, want)
	}
	if got, want := canonicalHashOfSource(t, anchored), canonicalHashOfSource(t, inline); got != want {
		t.Errorf("anchored: hash %s, want %s", got, want)
	}
}

func TestCanonical_HashChangesWithContent(t *testing.T) {
	base := canonicalHashOfSource(t, freezeDocument)
	changed := strings.Replace(freezeDocument, "published: 8080", "published: 8081", 1)
	if canonicalHashOfSource(t, changed) == base {
		t.Fatal("a different port kept the same hash")
	}
}

func TestCanonical_KeysSortedSequencesKeptInOrder(t *testing.T) {
	root, err := parseMerged([]byte("b: 1\na:\n  - z\n  - y\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := canonicalYAML(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), "\"a\":\n  - \"z\"\n  - \"y\"\n\"b\": 1\n"; got != want {
		t.Fatalf("canonical =\n%s\nwant\n%s", got, want)
	}
}
