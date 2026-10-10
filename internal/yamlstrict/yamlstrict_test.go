package yamlstrict

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

type inner struct {
	Wait time.Duration `yaml:"wait"`
}

type doc struct {
	Name  string  `yaml:"name"`
	Inner inner   `yaml:"inner"`
	Items []inner `yaml:"items"`
	Pick  pick    `yaml:"pick"`
}

type pick struct{ A *branchA }

type branchA struct {
	Kind string `yaml:"kind"`
	X    int    `yaml:"x"`
}

func (p *pick) UnmarshalYAML(n *yaml.Node) error {
	var b branchA
	if err := n.Decode(&b); err != nil {
		return err
	}
	p.A = &b
	return nil
}

func selectA(n *yaml.Node) (reflect.Type, string) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "kind" && n.Content[i+1].Value == "a" {
			return reflect.TypeFor[branchA](), ""
		}
	}
	return nil, "unsupported kind"
}

func decode(src string) error {
	var d doc
	return Decode(strings.NewReader(src), &d, WithUnion(reflect.TypeFor[pick](), selectA))
}

func TestDecodeReportsPathAndLine(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{"depth 1", "bogus: 1\n", "bogus (line 1): unknown field"},
		{"depth 3", "inner:\n  wiat: 1s\n", "inner.wiat (line 2): unknown field"},
		{"list item", "items:\n  - wait: 1s\n  - wiat: 1s\n", "items[1].wiat (line 3): unknown field"},
		{"union branch", "pick:\n  kind: a\n  y: 1\n", "pick.y (line 3): unknown field"},
		{"union without branch", "pick:\n  kind: z\n", "pick.type"},
		{"duplicate", "name: a\nname: b\n", "name (line 2): duplicate key"},
		{"duration number", "inner:\n  wait: 30\n", "inner.wait"},
		{"alias", "name: &n x\ninner: *n\n", "aliases are not supported"},
		{"merge", "inner:\n  <<: {wait: 1s}\n", "merge keys are not supported"},
		{"two documents", "name: a\n---\nname: b\n", "exactly one YAML document"},
		{"malformed", "name: [\n", "malformed YAML"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := decode(tt.src); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestDecodeEmptyAndTarget(t *testing.T) {
	if err := decode(""); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty: err = %v, want ErrEmpty", err)
	}
	if err := Decode(strings.NewReader("name: a\n"), doc{}); err == nil {
		t.Error("non-pointer target must be rejected")
	}
}

func TestDecodeAcceptsValidDocument(t *testing.T) {
	var d doc
	src := "name: a\ninner: {wait: 5s}\npick: {kind: a, x: 2}\n"
	if err := Decode(strings.NewReader(src), &d, WithUnion(reflect.TypeFor[pick](), selectA)); err != nil {
		t.Fatal(err)
	}
	if d.Inner.Wait != 5*time.Second || d.Pick.A == nil || d.Pick.A.X != 2 {
		t.Errorf("decoded %+v", d)
	}
}
