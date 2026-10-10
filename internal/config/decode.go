package config

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Problem is one thing wrong with a configuration, located by YAML path.
type Problem struct {
	Path    string
	Line    int // 0 when unknown
	Message string
}

func (p Problem) String() string {
	loc := p.Path
	if loc == "" {
		loc = "(document)"
	}
	if p.Line > 0 {
		loc = fmt.Sprintf("%s (line %d)", loc, p.Line)
	}
	return loc + ": " + p.Message
}

// Problems is a multi-error: every problem found, not just the first.
type Problems []Problem

func (ps Problems) Error() string {
	lines := make([]string, len(ps))
	for i, p := range ps {
		lines[i] = p.String()
	}
	return strings.Join(lines, "; ")
}

func invalid(msg string, cause error) error {
	return smerr.Wrap(cause, smerr.CodeInvalidArgument, "", msg)
}

var durationType = reflect.TypeFor[time.Duration]()

// DecodeStrict decodes exactly one YAML document into v (a non-nil pointer).
// Unknown fields at any depth, duplicate keys, aliases, anchors and merge
// keys are errors that name the YAML path. Durations must be strings ("30s").
func DecodeStrict(r io.Reader, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return invalid("decode target must be a non-nil pointer", nil)
	}
	root, err := readSingleDocument(r)
	if err != nil {
		return err
	}
	w := &walker{}
	w.walk(root, rv.Elem().Type(), "")
	if len(w.problems) > 0 {
		return invalid("invalid configuration file", w.problems)
	}
	if err := root.Decode(v); err != nil {
		return invalid("invalid configuration file", err)
	}
	return nil
}

func readSingleDocument(r io.Reader) (*yaml.Node, error) {
	dec := yaml.NewDecoder(r)
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, invalid("empty configuration file", nil)
		}
		return nil, invalid("malformed YAML", err)
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return nil, invalid("configuration must contain exactly one YAML document", Problems{{Line: extra.Line, Message: "second document"}})
	case !errors.Is(err, io.EOF):
		return nil, invalid("malformed YAML", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, invalid("malformed YAML document", nil)
	}
	return doc.Content[0], nil
}

// walker checks a YAML node tree against a Go type: it finds what
// yaml.Node.Decode silently accepts (unknown and duplicate keys) and what
// this project forbids (aliases, anchors, merge keys, non-string durations).
type walker struct{ problems Problems }

func (w *walker) add(path string, n *yaml.Node, format string, args ...any) {
	w.problems = append(w.problems, Problem{Path: path, Line: n.Line, Message: fmt.Sprintf(format, args...)})
}

func (w *walker) walk(n *yaml.Node, t reflect.Type, path string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if n.Kind == yaml.AliasNode {
		w.add(path, n, "YAML aliases are not supported")
		return
	}
	if n.Anchor != "" {
		w.add(path, n, "YAML anchors are not supported")
	}
	switch {
	case t == durationType:
		w.walkDuration(n, path)
	case t == reflect.TypeFor[Provider]():
		w.walkProvider(n, path)
	case t.Kind() == reflect.Struct && n.Kind == yaml.MappingNode:
		w.walkStruct(n, t, path)
	case t.Kind() == reflect.Slice && n.Kind == yaml.SequenceNode:
		for i, item := range n.Content {
			w.walk(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

func (w *walker) walkDuration(n *yaml.Node, path string) {
	if n.Kind == yaml.ScalarNode && n.Tag != "!!str" && n.Tag != "!!null" {
		w.add(path, n, "duration must be a string with a unit, such as 30s")
	}
}

func (w *walker) walkProvider(n *yaml.Node, path string) {
	if n.Kind != yaml.MappingNode {
		return
	}
	branch, ok := providerBranches[scalarField(n, "type")]
	if !ok {
		w.add(path+".type", n, "unsupported provider type %q (supported: proxmox, ssh)", scalarField(n, "type"))
		return
	}
	w.walkStruct(n, branch, path)
}

func (w *walker) walkStruct(n *yaml.Node, t reflect.Type, path string) {
	fields := yamlFields(t)
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		child := joinPath(path, key.Value)
		if key.Tag == "!!merge" {
			w.add(path, key, "YAML merge keys are not supported")
			continue
		}
		if seen[key.Value] {
			w.add(child, key, "duplicate key")
			continue
		}
		seen[key.Value] = true
		field, known := fields[key.Value]
		if !known {
			w.add(child, key, "unknown field")
			continue
		}
		w.walk(val, field.Type, child)
	}
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// yamlFields indexes the exported fields of a struct by their yaml key.
func yamlFields(t reflect.Type) map[string]reflect.StructField {
	fields := map[string]reflect.StructField{}
	for i := range t.NumField() {
		f := t.Field(i)
		if key := yamlKey(f); key != "" {
			fields[key] = f
		}
	}
	return fields
}

func yamlKey(f reflect.StructField) string {
	key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	if key == "-" || !f.IsExported() {
		return ""
	}
	return key
}
