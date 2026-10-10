// Package yamlstrict decodes YAML documents strictly and reports every
// problem with its YAML path and line. It exists because yaml.v3's
// KnownFields option names no path and is ignored by yaml.Node.Decode.
//
// A document is accepted only if it has exactly one YAML document, no
// aliases, anchors or merge keys, no duplicate keys, no keys the target Go
// type does not declare (via yaml tags), and time.Duration fields given as
// strings such as "30s".
package yamlstrict

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// ErrEmpty is returned (possibly wrapped) for a document with no content.
var ErrEmpty = errors.New("empty document")

// Problem is one thing wrong with a document, located by YAML path.
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

// Selector picks the Go struct type that describes a union node. It returns
// a non-empty problem message when the node selects no known branch.
type Selector func(n *yaml.Node) (branch reflect.Type, problem string)

// Option customizes Decode.
type Option func(*walker)

// WithUnion makes nodes decoded into Go type t (a discriminated union with a
// custom UnmarshalYAML) be checked against the branch type sel selects.
func WithUnion(t reflect.Type, sel Selector) Option {
	return func(w *walker) { w.unions[t] = sel }
}

var durationType = reflect.TypeFor[time.Duration]()

// Decode decodes exactly one YAML document from r into v, a non-nil pointer.
// Errors are ErrEmpty, Problems, or wrap one of them / the YAML error.
func Decode(r io.Reader, v any, opts ...Option) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("decode target must be a non-nil pointer")
	}
	root, err := readSingleDocument(r)
	if err != nil {
		return err
	}
	w := &walker{unions: map[reflect.Type]Selector{}}
	for _, opt := range opts {
		opt(w)
	}
	w.walk(root, rv.Elem().Type(), "")
	if len(w.problems) > 0 {
		return w.problems
	}
	if err := root.Decode(v); err != nil {
		return fmt.Errorf("cannot decode: %w", err)
	}
	return nil
}

func readSingleDocument(r io.Reader) (*yaml.Node, error) {
	dec := yaml.NewDecoder(r)
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrEmpty
		}
		return nil, fmt.Errorf("malformed YAML: %w", err)
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return nil, fmt.Errorf("must contain exactly one YAML document: %w", Problems{{Line: extra.Line, Message: "second document"}})
	case !errors.Is(err, io.EOF):
		return nil, fmt.Errorf("malformed YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("malformed YAML document")
	}
	return doc.Content[0], nil
}

// walker checks a YAML node tree against a Go type: it finds what
// yaml.Node.Decode silently accepts (unknown and duplicate keys) and what
// this project forbids (aliases, anchors, merge keys, non-string durations).
type walker struct {
	problems Problems
	unions   map[reflect.Type]Selector
}

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
	if sel, ok := w.unions[t]; ok {
		w.walkUnion(n, sel, path)
		return
	}
	switch {
	case t == durationType:
		w.walkDuration(n, path)
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

func (w *walker) walkUnion(n *yaml.Node, sel Selector, path string) {
	if n.Kind != yaml.MappingNode {
		return
	}
	branch, problem := sel(n)
	if branch == nil {
		w.add(path+".type", n, "%s", problem)
		return
	}
	w.walkStruct(n, branch, path)
}

func (w *walker) walkStruct(n *yaml.Node, t reflect.Type, path string) {
	fields := Fields(t)
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		child := JoinPath(path, key.Value)
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

// JoinPath appends a mapping key to a YAML path.
func JoinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// Fields indexes the exported fields of a struct by their yaml key.
func Fields(t reflect.Type) map[string]reflect.StructField {
	fields := map[string]reflect.StructField{}
	for i := range t.NumField() {
		f := t.Field(i)
		if key := Key(f); key != "" {
			fields[key] = f
		}
	}
	return fields
}

// Key returns the yaml key of a struct field, or "" if it is not decoded.
func Key(f reflect.StructField) string {
	key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	if key == "-" || !f.IsExported() {
		return ""
	}
	return key
}
