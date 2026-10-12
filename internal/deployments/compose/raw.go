package compose

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Bounds on the expanded document. They stop alias expansion bombs and
// pathological nesting before any schema walk runs.
const (
	maxDepth = 64
	maxNodes = 50_000
)

type kind uint8

const (
	scalarNode kind = iota + 1
	sequenceNode
	mappingNode
)

// node is the merged YAML tree: aliases expanded, "<<" merge keys resolved,
// mapping keys plain strings. Everything downstream (schema walk,
// interpolation) sees only this form, so a construct introduced through an
// anchor or a merge is checked exactly like one written inline.
type node struct {
	kind    kind
	tag     string // short tag of a scalar: !!str, !!int, !!bool, !!float, !!null
	value   string
	items   []*node
	entries []entry
	line    int
}

type entry struct {
	key     string
	keyLine int
	val     *node
}

func (n *node) get(key string) *node {
	for _, e := range n.entries {
		if e.key == key {
			return e.val
		}
	}
	return nil
}

// CheckRaw applies spec §20.3 step 1 and the source-form half of the closed
// schema of steps 4-6 (ADR-0006, first pass) to the author's Compose text.
// It rejects what the pinned loader would silently rewrite or drop (version,
// short or ranged ports, string commands, list environments), and every
// privileged construct, however it was introduced.
func CheckRaw(raw []byte, t Target) error {
	root, err := parseMerged(raw)
	if err != nil {
		return err
	}
	if err := rejectForbiddenKeys(root); err != nil {
		return err
	}
	return checkSchema(root, t)
}

func rejected(path string, line int, format string, args ...any) error {
	where := pathOrRoot(path)
	e := smerr.FromReason(smerr.ReasonComposeRejected, fmt.Sprintf("%s (line %d): %s", where, line, fmt.Sprintf(format, args...)))
	e.Details = map[string]any{"path": where, "line": line}
	return e
}

func pathOrRoot(path string) string {
	if path == "" {
		return "<document>"
	}
	return path
}

func parseMerged(raw []byte) (*node, error) {
	if len(raw) > MaxRawBytes {
		return nil, rejected("", 1, "document is %d bytes, the limit is %d", len(raw), MaxRawBytes)
	}
	doc, err := decodeSingleDocument(raw)
	if err != nil {
		return nil, err
	}
	b := builder{budget: maxNodes}
	root, err := b.build(doc.Content[0], 0)
	if err != nil {
		return nil, err
	}
	if root.kind != mappingNode {
		return nil, rejected("", root.line, "the top level must be a mapping")
	}
	return root, nil
}

func decodeSingleDocument(raw []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, rejected("", 1, "the document is empty")
		}
		return nil, rejected("", 1, "invalid YAML: %v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, rejected("", extra.Line, "exactly one YAML document is allowed")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, rejected("", 1, "the document is empty")
	}
	return &doc, nil
}

type builder struct{ budget int }

func (b *builder) build(n *yaml.Node, depth int) (*node, error) {
	if depth > maxDepth {
		return nil, rejected("", n.Line, "nesting deeper than %d levels", maxDepth)
	}
	if b.budget--; b.budget < 0 {
		return nil, rejected("", n.Line, "document expands to more than %d nodes", maxNodes)
	}
	switch n.Kind {
	case yaml.AliasNode:
		return b.build(n.Alias, depth)
	case yaml.ScalarNode:
		return b.scalar(n)
	case yaml.SequenceNode:
		return b.sequence(n, depth)
	case yaml.MappingNode:
		return b.mapping(n, depth)
	case yaml.DocumentNode:
		break
	}
	return nil, rejected("", n.Line, "unsupported YAML node")
}

func (b *builder) scalar(n *yaml.Node) (*node, error) {
	if n.Style&yaml.TaggedStyle != 0 {
		return nil, rejected("", n.Line, "explicit YAML tags are not allowed")
	}
	return &node{kind: scalarNode, tag: n.ShortTag(), value: n.Value, line: n.Line}, nil
}

func (b *builder) sequence(n *yaml.Node, depth int) (*node, error) {
	out := &node{kind: sequenceNode, line: n.Line}
	for _, c := range n.Content {
		item, err := b.build(c, depth+1)
		if err != nil {
			return nil, err
		}
		out.items = append(out.items, item)
	}
	return out, nil
}

func (b *builder) mapping(n *yaml.Node, depth int) (*node, error) {
	var merged, explicit []entry
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind == yaml.ScalarNode && k.ShortTag() == "!!merge" {
			sources, err := b.mergeSources(v, depth)
			if err != nil {
				return nil, err
			}
			merged = append(merged, sources...)
			continue
		}
		key, err := b.key(k, depth)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, rejected("", k.Line, "duplicate key %q", key)
		}
		seen[key] = true
		val, err := b.build(v, depth+1)
		if err != nil {
			return nil, err
		}
		explicit = append(explicit, entry{key: key, keyLine: k.Line, val: val})
	}
	return &node{kind: mappingNode, entries: overlay(firstWins(merged), explicit), line: n.Line}, nil
}

func (b *builder) key(k *yaml.Node, depth int) (string, error) {
	kn, err := b.build(k, depth+1)
	if err != nil {
		return "", err
	}
	if kn.kind != scalarNode || kn.tag != "!!str" {
		return "", rejected("", k.Line, "mapping keys must be strings")
	}
	return kn.value, nil
}

// mergeSources resolves the value of a "<<" key into the entries it brings.
// Earlier sources win over later ones, as in YAML 1.1 merge semantics.
func (b *builder) mergeSources(v *yaml.Node, depth int) ([]entry, error) {
	targets := []*yaml.Node{v}
	if resolved := resolveAlias(v); resolved.Kind == yaml.SequenceNode {
		targets = resolved.Content
	}
	var out []entry
	for _, t := range targets {
		m, err := b.build(t, depth+1)
		if err != nil {
			return nil, err
		}
		if m.kind != mappingNode {
			return nil, rejected("", t.Line, "a merge key needs a mapping")
		}
		out = append(out, m.entries...)
	}
	return out, nil
}

func resolveAlias(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func firstWins(entries []entry) []entry {
	seen := map[string]bool{}
	var out []entry
	for _, e := range entries {
		if !seen[e.key] {
			seen[e.key] = true
			out = append(out, e)
		}
	}
	return out
}

// overlay returns merged entries with explicit entries replacing same-key
// ones in place and the rest appended.
func overlay(merged, explicit []entry) []entry {
	out := append([]entry(nil), merged...)
	index := map[string]int{}
	for i, e := range out {
		index[e.key] = i
	}
	for _, e := range explicit {
		if i, ok := index[e.key]; ok {
			out[i] = e
			continue
		}
		out = append(out, e)
	}
	return out
}

var forbiddenTopLevel = []string{"include", "secrets", "configs", "name"}

// forbiddenAnywhere are keys rejected at any depth, extension blocks
// included: an env_file or extends hidden in x-* could be merged into a
// service.
var forbiddenAnywhere = []string{"extends", "env_file"}

func rejectForbiddenKeys(root *node) error {
	for _, k := range forbiddenTopLevel {
		if root.get(k) != nil {
			return rejected(k, keyLine(root, k), "top-level key %q is not allowed", k)
		}
	}
	return walkKeys(root, "", func(path, key string, line int) error {
		for _, f := range forbiddenAnywhere {
			if key == f {
				return rejected(path, line, "key %q is not allowed", f)
			}
		}
		return nil
	})
}

func keyLine(m *node, key string) int {
	for _, e := range m.entries {
		if e.key == key {
			return e.keyLine
		}
	}
	return m.line
}

func walkKeys(n *node, path string, visit func(path, key string, line int) error) error {
	switch n.kind {
	case scalarNode:
		break
	case mappingNode:
		for _, e := range n.entries {
			p := joinPath(path, e.key)
			if err := visit(p, e.key, e.keyLine); err != nil {
				return err
			}
			if err := walkKeys(e.val, p, visit); err != nil {
				return err
			}
		}
	case sequenceNode:
		for i, item := range n.items {
			if err := walkKeys(item, fmt.Sprintf("%s[%d]", path, i), visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func isExtension(key string) bool { return strings.HasPrefix(key, "x-") }
