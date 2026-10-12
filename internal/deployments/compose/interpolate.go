package compose

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const secretRefScheme = "secret://"

var secretPlaceholder = regexp.MustCompile(`^\$\{secret:([A-Za-z0-9_.-]+)\}$`)

// Interpolate performs spec §20.3 step 2: a single substitution pass by
// SuperMgmt over the merged source, never by the loader or the node CLI.
//
// Only environment values, command/entrypoint elements and service label
// values are substituted; a "$" anywhere else must be "$$". Every literal "$"
// of the result is re-escaped as "$$", so interpolating the output with an
// empty environment is the identity. Entries that are exactly
// "${secret:<ref-name>}" are removed from the result; SecretUses reports them.
// Interpolate assumes CheckRaw already passed.
func Interpolate(raw []byte, s Source) ([]byte, error) {
	out, _, err := interpolate(raw, s)
	return out, err
}

// SecretUses lists the secret references Interpolate removes from the public
// model, ordered by service and environment name. Versions are bound later
// (ADR-0008), so Version is zero.
func SecretUses(raw []byte, s Source) ([]SecretUse, error) {
	_, uses, err := interpolate(raw, s)
	return uses, err
}

func interpolate(raw []byte, s Source) ([]byte, []SecretUse, error) {
	root, err := parseMerged(raw)
	if err != nil {
		return nil, nil, err
	}
	r := rewriter{src: s}
	if err := r.node(root, nil); err != nil {
		return nil, nil, err
	}
	out, err := encode(root)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(r.uses, func(i, j int) bool {
		if r.uses[i].Service != r.uses[j].Service {
			return r.uses[i].Service < r.uses[j].Service
		}
		return r.uses[i].EnvName < r.uses[j].EnvName
	})
	return out, r.uses, nil
}

type rewriter struct {
	src  Source
	uses []SecretUse
}

// Path elements are mapping keys; sequence items appear as "#".
func (r *rewriter) node(n *node, path []string) error {
	switch n.kind {
	case scalarNode:
		return r.scalar(n, path)
	case sequenceNode:
		for _, item := range n.items {
			if err := r.node(item, append(path, "#")); err != nil {
				return err
			}
		}
	case mappingNode:
		return r.mapping(n, path)
	}
	return nil
}

func (r *rewriter) mapping(n *node, path []string) error {
	kept := n.entries[:0:0]
	for _, e := range n.entries {
		if err := requireEscapedDollars(e.key, e.keyLine, path); err != nil {
			return err
		}
		if ref, ok, err := r.secretEntry(e, path); err != nil {
			return err
		} else if ok {
			r.uses = append(r.uses, SecretUse{Service: path[1], EnvName: e.key, Ref: ref})
			continue
		}
		if err := r.node(e.val, append(path, e.key)); err != nil {
			return err
		}
		kept = append(kept, e)
	}
	n.entries = kept
	return nil
}

func (r *rewriter) scalar(n *node, path []string) error {
	if n.tag != "!!str" {
		return nil
	}
	if !substitutes(path) {
		return requireEscapedDollars(n.value, n.line, path)
	}
	v, err := r.substitute(n.value)
	if err != nil {
		return rejected(strings.Join(path, "."), n.line, "%v", err)
	}
	n.value = strings.ReplaceAll(v, "$", "$$")
	return nil
}

// substitutes reports whether a string at path is an interpolation site:
// services.<svc>.environment.<NAME>, services.<svc>.labels.<key> and
// services.<svc>.command|entrypoint[#].
func substitutes(path []string) bool {
	if len(path) != 4 || path[0] != "services" {
		return false
	}
	switch path[2] {
	case "environment", "labels":
		return path[3] != "#"
	case "command", "entrypoint":
		return path[3] == "#"
	}
	return false
}

func isEnvironmentValue(path []string) bool {
	return len(path) == 3 && path[0] == "services" && path[2] == "environment"
}

// secretEntry recognizes an environment entry whose whole value is a secret
// placeholder and resolves its ref-name to the secret path.
func (r *rewriter) secretEntry(e entry, path []string) (ref string, ok bool, err error) {
	if !isEnvironmentValue(path) || e.val.kind != scalarNode || e.val.tag != "!!str" {
		return "", false, nil
	}
	if !strings.HasPrefix(e.val.value, "${secret:") {
		return "", false, nil
	}
	m := secretPlaceholder.FindStringSubmatch(e.val.value)
	where := strings.Join(append(append([]string{}, path...), e.key), ".")
	if m == nil {
		return "", false, rejected(where, e.val.line, "a secret reference must be exactly ${secret:<ref-name>}")
	}
	target, found := r.src.SecretRefs[m[1]]
	if !found || !strings.HasPrefix(target, secretRefScheme) || len(target) == len(secretRefScheme) {
		return "", false, rejected(where, e.val.line, "secret reference %q is not defined in the app's secret_refs", m[1])
	}
	return strings.TrimPrefix(target, secretRefScheme), true, nil
}

// requireEscapedDollars enforces "a $ anywhere else is rejected, except $$".
func requireEscapedDollars(s string, line int, path []string) error {
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		if i+1 >= len(s) || s[i+1] != '$' {
			return rejected(strings.Join(path, "."), line, "interpolation is not allowed here; write $$ for a literal $")
		}
		i++
	}
	return nil
}

var variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// substitute expands one string: $$, $NAME and ${NAME} only.
func (r *rewriter) substitute(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		rest := s[i+1:]
		switch {
		case strings.HasPrefix(rest, "$"):
			b.WriteByte('$')
			i++
		case strings.HasPrefix(rest, "{"):
			end := strings.IndexByte(rest, '}')
			if end < 0 || !isVariableName(rest[1:end]) {
				return "", fmt.Errorf("unsupported interpolation form near %q", abbreviate(s[i:]))
			}
			v, err := r.variable(rest[1:end])
			if err != nil {
				return "", err
			}
			b.WriteString(v)
			i += end + 1
		default:
			name := variableName.FindString(rest)
			if name == "" {
				return "", fmt.Errorf("a lone $ near %q; write $$ for a literal $", abbreviate(s[i:]))
			}
			v, err := r.variable(name)
			if err != nil {
				return "", err
			}
			b.WriteString(v)
			i += len(name)
		}
	}
	return b.String(), nil
}

func isVariableName(s string) bool { return s != "" && variableName.FindString(s) == s }

func (r *rewriter) variable(name string) (string, error) {
	v, ok := r.src.Variables[name]
	if !ok {
		return "", fmt.Errorf("variable %q is not defined in the app's variables", name)
	}
	return v, nil
}

func abbreviate(s string) string {
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}

// encode serializes the merged tree as plain YAML: strings always double
// quoted so their type survives the round trip, no anchors, no aliases.
func encode(root *node) ([]byte, error) {
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(toYAML(root)); err != nil {
		return nil, fmt.Errorf("encode interpolated compose: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode interpolated compose: %w", err)
	}
	return []byte(buf.String()), nil
}

func toYAML(n *node) *yaml.Node {
	switch n.kind {
	case scalarNode:
		break
	case sequenceNode:
		out := &yaml.Node{Kind: yaml.SequenceNode}
		for _, item := range n.items {
			out.Content = append(out.Content, toYAML(item))
		}
		return out
	case mappingNode:
		out := &yaml.Node{Kind: yaml.MappingNode}
		for _, e := range n.entries {
			out.Content = append(out.Content, quoted(e.key), toYAML(e.val))
		}
		return out
	}
	if n.tag == "!!str" {
		return quoted(n.value)
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Value: n.value}
}

func quoted(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s, Style: yaml.DoubleQuotedStyle}
}
