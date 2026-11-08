package config

import (
	"fmt"
	"io"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/yamlstrict"
)

// Problem and Problems are the shared strict-decoding diagnostics.
type (
	Problem  = yamlstrict.Problem
	Problems = yamlstrict.Problems
)

func invalid(msg string, cause error) error {
	return smerr.Wrap(cause, smerr.CodeInvalidArgument, "", msg)
}

// DecodeStrict decodes exactly one YAML document into v (a non-nil pointer).
// Unknown fields at any depth, duplicate keys, aliases, anchors and merge
// keys are errors that name the YAML path. Durations must be strings ("30s").
//
// Blocks and providers that ADR-0043 retired are dropped, not rejected; their
// warnings are returned.
func DecodeStrict(r io.Reader, v any) ([]string, error) {
	var warnings []string
	err := yamlstrict.Decode(r, v,
		yamlstrict.WithUnion(reflect.TypeFor[Provider](), selectProviderBranch),
		yamlstrict.WithRetired(retiredConfig, &warnings))
	if err != nil {
		return nil, invalid("invalid configuration file", err)
	}
	return warnings, nil
}

// retiredConfig recognises the top-level blocks github: and health: and the
// providers of type github, which ADR-0043 removed with the deployment engine.
func retiredConfig(path string, n *yaml.Node) (string, bool) {
	switch {
	case path == "github" || path == "health":
		return fmt.Sprintf("config block %s: was retired by ADR-0043 and is ignored; remove it", path), true
	case strings.HasPrefix(path, "providers[") && scalarField(n, "type") == "github":
		return fmt.Sprintf("%s: provider of type github was retired by ADR-0043 and is ignored; remove it", path), true
	}
	return "", false
}

func yamlKey(f reflect.StructField) string { return yamlstrict.Key(f) }

func joinPath(parent, key string) string { return yamlstrict.JoinPath(parent, key) }
