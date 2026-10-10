package config

import (
	"io"
	"reflect"

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
func DecodeStrict(r io.Reader, v any) error {
	err := yamlstrict.Decode(r, v, yamlstrict.WithUnion(reflect.TypeFor[Provider](), selectProviderBranch))
	if err != nil {
		return invalid("invalid configuration file", err)
	}
	return nil
}

func yamlKey(f reflect.StructField) string { return yamlstrict.Key(f) }

func joinPath(parent, key string) string { return yamlstrict.JoinPath(parent, key) }
