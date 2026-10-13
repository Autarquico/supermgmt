package compose

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Equivalent compares the expected effective model with the masked model the
// node's compose.verify printed (spec §20.3 step 10, ADR-0006, ADR-0010). Both
// sides carry `environment` values as sha256 digests, so the comparison never
// sees a secret. cliMasked is the masked model itself (the `model` member of
// the verify output).
//
// It returns one entry per difference, each naming a path and a kind and never
// a value, so the list is safe to log and to return in an error. The only
// difference ignored is a declared network or volume no service uses, which
// the CLI omits (normalize.go). Empty diffs means equivalent.
func Equivalent(expectedMasked json.RawMessage, cliMasked []byte) (diffs []string, err error) {
	expected, err := equivalenceDecode(expectedMasked, "expected model")
	if err != nil {
		return nil, err
	}
	cli, err := equivalenceDecode(cliMasked, "node model")
	if err != nil {
		return nil, err
	}
	pruneUnusedResources(expected.(map[string]any))
	var d equivalenceDiffs
	d.compare(nil, expected, cli)
	sort.Strings(d)
	return d, nil
}

func equivalenceDecode(data []byte, what string) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, smerr.FromReason(smerr.ReasonStagingFailed, what+" is not valid JSON")
	}
	if _, isObject := v.(map[string]any); !isObject || dec.More() {
		return nil, smerr.FromReason(smerr.ReasonStagingFailed, what+" is not a single JSON object")
	}
	return v, nil
}

type equivalenceDiffs []string

func (d *equivalenceDiffs) add(path []string, kind string) {
	*d = append(*d, equivalencePath(path)+": "+kind)
}

func (d *equivalenceDiffs) compare(path []string, expected, cli any) {
	switch e := expected.(type) {
	case map[string]any:
		if c, ok := cli.(map[string]any); ok {
			d.compareObjects(path, e, c)
			return
		}
	case []any:
		if c, ok := cli.([]any); ok {
			d.compareArrays(path, e, c)
			return
		}
	default:
		if expected == cli {
			return
		}
	}
	d.add(path, "differs")
}

func (d *equivalenceDiffs) compareObjects(path []string, expected, cli map[string]any) {
	for key, e := range expected {
		c, ok := cli[key]
		if !ok {
			d.add(append(path, key), "missing from node output")
			continue
		}
		d.compare(append(path, key), e, c)
	}
	for key, c := range cli {
		if _, ok := expected[key]; ok {
			continue
		}
		d.unexpected(append(path, key), c)
	}
}

// unexpected names the leaves of a CLI-only subtree, so the diff points at the
// field and not just at its parent.
func (d *equivalenceDiffs) unexpected(path []string, cli any) {
	if object, ok := cli.(map[string]any); ok && len(object) > 0 {
		for key, child := range object {
			d.unexpected(append(path, key), child)
		}
		return
	}
	d.add(path, "unexpected in node output")
}

func (d *equivalenceDiffs) compareArrays(path []string, expected, cli []any) {
	if len(expected) != len(cli) {
		d.add(path, "length differs")
		return
	}
	for i := range expected {
		d.compare(append(path, strconv.Itoa(i)), expected[i], cli[i])
	}
}

func equivalencePath(path []string) string {
	if len(path) == 0 {
		return "(model)"
	}
	return strings.Join(path, ".")
}
