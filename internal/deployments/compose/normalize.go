package compose

import "encoding/json"

// cliDefault is one field the Compose CLI adds to `config --format json` that
// the pinned loader's model does not carry. It is the only thing step 10 of
// the pipeline (spec §20.3, ADR-0006) ignores: a field present only in the CLI
// output, at a path matching Path, holding one of the Allowed values.
//
// Path is a dotted pattern over mapping keys and array indexes; "*" matches
// exactly one segment. Allowed holds compact JSON texts; empty means the value
// is derived from the project name (not constant) and any value is accepted.
// Evidence names the fixture that proves the CLI emits the field.
type cliDefault struct {
	Path     []string
	Allowed  []string
	Evidence string
}

// cliDefaults is the CLI-defaults normalization table. Every row was observed
// in `docker compose config --format json` output of the corpus file named in
// Evidence. Observed so far on Compose v5.0.2 only; the ADR-0006 matrix pins
// v5.5.1, so each row stays unproven for the matrix until the
// `compose-equivalence` job (T17a) runs the corpus on that version.
var cliDefaults = []cliDefault{
	{Path: []string{"name"}, Evidence: "basic.yaml: project name from -p"},
	{Path: []string{"networks", "default"}, Evidence: "basic.yaml: implicit default network"},
	{Path: []string{"networks", "*", "name"}, Evidence: "volumes_networks.yaml: project-prefixed name"},
	{Path: []string{"networks", "*", "ipam"}, Allowed: []string{`{}`}, Evidence: "volumes_networks.yaml"},
	{Path: []string{"volumes", "*", "name"}, Evidence: "volumes_networks.yaml: project-prefixed name"},
	{Path: []string{"services", "*", "command"}, Allowed: []string{`null`}, Evidence: "basic.yaml: service without command"},
	{Path: []string{"services", "*", "entrypoint"}, Allowed: []string{`null`}, Evidence: "basic.yaml: service without entrypoint"},
	{Path: []string{"services", "*", "networks", "default"}, Allowed: []string{`null`}, Evidence: "basic.yaml: service without networks"},
	{Path: []string{"services", "*", "depends_on", "*", "required"}, Allowed: []string{`true`}, Evidence: "basic.yaml: depends_on"},
	{Path: []string{"services", "*", "ports", "*", "mode"}, Allowed: []string{`"ingress"`}, Evidence: "ports_long.yaml"},
}

// normalizeIgnorable reports whether a field found only in the CLI output is a
// listed CLI default.
func normalizeIgnorable(path []string, value any) bool {
	for _, d := range cliDefaults {
		if normalizeMatches(d.Path, path) && normalizeAllowed(d.Allowed, value) {
			return true
		}
	}
	return false
}

func normalizeMatches(pattern, path []string) bool {
	if len(pattern) != len(path) {
		return false
	}
	for i := range pattern {
		if pattern[i] != "*" && pattern[i] != path[i] {
			return false
		}
	}
	return true
}

func normalizeAllowed(allowed []string, value any) bool {
	if len(allowed) == 0 {
		return true
	}
	text, err := json.Marshal(value)
	if err != nil {
		return false
	}
	for _, a := range allowed {
		if a == string(text) {
			return true
		}
	}
	return false
}
