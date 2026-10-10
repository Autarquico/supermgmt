package plan

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// maxSafeInteger is 2^53-1, the largest integer every JSON implementation
// represents exactly.
const maxSafeInteger = 1<<53 - 1

// maxDepth bounds nesting of parameters and of canonicalized documents.
const maxDepth = 64

// checker records the first violation while a plan is validated.
type checker struct{ err error }

func (c *checker) fail(format string, args ...any) {
	if c.err == nil {
		c.err = invalid(format, args...)
	}
}

func (c *checker) text(path, s string) string {
	if !utf8.ValidString(s) {
		c.fail("%s is not valid UTF-8", path)
	}
	return s
}

func (c *checker) optText(path string, s *string) *string {
	if s != nil {
		c.text(path, *s)
	}
	return s
}

func (c *checker) integer(path string, v int64) int64 {
	if v < 0 || v > maxSafeInteger {
		c.fail("%s = %d is outside [0, 2^53-1]", path, v)
	}
	return v
}

func (c *checker) optInteger(path string, v *int64) *int64 {
	if v != nil {
		c.integer(path, *v)
	}
	return v
}

// normalize returns a validated copy of p with every set sorted by the
// Appendix C rules and every nil slice or map made empty. The caller's plan is
// not modified.
func normalize(p *Plan) (Plan, error) {
	if p == nil {
		return Plan{}, invalid("is nil")
	}
	c := &checker{}
	if p.Version != Version {
		c.fail("version %d is not supported (want %d)", p.Version, Version)
	}
	if !p.Risk.Valid() {
		c.fail("risk %q is not a risk class", p.Risk)
	}
	n := Plan{
		Version: p.Version,
		Action:  c.text("action", p.Action),
		Actor:   c.text("actor", p.Actor),
		Risk:    p.Risk,
		Steps:   normalizeSteps(c, p.Steps),
	}
	n.Targets = sortedUnique(c, "targets", p.Targets, normalizeTarget(c), compareTargets)
	n.Inputs = sortedUnique(c, "inputs", p.Inputs, normalizeInput(c), compareInputs)
	n.Content = normalizeContent(c, p.Content)
	n.SubActions = sortedUnique(c, "sub_actions", p.SubActions, normalizeSubAction(c), compareSubActions)
	n.Parameters = normalizeParameters(c, p.Parameters)
	return n, c.err
}

// sortedUnique maps every item through each, sorts the copy and reports
// duplicate keys (two items that compare equal), which would otherwise make
// the order, and so the hash, depend on input order.
func sortedUnique[T any](c *checker, name string, items []T, each func(i int, item T) T, cmp func(a, b T) int) []T {
	out := make([]T, len(items))
	for i, item := range items {
		out[i] = each(i, item)
	}
	slices.SortStableFunc(out, cmp)
	for i := 1; i < len(out); i++ {
		if cmp(out[i-1], out[i]) == 0 {
			c.fail("%s contains a duplicate entry", name)
			break
		}
	}
	return out
}

func normalizeSteps(c *checker, steps []string) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = c.text(fmt.Sprintf("steps[%d]", i), s)
	}
	return out
}

func normalizeTarget(c *checker) func(int, Target) Target {
	return func(i int, t Target) Target {
		path := fmt.Sprintf("targets[%d]", i)
		return Target{
			Type:         c.text(path+".type", t.Type),
			ID:           c.text(path+".id", t.ID),
			SpecRevision: c.optInteger(path+".spec_revision", t.SpecRevision),
		}
	}
}

func normalizeInput(c *checker) func(int, Input) Input {
	return func(i int, in Input) Input {
		path := fmt.Sprintf("inputs[%d]", i)
		out := Input{
			Type:                c.text(path+".type", in.Type),
			ID:                  c.text(path+".id", in.ID),
			SpecRevision:        c.optInteger(path+".spec_revision", in.SpecRevision),
			Version:             c.optInteger(path+".version", in.Version),
			HostPublicKeySHA256: c.optText(path+".host_public_key_sha256", in.HostPublicKeySHA256),
		}
		if in.Endpoint != nil {
			out.Endpoint = &Endpoint{
				Address: c.text(path+".endpoint.address", in.Endpoint.Address),
				Port:    c.integer(path+".endpoint.port", in.Endpoint.Port),
				User:    c.text(path+".endpoint.user", in.Endpoint.User),
			}
		}
		return out
	}
}

func normalizeSubAction(c *checker) func(int, SubAction) SubAction {
	return func(i int, s SubAction) SubAction {
		path := fmt.Sprintf("sub_actions[%d]", i)
		return SubAction{
			Action: c.text(path+".action", s.Action),
			Target: SubTarget{
				Type: c.text(path+".target.type", s.Target.Type),
				ID:   c.text(path+".target.id", s.Target.ID),
			},
		}
	}
}

func normalizeContent(c *checker, in Content) Content {
	out := Content{
		CommitSHA:            c.optText("content.commit_sha", in.CommitSHA),
		ManifestBlobSHA:      c.optText("content.manifest_blob_sha", in.ManifestBlobSHA),
		ComposeHash:          c.optText("content.compose_hash", in.ComposeHash),
		ExceptionsHash:       c.optText("content.exceptions_hash", in.ExceptionsHash),
		HealthHash:           c.optText("content.health_hash", in.HealthHash),
		DeploymentPolicyHash: c.optText("content.deployment_policy_hash", in.DeploymentPolicyHash),
	}
	out.Images = sortedUnique(c, "content.images", in.Images, func(i int, img Image) Image {
		path := fmt.Sprintf("content.images[%d]", i)
		return Image{
			Service: c.text(path+".service", img.Service),
			Ref:     c.text(path+".ref", img.Ref),
			Binding: c.text(path+".binding", img.Binding),
		}
	}, func(a, b Image) int { return strings.Compare(a.Service, b.Service) })

	out.HostPorts = sortedUnique(c, "content.host_ports", in.HostPorts, func(i int, port string) string {
		return c.text(fmt.Sprintf("content.host_ports[%d]", i), port)
	}, strings.Compare)

	if in.RollbackTarget != nil {
		out.RollbackTarget = &RollbackTarget{
			DeploymentID: c.text("content.rollback_target.deployment_id", in.RollbackTarget.DeploymentID),
			ComposeHash:  c.text("content.rollback_target.compose_hash", in.RollbackTarget.ComposeHash),
		}
	}
	out.SecretBindings = sortedUnique(c, "content.secret_bindings", in.SecretBindings,
		func(i int, b SecretBinding) SecretBinding {
			path := fmt.Sprintf("content.secret_bindings[%d]", i)
			return SecretBinding{
				Service:  c.text(path+".service", b.Service),
				EnvName:  c.text(path+".env_name", b.EnvName),
				SecretID: c.text(path+".secret_id", b.SecretID),
				Version:  c.integer(path+".version", b.Version),
			}
		}, func(a, b SecretBinding) int {
			return cmpChain(strings.Compare(a.Service, b.Service), strings.Compare(a.EnvName, b.EnvName))
		})
	return out
}

func compareTargets(a, b Target) int {
	return cmpChain(strings.Compare(a.Type, b.Type), strings.Compare(a.ID, b.ID))
}

func compareInputs(a, b Input) int {
	return cmpChain(strings.Compare(a.Type, b.Type), strings.Compare(a.ID, b.ID))
}

// compareSubActions orders by (action, target id) as Appendix C requires, then
// by target type so two sub-actions that differ only in type still have a
// deterministic order.
func compareSubActions(a, b SubAction) int {
	return cmpChain(strings.Compare(a.Action, b.Action), strings.Compare(a.Target.ID, b.Target.ID),
		strings.Compare(a.Target.Type, b.Target.Type))
}

// cmpChain returns the first non-zero comparison.
func cmpChain(results ...int) int {
	for _, r := range results {
		if r != 0 {
			return r
		}
	}
	return 0
}

func normalizeParameters(c *checker, params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		path := "parameters." + k
		c.text("parameters key "+path, k)
		out[k] = normalizeValue(c, path, v, 1)
	}
	return out
}

// normalizeValue checks that v is a JSON value without floats and returns a
// deep copy. Integers are checked through their exact representation, never by
// converting to float64.
func normalizeValue(c *checker, path string, v any, depth int) any {
	if depth > maxDepth {
		c.fail("%s is nested deeper than %d levels", path, maxDepth)
		return nil
	}
	switch t := v.(type) {
	case nil, bool:
		return t
	case string:
		return c.text(path, t)
	case json.Number:
		return checkNumberText(c, path, t)
	case int:
		return c.integer(path, int64(t))
	case int8:
		return c.integer(path, int64(t))
	case int16:
		return c.integer(path, int64(t))
	case int32:
		return c.integer(path, int64(t))
	case int64:
		return c.integer(path, t)
	case uint:
		return unsigned(c, path, uint64(t))
	case uint8:
		return unsigned(c, path, uint64(t))
	case uint16:
		return unsigned(c, path, uint64(t))
	case uint32:
		return unsigned(c, path, uint64(t))
	case uint64:
		return unsigned(c, path, t)
	case float32, float64:
		c.fail("%s is a float (%v); floats are forbidden in plans", path, t)
		return nil
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = normalizeValue(c, fmt.Sprintf("%s[%d]", path, i), item, depth+1)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			c.text(path+" key", k)
			out[k] = normalizeValue(c, path+"."+k, item, depth+1)
		}
		return out
	default:
		c.fail("%s has unsupported type %T", path, v)
		return nil
	}
}

func unsigned(c *checker, path string, v uint64) uint64 {
	if v > maxSafeInteger {
		c.fail("%s = %d is outside [0, 2^53-1]", path, v)
	}
	return v
}

func checkNumberText(c *checker, path string, n json.Number) json.Number {
	if _, err := integerText(string(n)); err != nil {
		c.fail("%s: %v", path, err)
	}
	return n
}
