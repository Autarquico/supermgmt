package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func policySeeds(f *testing.F) [][]byte {
	f.Helper()
	seeds := [][]byte{DefaultYAML()}
	example, err := os.ReadFile(filepath.Join("..", "..", "examples", "policies.yaml"))
	if err != nil {
		f.Fatal(err)
	}
	seeds = append(seeds, example)
	for _, seed := range []string{
		"", "version: 1\n", "version: 1\nrules: []\n", "version: 2\nrules: []\n",
		"version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['*']}\n",
		"version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['token.create'], require_approval: true}\n",
		"version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['*'], approvals: 9}\n",
		"version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['*'], bogus: 1}\n",
		"version: 1\nrules:\n  - {name: a, subjects: ['*'], allow: ['*']}\n---\nversion: 1\n",
		"version: 1\nrules:\n  - &x {name: a, subjects: ['*'], allow: ['*']}\n  - *x\n",
		"\xff\xfe", "[", "{{{", "version: 1\nrules: [null]\n",
	} {
		seeds = append(seeds, []byte(seed))
	}
	return seeds
}

// evaluationProbes are requests that touch every mode in the catalog.
func evaluationProbes() []Request {
	var probes []Request
	for _, spec := range Catalog() {
		caps := []string{}
		if spec.Capability != "" {
			caps = append(caps, spec.Capability)
		}
		resource := spec.Resource
		if resource == "" {
			resource = domain.ResourceNode
		}
		for _, a := range []domain.Actor{human("admin", "viewer"), automation("operator"), mcp("viewer")} {
			probes = append(probes, Request{
				Actor:   a,
				Action:  spec.Name,
				Params:  map[string]any{"verb": "stop"},
				Targets: []Target{target(resource, "t", prodAttrs, caps...)},
			})
		}
	}
	return probes
}

func validDecision(d Decision) bool {
	return d == DecisionAllow || d == DecisionDeny || d == DecisionCapabilityUnavailable
}

func FuzzParsePolicy(f *testing.F) {
	for _, seed := range policySeeds(f) {
		f.Add(seed)
	}
	probes := evaluationProbes()
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data) // must never panic
		if err != nil {
			return
		}
		if _, err := New(Document{Version: SupportedVersion, Rules: p.Rules()}); err != nil {
			t.Fatalf("Parse accepted a policy that does not validate: %v\n%q", err, data)
		}
		for _, req := range probes {
			if got := p.Evaluate(req); !validDecision(got.Decision) {
				t.Fatalf("Evaluate returned decision %q for %s\n%q", got.Decision, req.Action, data)
			}
		}
	})
}

func FuzzEvaluate(f *testing.F) {
	for _, seed := range policySeeds(f) {
		f.Add(seed, "node.reboot", "operator", "human", "production", 2)
	}
	f.Add([]byte{}, "node.reboot", "operator", "human", "production", 3)
	f.Add([]byte{}, "", "", "", "", -1)
	f.Add([]byte{}, "*", "*", "system", "dev", 99)
	f.Fuzz(func(t *testing.T, data []byte, action, role, actorType, env string, approvals int) {
		p, err := Parse(data)
		if err != nil {
			p, err = Default()
			if err != nil {
				t.Fatal(err)
			}
		}
		attrs := Attributes{Environment: env, EnvironmentRisk: domain.EnvironmentRiskLevel(env), ApprovalsRequired: approvals, Tags: []string{role}}
		req := Request{
			Actor:      actor(domain.ActorType(actorType), role),
			Action:     action,
			Targets:    []Target{nodeT(attrs, "node.reboot", "node.read")},
			SubActions: []SubAction{{Action: ActionSnapshotCreate, Target: nodeT(attrs)}},
		}
		got := p.Evaluate(req) // must never panic
		if !validDecision(got.Decision) {
			t.Fatalf("invalid decision %q", got.Decision)
		}
		if got.Quorum < 0 || got.Quorum > maxApprovals {
			t.Fatalf("quorum %d outside 0..%d", got.Quorum, maxApprovals)
		}
		if got.Decision != DecisionAllow && (got.ApprovalRequired || got.Quorum != 0) {
			t.Fatalf("non-allow result carries approval data: %+v", got)
		}
	})
}
