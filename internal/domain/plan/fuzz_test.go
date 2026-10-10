package plan

import (
	"slices"
	"strings"
	"testing"
)

func FuzzPlanHash(f *testing.F) {
	f.Add(readFile(f, "testdata/golden/plan.json"))
	for _, seed := range []string{
		`{}`, `null`, `[]`, "\xff",
		`{"version":3,"action":"node.reboot","actor":"a","targets":[],"inputs":[],"content":{},"sub_actions":[],"parameters":{"n":1.5},"steps":[],"risk":"high"}`,
		`{"version":3,"parameters":{"n":9007199254740993}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		hash, err := Hash(p) // must never panic
		if err != nil {
			return
		}
		if !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
			t.Fatalf("malformed hash %q", hash)
		}
		if again, err := Hash(p); err != nil || again != hash {
			t.Fatalf("hash is not deterministic: %q then %q, %v", hash, again, err)
		}
		reordered := *p
		reordered.Targets = reversed(p.Targets)
		reordered.Inputs = reversed(p.Inputs)
		reordered.SubActions = reversed(p.SubActions)
		if got, err := Hash(&reordered); err != nil || got != hash {
			t.Fatalf("set order changed the hash: %q vs %q, %v", hash, got, err)
		}
	})
}

func reversed[T any](items []T) []T {
	out := slices.Clone(items)
	slices.Reverse(out)
	return out
}
