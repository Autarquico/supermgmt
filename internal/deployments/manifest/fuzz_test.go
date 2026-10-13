package manifest

import (
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

var manifestFuzzSeeds = []string{
	validManifest,
	header + "  health:\n    type: tcp\n    port: 5432\n",
	header + "  health:\n    type: docker-health\n",
	header + "  deployment: {}\n",
	header + "  image: evil\n",
	"a: &x 1\nb: *x\n",
	validManifest + "---\n" + validManifest,
	"apiVersion: supermgmt.dev/v1\nkind: Application\nmetadata: {name: a}\nspec: {health: {type: http, port: 1, path: '/', timeout: 99h}}\n",
	"",
	"[",
	strings.Repeat("a: [", 200),
}

// A manifest comes from a repository, so it is hostile input: it either parses
// into a bounded, defaulted manifest or fails with INVALID_ARGUMENT.
func FuzzManifest(f *testing.F) {
	for _, seed := range manifestFuzzSeeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			if code := smerr.CodeOf(err); code != smerr.CodeInvalidArgument {
				t.Fatalf("error code = %s, want INVALID_ARGUMENT: %v", code, err)
			}
			return
		}
		if m.APIVersion != APIVersion || m.Kind != Kind || strings.TrimSpace(m.Metadata.Name) == "" {
			t.Fatalf("accepted a manifest without its identity: %+v", m)
		}
		if h := m.Spec.Health; h != nil {
			manifestWantBoundedHealth(t, *h)
		}
	})
}

func manifestWantBoundedHealth(t *testing.T, h ManifestHealth) {
	t.Helper()
	if h.Timeout <= 0 || h.Timeout > maxHealthTimeout ||
		h.Interval <= 0 || h.Interval > maxHealthInterval ||
		h.Attempts <= 0 || h.Attempts > maxHealthAttempts {
		t.Fatalf("health timing out of bounds after defaults: %+v", h)
	}
}
