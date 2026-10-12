package compose

import "testing"

var fuzzSeeds = []string{
	validCompose,
	"",
	"services: {}\n",
	"x-a: &a [*a]\nservices: {}\n",
	"services:\n  web:\n    <<: [*x]\n",
	"services:\n  web:\n    image: x\n    environment: {A: \"${secret:db}$$$\"}\n",
	"a: !!binary aGk=\n",
	"---\na: 1\n---\nb: 2\n",
	"services:\n  web:\n    image: x\n    ports: ['8000-8010:80']\n",
}

// The checks sit on the untrusted border: whatever the author writes, they
// return an error or a result and never panic.
func FuzzCheckRaw(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = CheckRaw(raw, testTarget)
	})
}

func FuzzInterpolate(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := Interpolate(raw, testSource)
		if err != nil {
			return
		}
		// A successful pass yields a document the raw parser accepts again.
		if _, err := parseMerged(out); err != nil {
			t.Fatalf("output does not parse: %v\n%s", err, out)
		}
	})
}
