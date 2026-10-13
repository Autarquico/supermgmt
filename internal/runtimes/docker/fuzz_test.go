package docker

import "testing"

func FuzzDecodeInspect(f *testing.F) {
	f.Add([]byte(`[{"Id":"aaaa","Name":"/web","Config":{"Image":"x"},"State":{"Running":true,"Status":"running","StartedAt":"2026-01-01T00:00:00Z"}}]`))
	f.Add([]byte(`[{`))
	f.Add([]byte(`  `))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, out []byte) {
		all, err := decodeInspect(out)
		if err != nil && len(all) != 0 {
			t.Fatalf("error %v with %d results", err, len(all))
		}
		if len(all) > len(out) {
			t.Fatalf("%d containers from %d bytes", len(all), len(out))
		}
		for _, c := range all {
			_ = c.state()
		}
	})
}
