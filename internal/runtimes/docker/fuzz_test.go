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
			_ = detail(c)
		}
	})
}

func FuzzParseStats(f *testing.F) {
	f.Add([]byte(`{"ID":"a","Name":"web","CPUPerc":"0.50%","MemUsage":"1.5MiB / 2GiB"}` + "\n"))
	f.Add([]byte("json\njson\n"))
	f.Add([]byte(`{"CPUPerc":"1e999%","MemUsage":"1e999MiB / 1B"}`))
	f.Add([]byte(`{"CPUPerc":"NaN","MemUsage":"99999999999999999999GiB / 1B"}`))
	f.Fuzz(func(t *testing.T, out []byte) {
		stats, err := parseStats(out)
		if err != nil && len(stats) != 0 {
			t.Fatalf("error %v with %d results", err, len(stats))
		}
		for _, s := range stats {
			if s.CPUPercent < 0 || s.CPUPercent != s.CPUPercent {
				t.Fatalf("cpu = %v", s.CPUPercent)
			}
		}
	})
}

func FuzzParseSize(f *testing.F) {
	for _, s := range []string{"1.5MiB", "0B", "2GiB", "1.2kB", "", ".", "..5B", "1e5MiB", "9999999999999999999TiB", "-1B"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseSize(s)
		_, _, _ = parseMemUsage(s)
	})
}
