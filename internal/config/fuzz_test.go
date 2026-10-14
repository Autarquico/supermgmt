package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const envFuzzSeparator = "\x00"

func loadFuzzSeeds(f *testing.F) {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil {
		f.Fatal(err)
	}
	files = append(files, filepath.Join("..", "..", "examples", "config.yaml"))
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, "HOME=/home/u"+envFuzzSeparator+"SUPERMGMT_NO_AUTOSTART=1")
	}
	for _, seed := range []string{
		"", "version: 1\n", "version: 1\ninstance:\n  mode: local\n", "version: 1\nbogus: true\n",
		"version: 2\n", "version: 1\ninstance:\n  mode: server\n", "{{{", "\xff\xfe",
	} {
		f.Add([]byte(seed), "HOME=/home/u")
	}
}

// FuzzLoadBytes feeds any document and environment (NUL-separated KEY=VALUE
// entries) through the whole load: decode, overrides, defaults, validation.
func FuzzLoadBytes(f *testing.F) {
	loadFuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte, env string) {
		res, err := LoadBytes(data, strings.Split(env, envFuzzSeparator))
		if err != nil {
			return
		}
		if res.Config == nil {
			t.Fatal("LoadBytes succeeded without a configuration")
		}
		if err := res.Config.Validate(); err != nil {
			t.Fatalf("a configuration LoadBytes accepted fails Validate: %v", err)
		}
	})
}

func FuzzParseEnv(f *testing.F) {
	for _, seed := range []string{
		"", "A=1", "A=1\x00B=2", "A", "=v", "A=", "A=b=c", "SUPERMGMT_NO_AUTOSTART=1\x00HOME=/h", "A=1\x00A=2", "\xff=\xfe",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, joined string) {
		entries := strings.Split(joined, envFuzzSeparator)
		values := parseEnv(entries)
		if len(values) > len(entries) {
			t.Fatalf("%d values from %d entries", len(values), len(entries))
		}
		for name, value := range values {
			if !slices.Contains(entries, name+"="+value) {
				t.Fatalf("value %s=%q does not come from any entry", name, value)
			}
		}
	})
}
