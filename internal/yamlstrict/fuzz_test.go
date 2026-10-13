package yamlstrict

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

type strictFuzzTarget struct {
	Name  string             `yaml:"name"`
	Wait  time.Duration      `yaml:"wait"`
	Flag  *bool              `yaml:"flag"`
	Items []strictFuzzTarget `yaml:"items"`
	Extra map[string]string  `yaml:"extra"`
}

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"", "name: a\n", "name: a\nwait: 30s\nflag: true\n", "items:\n  - name: b\n  - name: c\n",
		"bogus: 1\n", "name: a\nname: b\n", "name: &x a\nextra: {k: *x}\n", "base: &b {name: a}\nitems: [<<: *b]\n",
		"name: a\n---\nname: b\n", "wait: 30\n", "wait: 1h30m\n", "[", "{{{", "\xff\xfe", "name: !!binary aGk=\n",
		"items: [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\n",
		"extra:\n  ? [a]\n  : b\n", "name: |\n  line\n  line\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		first := Decode(bytes.NewReader(data), new(strictFuzzTarget))
		second := Decode(bytes.NewReader(data), new(strictFuzzTarget))
		if (first == nil) != (second == nil) || (first != nil && first.Error() != second.Error()) {
			t.Fatalf("decoding is not deterministic: %v then %v", first, second)
		}
		var problems Problems
		if errors.As(first, &problems) && len(problems) == 0 {
			t.Fatalf("a Problems error carries no problem: %v", first)
		}
	})
}
