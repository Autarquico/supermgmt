package compose

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPruneUnusedResources(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  string
	}{
		{
			"unused network and volume sections vanish",
			`{"services":{"app":{"image":"i"}},"networks":{"idle":{}},"volumes":{"idle":{}}}`,
			`{"services":{"app":{"image":"i"}}}`,
		},
		{
			"referenced ones stay, unreferenced go",
			`{"services":{"app":{"networks":{"back":null},"volumes":[{"type":"volume","source":"data","target":"/d"}]}},"networks":{"back":{},"idle":{}},"volumes":{"data":{},"idle":{}}}`,
			`{"services":{"app":{"networks":{"back":null},"volumes":[{"type":"volume","source":"data","target":"/d"}]}},"networks":{"back":{}},"volumes":{"data":{}}}`,
		},
		{
			"list-form service networks count as references",
			`{"services":{"app":{"networks":["back"]}},"networks":{"back":{},"idle":{}}}`,
			`{"services":{"app":{"networks":["back"]}},"networks":{"back":{}}}`,
		},
		{
			"bind and tmpfs mounts reference no volume",
			`{"services":{"app":{"volumes":[{"type":"bind","source":"data","target":"/d"},{"type":"tmpfs","target":"/t"}]}},"volumes":{"data":{}}}`,
			`{"services":{"app":{"volumes":[{"type":"bind","source":"data","target":"/d"},{"type":"tmpfs","target":"/t"}]}}}`,
		},
		{
			"the implicit default network is kept",
			`{"services":{"app":{}},"networks":{"default":{}}}`,
			`{"services":{"app":{}},"networks":{"default":{}}}`,
		},
		{
			"a model without services prunes everything declared",
			`{"networks":{"idle":{}}}`, `{}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got, want map[string]any
			if err := json.Unmarshal([]byte(tc.model), &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			pruneUnusedResources(got)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("pruned = %v, want %v", got, want)
			}
		})
	}
}
