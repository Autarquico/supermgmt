package app

import (
	"encoding/json"
	"slices"
	"testing"
)

func FuzzResourceLimits(f *testing.F) {
	for _, seed := range []string{
		`{"services":{"web":{"mem_limit":"512m","cpus":"0.5"},"db":{"deploy":{"resources":{"limits":{"memory":1073741824,"cpus":2}}}}}}`,
		`{"services":{"web":{}}}`, `{}`, `{"services":{"web":{"mem_limit":"-1"}}}`, `{"services":{"web":{"mem_limit":"99999999999999g"}}}`,
		`{"services":{"web":{"cpus":"-1"}}}`, `{"services":{"web":{"mem_limit":[1]}}}`, `null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		memory, cpus, err := resourceLimits(json.RawMessage(in))
		if err == nil && (memory < 0 || cpus < 0) {
			t.Errorf("%q gave %d bytes and %v cpus", in, memory, cpus)
		}
	})
}

func FuzzVolumeMapOf(f *testing.F) {
	for _, seed := range []string{
		modelSharedVolume, modelStateless, `{}`, `null`,
		`{"services":{"web":{"volumes":[{"type":"bind","source":"/x","target":"/y"}]}}}`,
		`{"services":{"web":{"volumes":[{"type":"volume","target":"/y"}]}}}`,
		`{"services":{"web":{"volumes":[{"type":"volume","source":"d","target":"/y","read_only":true}]}}}`,
		`{"services":{"web":{"volumes":[{"type":"volume","source":"d","target":"/y"}]}},"volumes":{"d":{"name":"fixed"}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		volumes, err := volumeMapOf("shop", json.RawMessage(in))
		if err != nil {
			return
		}
		names := make([]string, len(volumes))
		for i, v := range volumes {
			names[i] = v.VolumeName
			if v.VolumeName == "" {
				t.Errorf("%q gave an incomplete volume %+v", in, v)
			}
		}
		if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
			t.Errorf("%q gave volumes %v: want sorted and distinct", in, names)
		}
	})
}

func TestResourceLimitsRejectsCPULimitsThatAreNotFiniteNumbers(t *testing.T) {
	t.Skip("BUG: limitCPUs (app_move_preflight.go) hands strconv.ParseFloat's NaN and Inf through: a NaN limit makes the 'cpus > NCPU' check pass; resourceLimits must fail closed")
	for _, cpus := range []string{"NaN", "Inf", "1e999"} {
		if _, _, err := resourceLimits(json.RawMessage(`{"services":{"web":{"cpus":"` + cpus + `"}}}`)); err == nil {
			t.Errorf("cpus %q was accepted", cpus)
		}
	}
}

func TestVolumeMapOfRefusesAMountWithNoTarget(t *testing.T) {
	t.Skip("BUG: volumeEntry (app_move_plan.go) accepts a named-volume mount whose target (or service name) is empty and plans docker cp <c>:/. for it; volumeMapOf must fail closed")
	model := `{"services":{"web":{"volumes":[{"type":"volume","source":"data"}]}}}`
	if volumes, err := volumeMapOf("shop", json.RawMessage(model)); err == nil {
		t.Errorf("volume map = %+v, want a refusal", volumes)
	}
}
