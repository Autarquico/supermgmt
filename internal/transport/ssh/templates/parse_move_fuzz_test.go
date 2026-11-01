package templates

import (
	"math"
	"testing"
	"time"
)

func FuzzParseInfoResources(f *testing.F) {
	for _, seed := range []string{`{"NCPU":12,"MemTotal":8216776704}` + "\n", `{"NCPU":0,"MemTotal":1}`, `{"NCPU":1}`, `{"NCPU":1,"MemTotal":1,"x":1}`, `{"NCPU":1,"MemTotal":99999999999999999999}`, "", `{} {}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ParseInfoResources(in)
		if err == nil && (got.NCPU <= 0 || got.MemTotal <= 0) {
			t.Errorf("%q parsed as %+v", in, got)
		}
	})
}

func FuzzParseVolumeSizes(f *testing.F) {
	for _, seed := range []string{
		`{"Volumes":[{"Name":"shop_data","Size":"3MB"},{"Name":"shop_cache","Size":"1.23GB"},{"Name":"shop_zero","Size":"0B"}]}`,
		`{"Volumes":[]}`, `{"Volumes":[{"Name":"v","Size":"N/A"}]}`, `{"Volumes":[{"Name":"v","Size":"1e3B"}]}`,
		`{"Volumes":[{"Name":"v","Size":"99999999999PB"}]}`, `{"Volumes":[{"Name":"v","Size":"1B"},{"Name":"v","Size":"1B"}]}`, `{}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		sizes, err := ParseVolumeSizes(in)
		if err != nil {
			return
		}
		for name, n := range sizes {
			if n < 0 || ValidateVolume(name) != nil {
				t.Errorf("%q parsed volume %q as %d bytes", in, name, n)
			}
		}
	})
}

func FuzzParseVolumeInspectMany(f *testing.F) {
	for _, seed := range []string{
		`[{"Name":"shop_data","Driver":"local","Labels":{"a":"b"}}]`, `[]`, `null`, `[{"Name":"v","Driver":""}]`,
		`[{"Name":"v","Driver":"local"},{"Name":"v","Driver":"local"}]`, `[{"Name":"../x","Driver":"local"}]`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		volumes, err := ParseVolumeInspectMany(in)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, v := range volumes {
			if ValidateVolume(v.Name) != nil || v.Driver == "" || seen[v.Name] {
				t.Errorf("%q parsed unusable volume %+v", in, v)
			}
			seen[v.Name] = true
		}
	})
}

func FuzzParsePsState(f *testing.F) {
	const project = "shop"
	line := func(state, labels string) string {
		return `{"ID":"0123456789ab","Names":"shop-web-1","State":"` + state + `","Labels":"` + labels + `"}` + "\n"
	}
	ok := "com.docker.compose.project=shop,com.docker.compose.service=web"
	for _, seed := range []string{
		line("running", ok), line("exited", ok) + line("created", ok), "", "\n", line("weird", ok),
		line("running", ok+",a,b"), line("running", ok+",com.docker.compose.service=api"), line("running", "com.docker.compose.project=other,com.docker.compose.service=web"),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		containers, err := ParsePsState(in, project)
		if err != nil {
			return
		}
		for _, c := range containers {
			if !containerStates[c.State] || c.Service == "" || c.Labels[composeProjectLabel] != project {
				t.Errorf("%q parsed unusable container %+v", in, c)
			}
		}
	})
}

func FuzzParseDeadlineArg(f *testing.F) {
	for _, seed := range []string{"600s", "0s", "1s", "86400s", "86401s", "99999999999999999999s", "-5s", "5", "5m", " 5s", "05s", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		d, err := parseDeadlineArg(in)
		if err == nil && (d < 0 || d > MaxStreamDeadline || d%time.Second != 0 || d == math.MaxInt64) {
			t.Errorf("%q parsed as %s", in, d)
		}
	})
}
