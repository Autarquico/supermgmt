package templates

import (
	"strings"
	"testing"
)

func TestParseInfoResources(t *testing.T) {
	got, err := ParseInfoResources([]byte(`{"NCPU":12,"MemTotal":8216776704}` + "\n"))
	if err != nil || got.NCPU != 12 || got.MemTotal != 8216776704 {
		t.Fatalf("got %+v, %v", got, err)
	}
	for name, in := range map[string]string{
		"empty": "", "zero cpus": `{"NCPU":0,"MemTotal":1}`, "negative memory": `{"NCPU":1,"MemTotal":-1}`,
		"missing memory": `{"NCPU":1}`, "missing cpus": `{"MemTotal":1}`, "overflow": `{"NCPU":1,"MemTotal":99999999999999999999}`,
		"fraction": `{"NCPU":1.5,"MemTotal":1}`, "unknown field": `{"NCPU":1,"MemTotal":1,"x":1}`, "string": `{"NCPU":"1","MemTotal":1}`,
		"trailing": `{"NCPU":1,"MemTotal":1} {}`, "array": `[1]`, "null": `null`, "text": "NCPU=1",
	} {
		if got, err := ParseInfoResources([]byte(in)); err == nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
}

// dfOutput is the shape docker system df -v --format json prints (Docker 26-29),
// reduced to the volumes and one other section.
const dfOutput = `{"Images":[{"ID":"sha256:83","Size":"4.11MB"}],"Containers":[],"Volumes":[` +
	`{"Availability":"N/A","Driver":"local","Labels":"a=b","Links":"1","Mountpoint":"/var/lib/docker/volumes/mvgate_data/_data","Name":"mvgate_data","Scope":"local","Size":"3MB","Status":"N/A"},` +
	`{"Name":"mvgate_state","Size":"22B"},{"Name":"big","Size":"1.23GB"},{"Name":"empty","Size":"0B"}],"BuildCache":[]}`

func TestParseVolumeSizesRoundsUp(t *testing.T) {
	got, err := ParseVolumeSizes([]byte(dfOutput))
	if err != nil {
		t.Fatal(err)
	}
	for name, atLeast := range map[string]int64{"mvgate_data": 3_000_000, "mvgate_state": 22, "big": 1_230_000_000, "empty": 0} {
		v, ok := got[name]
		if !ok || v < atLeast || v > atLeast+atLeast/50+1 {
			t.Errorf("%s = %d (%v), want %d rounded up by about 1%%", name, v, ok, atLeast)
		}
	}
	if len(got) != 4 {
		t.Errorf("got %d volumes", len(got))
	}
	if sizes, err := ParseVolumeSizes([]byte(`{"Volumes":[]}`)); err != nil || len(sizes) != 0 {
		t.Errorf("no volumes: %v %v", sizes, err)
	}
}

func TestParseVolumeSizesFailsClosed(t *testing.T) {
	vol := func(name, size string) string { return `{"Volumes":[{"Name":"` + name + `","Size":"` + size + `"}]}` }
	for name, in := range map[string]string{
		"empty": "", "no volumes section": `{"Images":[]}`, "null volumes": `{"Volumes":null}`, "unknown size": vol("v", "N/A"),
		"no unit": vol("v", "12"), "bad unit": vol("v", "12XB"), "negative": vol("v", "-3MB"), "empty size": vol("v", ""),
		"huge": vol("v", "99999999999PB"), "inf": vol("v", "1e999MB"), "exponent": vol("v", "1e3MB"), "bad name": vol("-v", "1MB"),
		"duplicate": `{"Volumes":[{"Name":"v","Size":"1B"},{"Name":"v","Size":"1B"}]}`, "trailing": dfOutput + "x", "array": "[]",
	} {
		if got, err := ParseVolumeSizes([]byte(in)); err == nil {
			t.Errorf("%s accepted: %v", name, got)
		}
	}
}

func TestParseVolumeInspectMany(t *testing.T) {
	in := `[{"CreatedAt":"2026-11-01T07:31:17Z","Driver":"local","Labels":{"com.docker.compose.project":"mvgate"},"Mountpoint":"/x","Name":"mvgate_data","Options":null,"Scope":"local"},` +
		`{"Driver":"local","Labels":null,"Name":"loose"}]`
	got, err := ParseVolumeInspectMany([]byte(in))
	if err != nil || len(got) != 2 || got[0].Labels["com.docker.compose.project"] != "mvgate" || got[1].Labels != nil {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, err := ParseVolumeInspectMany([]byte("[]\n")); err != nil || len(got) != 0 {
		t.Errorf("empty array: %v %v", got, err)
	}
	for name, in := range map[string]string{
		"empty": "", "null": "null", "object": `{}`, "no name": `[{"Driver":"local"}]`, "no driver": `[{"Name":"v"}]`,
		"bad name": `[{"Name":"a b","Driver":"local"}]`, "duplicate": `[{"Name":"v","Driver":"l"},{"Name":"v","Driver":"l"}]`,
		"labels not strings": `[{"Name":"v","Driver":"l","Labels":{"a":1}}]`, "trailing": `[] []`,
	} {
		if got, err := ParseVolumeInspectMany([]byte(in)); err == nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
}

const psLine = `{"Command":"\"sleep infinity\"","ID":"55f1898056469c17ca27f7f8fc28ddb08920c2ab91c6c71b740ef746765a39c9","Image":"sm-move-seed:1",` +
	`"Labels":"com.docker.compose.project=mvgate,com.docker.compose.service=web,com.docker.compose.depends_on=,com.docker.compose.project.config_files=/srv/x/compose.yaml","Names":"mvgate-web-1","State":"exited","Status":"Exited (0) 2 seconds ago"}`

func TestParsePsState(t *testing.T) {
	got, err := ParsePsState([]byte(psLine+"\n"+strings.ReplaceAll(psLine, "web", "db")+"\n"), "mvgate")
	if err != nil || len(got) != 2 || got[0].State != "exited" || got[0].Service != "web" || got[1].Service != "db" || got[0].Name != "mvgate-web-1" {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, empty := range []string{"", "\n"} {
		if got, err := ParsePsState([]byte(empty), "mvgate"); err != nil || len(got) != 0 {
			t.Errorf("no containers: %v %v", got, err)
		}
	}
	bad := map[string]string{
		"other project":   strings.Replace(psLine, "project=mvgate", "project=other", 1),
		"no service":      strings.Replace(psLine, "service=web", "svc=web", 1),
		"unknown state":   strings.Replace(psLine, `"exited"`, `"zombie"`, 1),
		"no state":        strings.Replace(psLine, `"State":"exited",`, "", 1),
		"no id":           strings.Replace(psLine, `"ID":"55f1898056469c17ca27f7f8fc28ddb08920c2ab91c6c71b740ef746765a39c9"`, `"ID":""`, 1),
		"two names":       strings.Replace(psLine, "mvgate-web-1", "mvgate-web-1,other/link", 1),
		"comma in label":  strings.Replace(psLine, "/srv/x/compose.yaml", "/srv/x,y/compose.yaml", 1),
		"duplicate label": strings.Replace(psLine, "service=web", "service=web,com.docker.compose.project=mvgate", 1),
		"not json":        "mvgate-web-1 exited",
		"blank line":      psLine + "\n\n" + psLine,
		"trailing":        psLine + " x",
	}
	for name, in := range bad {
		if got, err := ParsePsState([]byte(in), "mvgate"); err == nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
}
