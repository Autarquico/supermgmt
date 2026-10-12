package proxmox

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const sampleUPID = "UPID:pve1:000003E9:000003EA:6B49D200:qmstart:100:sm-ab12cd34@pve!sm:"

func TestParseUPID(t *testing.T) {
	u, err := ParseUPID(sampleUPID)
	if err != nil {
		t.Fatal(err)
	}
	want := UPID{
		Raw: sampleUPID, Node: "pve1", PID: 0x3E9, PStart: 0x3EA, StartTime: time.Unix(0x6B49D200, 0).UTC(),
		Type: "qmstart", ID: "100", User: "sm-ab12cd34@pve!sm",
	}
	if u != want {
		t.Errorf("got %+v\nwant %+v", u, want)
	}
}

func TestParseUPIDRefusesAnythingElse(t *testing.T) {
	tests := map[string]string{
		"empty":           "",
		"wrong prefix":    strings.Replace(sampleUPID, "UPID", "XPID", 1),
		"missing trailer": strings.TrimSuffix(sampleUPID, ":"),
		"extra field":     sampleUPID + "x:",
		"too few fields":  "UPID:pve1:000003E9:000003EA:6B49D200:qmstart:100:",
		"non-hex pid":     strings.Replace(sampleUPID, "000003E9", "ZZZZZZZZ", 1),
		"empty starttime": strings.Replace(sampleUPID, "6B49D200", "", 1),
		"signed hex":      strings.Replace(sampleUPID, "000003E9", "+00003E9", 1),
		"path in node":    strings.Replace(sampleUPID, "pve1", "pve1/..", 1),
		"empty node":      strings.Replace(sampleUPID, "pve1", "", 1),
		"uppercase type":  strings.Replace(sampleUPID, "qmstart", "QmStart", 1),
		"empty type":      strings.Replace(sampleUPID, "qmstart", "", 1),
		"empty user":      strings.Replace(sampleUPID, "sm-ab12cd34@pve!sm", "", 1),
	}
	for name, raw := range tests {
		if _, err := ParseUPID(raw); err == nil {
			t.Errorf("%s: %q must be refused", name, raw)
		}
	}
}

func TestTaskType(t *testing.T) {
	tests := []struct {
		guest GuestType
		verb  string
		want  string
		ok    bool
	}{
		{GuestQEMU, "start", "qmstart", true},
		{GuestQEMU, "shutdown", "qmshutdown", true},
		{GuestLXC, "start", "vzstart", true},
		{GuestLXC, "reboot", "vzreboot", true},
		{GuestLXC, "stop", "vzstop", true},
		{GuestLXC, "suspend", "", false},
		{"vm", "start", "", false},
	}
	for _, tt := range tests {
		got, err := TaskType(tt.guest, tt.verb)
		if got != tt.want || (err == nil) != tt.ok {
			t.Errorf("TaskType(%q, %q) = %q, %v", tt.guest, tt.verb, got, err)
		}
	}
}

func TestCorrelationWindow(t *testing.T) {
	at := time.Unix(1_000_000, 0)
	from, until := CorrelationWindow(at, 30*time.Second)
	if !from.Equal(at.Add(-120*time.Second)) || !until.Equal(at.Add(150*time.Second)) {
		t.Errorf("window = [%v, %v]", from, until)
	}
}

func task(t *testing.T, start int64, typ, id, user string) TaskStatus {
	t.Helper()
	u, err := ParseUPID(fmt.Sprintf("UPID:pve1:000003E9:000003EA:%08X:%s:%s:%s:", start, typ, id, user))
	if err != nil {
		t.Fatal(err)
	}
	return TaskStatus{UPID: u, Status: "stopped", ExitStatus: "OK"}
}

func TestCorrelate(t *testing.T) {
	const user = "sm-ab@pve!sm"
	want := Want{Type: "qmstop", VMID: 100, User: user, From: time.Unix(1000, 0), Until: time.Unix(2000, 0)}
	match := task(t, 1500, "qmstop", "100", user)
	tests := []struct {
		name  string
		tasks []TaskStatus
		want  CorrelationResult
	}{
		{"nothing listed", nil, CorrelatedNone},
		{"exact match", []TaskStatus{match}, CorrelatedOne},
		{"window start is inclusive", []TaskStatus{task(t, 1000, "qmstop", "100", user)}, CorrelatedOne},
		{"window end is inclusive", []TaskStatus{task(t, 2000, "qmstop", "100", user)}, CorrelatedOne},
		{"earlier task", []TaskStatus{task(t, 999, "qmstop", "100", user)}, CorrelatedNone},
		{"later task", []TaskStatus{task(t, 2001, "qmstop", "100", user)}, CorrelatedNone},
		{"other guest type", []TaskStatus{task(t, 1500, "vzstop", "100", user)}, CorrelatedNone},
		{"other verb", []TaskStatus{task(t, 1500, "qmstart", "100", user)}, CorrelatedNone},
		{"other vmid", []TaskStatus{task(t, 1500, "qmstop", "101", user)}, CorrelatedNone},
		{"vmid that only shares a prefix", []TaskStatus{task(t, 1500, "qmstop", "1000", user)}, CorrelatedNone},
		{"user that contains ours", []TaskStatus{task(t, 1500, "qmstop", "100", "x"+user)}, CorrelatedNone},
		{"user that is contained in ours", []TaskStatus{task(t, 1500, "qmstop", "100", "sm-ab@pve")}, CorrelatedNone},
		{"other token of the same user", []TaskStatus{task(t, 1500, "qmstop", "100", "sm-ab@pve!other")}, CorrelatedNone},
		{"noise around one match", []TaskStatus{task(t, 10, "qmstop", "100", user), match, task(t, 1500, "qmstop", "7", user)}, CorrelatedOne},
		{"two matches", []TaskStatus{match, task(t, 1600, "qmstop", "100", user)}, CorrelatedMany},
		{"the same task listed twice counts once", []TaskStatus{match, match}, CorrelatedOne},
	}
	for _, tt := range tests {
		got, result := Correlate(tt.tasks, want)
		if result != tt.want {
			t.Errorf("%s: result = %d, want %d", tt.name, result, tt.want)
		}
		if (result == CorrelatedOne) != (got.Raw != "") {
			t.Errorf("%s: UPID %q returned for result %d", tt.name, got.Raw, result)
		}
	}
}
