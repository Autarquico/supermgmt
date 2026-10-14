package installer

import (
	"slices"
	"strings"
	"testing"
)

const staleID = "ab12cd34"

// plantJournal leaves a journal the way a crashed run would.
func plantJournal(t *testing.T, w *aw, id string, entries ...journalEntry) *journal {
	t.Helper()
	j, err := createJournal(w, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		seq, err := j.begin(e.Step, e.Resource, e.Name)
		if err != nil {
			t.Fatal(err)
		}
		if e.Phase != "" && e.Phase != phasePending {
			if err := j.mark(seq, e.Phase); err != nil {
				t.Fatal(err)
			}
		}
	}
	w.ops, w.opLog = 0, nil
	return j
}

func TestStaleJournal_OnlyTrustsPrivateRootOwnedEntries(t *testing.T) {
	tests := map[string]struct {
		dir  *EntryInfo // override for the journal directory
		file *EntryInfo // override for journal.jsonl
	}{
		"directory owned by another user": {dir: &EntryInfo{Dir: true, UID: 1000, Mode: 0o700}},
		"directory open to others":        {dir: &EntryInfo{Dir: true, Mode: 0o777}},
		"directory that is a symlink":     {dir: &EntryInfo{Mode: 0o777}},
		"journal owned by another user":   {file: &EntryInfo{Regular: true, UID: 1000, Mode: 0o600}},
		"journal writable by others":      {file: &EntryInfo{Regular: true, Mode: 0o666}},
		"journal that is a symlink":       {file: &EntryInfo{Mode: 0o777}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			w := newAW(t)
			j := plantJournal(t, w, staleID, journalEntry{Step: "S12a", Resource: resUser, Name: userIDFor(staleID)})
			w.users[userIDFor(staleID)] = "ours"
			if tc.dir != nil {
				w.entries[j.dir] = *tc.dir
			}
			if tc.file != nil {
				w.entries[j.path()] = *tc.file
			}
			err := w.recoverStale()
			if exitCodeOf(t, err) != ExitConfiguration || !strings.Contains(err.Error(), "inspect and remove it by hand") {
				t.Fatalf("err = %v", err)
			}
			if w.users[userIDFor(staleID)] == "" || !w.Exists(j.path()) || len(w.asked) != 0 {
				t.Error("an untrusted journal was acted on")
			}
		})
	}
}

func TestStaleJournal_IgnoresNamesThisInstallerNeverWrites(t *testing.T) {
	w := newAW(t)
	for _, name := range []string{"supermgmt-installer-evil", "supermgmt-installer-AB12CD34", "supermgmt-installer-ab12cd34x", "supermgmt-installer-"} {
		dir := journalTmpRoot + "/" + name
		w.dirs[dir] = true
		w.files[dir+"/keep"] = []byte("x")
	}
	if err := w.recoverStale(); err != nil {
		t.Fatal(err)
	}
	if got := w.hostPaths("/var/tmp/supermgmt-installer-"); len(got) != 8 {
		t.Errorf("look-alike directories were touched: %v", got)
	}
}

func TestStaleJournal_NeverDeletesOutsideItsStagingDirectory(t *testing.T) {
	for _, victim := range []string{"/etc/precious", "/var/tmp/other", "/var/tmp/supermgmt-installer-" + staleID + "/../../etc/precious", "/var/tmp/supermgmt-installer-" + staleID + "/stage/../journal.jsonl"} {
		t.Run(victim, func(t *testing.T) {
			w := newAW(t)
			w.files["/etc/precious"] = []byte("data")
			w.files["/var/tmp/other"] = []byte("data")
			j := plantJournal(t, w, staleID, journalEntry{Step: "S12e", Resource: resHostTemp, Name: victim})
			err := w.recoverStale()
			if err == nil || !strings.Contains(err.Error(), "staging directory") {
				t.Fatalf("err = %v", err)
			}
			if string(w.files["/etc/precious"]) != "data" || string(w.files["/var/tmp/other"]) != "data" || !w.Exists(j.path()) {
				t.Errorf("a path outside the staging directory was removed: %v", w.opLog)
			}
		})
	}
}

func TestStaleJournal_IdentityProofIsTheExactName(t *testing.T) {
	foreign := "ops-" + staleID + "@pve" // carries the install id, but is not what this install creates
	w := newAW(t)
	w.users[foreign] = "foreign"
	w.roles["Admin-"+staleID] = "foreign"
	plantJournal(t, w, staleID,
		journalEntry{Step: "S12a", Resource: resUser, Name: foreign},
		journalEntry{Step: "S12b", Resource: resRole, Name: "Admin-" + staleID},
	)
	err := w.recoverStale()
	if err == nil || !strings.Contains(err.Error(), "not one this install") {
		t.Fatalf("err = %v", err)
	}
	if w.users[foreign] == "" || w.roles["Admin-"+staleID] == "" || len(w.violations) > 0 {
		t.Errorf("an object that merely contains the install id was removed (violations %v)", w.violations)
	}
}

func TestJournal_RefusesContentThisInstallerCannotHaveWritten(t *testing.T) {
	tests := map[string]string{
		"unknown resource":      `{"seq":2,"step":"S1","phase":"pending","resource":"filesystem","name":"/"}`,
		"unknown phase":         `{"seq":2,"step":"S1","phase":"maybe","resource":"lxc","name":"900"}`,
		"sequence gap":          `{"seq":5,"step":"S7","phase":"pending","resource":"lxc","name":"900"}`,
		"first entry elsewhere": "",
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			w := newAW(t)
			j := plantJournal(t, w, staleID)
			if line == "" {
				w.files[j.path()] = []byte(`{"seq":1,"step":"S0","phase":"pending","resource":"journal","name":"deadbeef"}` + "\n")
			} else {
				w.files[j.path()] = append(w.files[j.path()], []byte(line+"\n")...)
			}
			if _, err := openJournal(w, j.dir); err == nil {
				t.Fatal("the journal was accepted")
			}
		})
	}
}

func TestStaleJournal_UnreadableRecordMeansUnknownNotUncommitted(t *testing.T) {
	for name, record := range map[string][]byte{
		"malformed JSON":          []byte("{not json"),
		"record without an id":    []byte(`{"vmid":900}`),
		"record for another VMID": []byte(`{"install_id":"` + staleID + `","vmid":901}`),
	} {
		t.Run(name, func(t *testing.T) {
			w := newAW(t)
			w.guests[900] = &fakeGuest{desc: ownershipMark(staleID), status: "running", tags: []string{applianceTag}, unpriv: true}
			w.dirs[appliancesDir] = true
			w.files[recordPath(900)] = record
			j := plantJournal(t, w, staleID, journalEntry{Step: "S7", Resource: resLXC, Name: "900", Phase: phaseDone})
			err := w.recoverStale()
			if exitCodeOf(t, err) != ExitConfiguration || !strings.Contains(err.Error(), "whether it completed is unknown") {
				t.Fatalf("err = %v", err)
			}
			if g := w.guests[900]; g == nil || g.status != "running" || !w.Exists(j.path()) || len(w.asked) != 0 {
				t.Error("a possibly working appliance was stopped, destroyed or its journal dropped")
			}
		})
	}
}

func TestStaleJournal_RecordThatCannotBeReadMeansUnknown(t *testing.T) {
	w := newAW(t)
	w.guests[900] = &fakeGuest{desc: ownershipMark(staleID), status: "running", tags: []string{applianceTag}, unpriv: true}
	w.dirs[appliancesDir] = true
	w.files[recordPath(900)] = []byte(`{"install_id":"` + staleID + `","vmid":900}`)
	w.unreadable = map[string]bool{recordPath(900): true}
	plantJournal(t, w, staleID, journalEntry{Step: "S7", Resource: resLXC, Name: "900", Phase: phaseDone})
	if err := w.recoverStale(); err == nil || !strings.Contains(err.Error(), "whether it completed is unknown") {
		t.Fatalf("err = %v", err)
	}
	if w.guests[900] == nil || w.guests[900].status != "running" {
		t.Error("a possibly working appliance was touched")
	}
}

func TestStaleJournal_MissingRecordStillRollsBack(t *testing.T) {
	w := newAW(t)
	w.guests[900] = &fakeGuest{desc: ownershipMark(staleID), status: "stopped", tags: []string{applianceTag}, unpriv: true}
	plantJournal(t, w, staleID, journalEntry{Step: "S7", Resource: resLXC, Name: "900", Phase: phaseDone})
	if err := w.recoverStale(); err != nil {
		t.Fatal(err)
	}
	if len(w.guests) != 0 {
		t.Error("an install without a record was not rolled back")
	}
}

func TestInstall_ACreationThatFailsWhileTheObjectExistsIsKeptNotDeleted(t *testing.T) {
	for _, kind := range []string{"user", "role", "token"} {
		t.Run(kind, func(t *testing.T) {
			w := newAW(t)
			w.raceCreate = map[string]bool{kind: true}
			err := w.install(fastHooks())
			if err == nil || !strings.Contains(err.Error(), "NOT fully rolled back") || !strings.Contains(err.Error(), "may be somebody else's") {
				t.Fatalf("err = %v", err)
			}
			if len(w.violations) > 0 {
				t.Errorf("rollback removed the other party's object: %v", w.violations)
			}
			var foreign []string
			foreign = append(foreign, mapKeysWith(w.users, "foreign")...)
			foreign = append(foreign, mapKeysWith(w.roles, "foreign")...)
			foreign = append(foreign, mapKeysWith(w.tokens, "foreign")...)
			if len(foreign) != 1 {
				t.Errorf("the other party's object is gone: %v", foreign)
			}
		})
	}
}

func mapKeysWith(m map[string]string, value string) []string {
	var out []string
	for k, v := range m {
		if v == value {
			out = append(out, k)
		}
	}
	return out
}

func TestInstall_AccessInformationIsShownOnceTheRecordIsDurable(t *testing.T) {
	failures := map[string]func(*aw) int{
		"committing the journal": func(w *aw) int {
			return slices.IndexFunc(w.opLog, func(op string) bool {
				return strings.HasPrefix(op, "host.append ") && strings.Contains(op, "supermgmt-installer-")
			}) + 1
		},
		"removing the journal": func(w *aw) int {
			return lastIndex(w.opLog, func(op string) bool {
				return strings.HasPrefix(op, "host.rm "+journalRoot+"/") && !strings.HasSuffix(op, "/stage")
			}) + 1
		},
	}
	probe := newAW(t)
	probe.mustInstall(t)
	for name, locate := range failures {
		t.Run(name, func(t *testing.T) {
			w := newAW(t)
			// the commit entry is the last append of the run
			w.failAt = locate(probe)
			if name == "committing the journal" {
				w.failAt = lastIndex(probe.opLog, func(op string) bool { return strings.HasPrefix(op, "host.append ") }) + 1
			}
			err := w.install(fastHooks())
			if err == nil || !strings.Contains(err.Error(), "run the installer again to finish it") {
				t.Fatalf("err = %v", err)
			}
			if out := w.out.String(); !strings.Contains(out, "BOOT-1234") || !strings.Contains(out, "sm profile add") {
				t.Errorf("the one-time access information was lost:\n%s", out)
			}
			if len(w.hostPaths(appliancesDir+"/")) != 1 {
				t.Error("the appliance record is missing")
			}
		})
	}
}

func lastIndex(ops []string, match func(string) bool) int {
	for i := len(ops) - 1; i >= 0; i-- {
		if match(ops[i]) {
			return i
		}
	}
	return -1
}
