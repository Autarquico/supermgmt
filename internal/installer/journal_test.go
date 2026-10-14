package installer

import (
	"context"
	"strings"
	"testing"
)

func TestJournalCreationIsDurableBeforeAnySideEffect(t *testing.T) {
	w := newAW(t)
	j, err := createJournal(w, "ab12cd34")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"host.mkdir " + journalRoot, "host.mkdir " + journalRoot + "/ab12cd34", "host.syncdir " + journalRoot,
		"host.append " + journalRoot + "/ab12cd34/journal.jsonl", "host.syncdir " + journalRoot + "/ab12cd34",
	}
	if strings.Join(w.opLog, "|") != strings.Join(want, "|") {
		t.Errorf("ops:\n%v\nwant\n%v", w.opLog, want)
	}
	if _, err := createJournal(w, "ab12cd34"); err == nil {
		t.Error("a second journal with the same id must be refused")
	}
	if j.id != "ab12cd34" {
		t.Errorf("id %q", j.id)
	}
}

func TestJournalFoldsPhasesAndListsNewestFirst(t *testing.T) {
	w := newAW(t)
	j, _ := createJournal(w, "ab12cd34")
	a, _ := j.begin("S7", resLXC, "900")
	b, _ := j.begin("S12a", resUser, "sm-ab12cd34@pve")
	_ = j.mark(a, phaseDone)
	_ = j.mark(b, phaseUndone)
	got := j.toUndo()
	if len(got) != 1 || got[0].Resource != resLXC || got[0].Phase != phaseDone {
		t.Fatalf("toUndo = %+v", got)
	}
	re, err := openJournal(w, j.dir)
	if err != nil || len(re.toUndo()) != 1 {
		t.Fatalf("reopened: %v %+v", err, re)
	}
}

func TestJournalDiscardsATornLastLineAndRepairsTheFile(t *testing.T) {
	w := newAW(t)
	j, _ := createJournal(w, "ab12cd34")
	_, _ = j.begin("S7", resLXC, "900")
	w.files[j.path()] = append(w.files[j.path()], []byte(`{"seq":3,"step":"S12a","pha`)...)

	re, err := openJournal(w, j.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(re.entries) != 2 {
		t.Fatalf("entries = %+v", re.entries)
	}
	if strings.Contains(string(w.files[j.path()]), "S12a") || !strings.HasSuffix(string(w.files[j.path()]), "\n") {
		t.Errorf("file not repaired: %q", w.files[j.path()])
	}
	if _, err := re.begin("S12a", resUser, "sm-ab12cd34@pve"); err != nil {
		t.Fatal(err)
	}
	if again, err := openJournal(w, j.dir); err != nil || len(again.entries) != 3 {
		t.Fatalf("after append: %v %+v", err, again)
	}
}

func TestJournalTornLineEndingInNewlineIsAlsoDiscarded(t *testing.T) {
	w := newAW(t)
	j, _ := createJournal(w, "ab12cd34")
	w.files[j.path()] = append(w.files[j.path()], []byte("{\"seq\":2,\n")...)
	re, err := openJournal(w, j.dir)
	if err != nil || len(re.entries) != 1 {
		t.Fatalf("%v %+v", err, re)
	}
}

func TestJournalCorruptionInTheMiddleIsAnError(t *testing.T) {
	w := newAW(t)
	j, _ := createJournal(w, "ab12cd34")
	w.files[j.path()] = append([]byte("garbage\n"), w.files[j.path()]...)
	if _, err := openJournal(w, j.dir); err == nil {
		t.Fatal("corruption before the tail must not be skipped")
	}
}

func TestJournalCommittedEntry(t *testing.T) {
	w := newAW(t)
	j, _ := createJournal(w, "ab12cd34")
	if j.isCommitted() {
		t.Fatal("fresh journal is committed")
	}
	_ = j.commit()
	re, _ := openJournal(w, j.dir)
	if !re.isCommitted() || len(re.toUndo()) != 0 {
		t.Errorf("committed journal: %+v", re.entries)
	}
}

func TestJournalCreationRefusesALocationItDoesNotControl(t *testing.T) {
	planted := map[string]struct {
		path string
		info EntryInfo
	}{
		"journal directory is a symlink":     {journalRoot + "/ab12cd34", EntryInfo{Mode: 0o777}},
		"journal directory owned by another": {journalRoot + "/ab12cd34", EntryInfo{Dir: true, UID: 1000, Mode: 0o700}},
		"journal directory open to others":   {journalRoot + "/ab12cd34", EntryInfo{Dir: true, Mode: 0o755}},
		"journals root is a symlink":         {journalRoot, EntryInfo{Mode: 0o777}},
		"journals root owned by another":     {journalRoot, EntryInfo{Dir: true, UID: 1000, Mode: 0o700}},
	}
	for name, tc := range planted {
		t.Run(name, func(t *testing.T) {
			w := newAW(t)
			w.entries[tc.path] = tc.info
			if _, err := createJournal(w, "ab12cd34"); err == nil {
				t.Fatal("expected a refusal")
			}
			if w.opIndex("host.append") >= 0 {
				t.Errorf("the journal was written before the location was verified: %v", w.opLog)
			}
		})
	}
}

func TestJournalCreationRefusesAPlantedDirectory(t *testing.T) {
	w := newAW(t)
	w.dirs[journalRoot+"/ab12cd34"] = true
	if _, err := createJournal(w, "ab12cd34"); err == nil || w.opIndex("host.append") >= 0 {
		t.Errorf("err = %v, ops %v", err, w.opLog)
	}
}

func TestStaleJournalInTheLegacyLocationIsRolledBack(t *testing.T) {
	w := newAW(t)
	w.confirmYes = true
	legacy := journalTmpRoot + "/" + journalDirPrefix + staleID
	w.dirs[legacy] = true
	w.files[legacy+"/"+journalFile] = []byte(
		`{"seq":1,"step":"S0","phase":"pending","resource":"journal","name":"` + staleID + `"}` + "\n" +
			`{"seq":2,"step":"S12a","phase":"pending","resource":"user","name":"` + userIDFor(staleID) + `"}` + "\n")
	w.users[userIDFor(staleID)] = "ours"
	p, err := New(w.deps(true)).newProvision(w.opts(), fastHooks())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.recoverStale(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.users[userIDFor(staleID)] != "" || w.Exists(legacy) {
		t.Errorf("legacy journal not rolled back: users %v, ops %v", w.users, w.opLog)
	}
}
