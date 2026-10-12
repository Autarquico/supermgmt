package installer

import (
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
		"host.mkdir /var/tmp/supermgmt-installer-ab12cd34", "host.syncdir /var/tmp",
		"host.append /var/tmp/supermgmt-installer-ab12cd34/journal.jsonl", "host.syncdir /var/tmp/supermgmt-installer-ab12cd34",
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
