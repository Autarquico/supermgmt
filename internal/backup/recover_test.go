package backup_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

// jmove and jfile mirror the on-disk journal; the test writes it by hand to
// place recovery in states a real run only reaches by crashing.
type jmove struct {
	Kind   string `json:"kind"`
	From   string `json:"from"`
	To     string `json:"to"`
	Status string `json:"status"`
	SHA256 string `json:"sha256,omitempty"`
}

type jfile struct {
	ID      string  `json:"id"`
	State   string  `json:"state"`
	Staging string  `json:"staging"`
	Moves   []jmove `json:"moves"`
}

// rig is a data directory holding a live file, a staged replacement and the
// pre-restore location, with a journal of two moves: retire, then install.
type rig struct {
	t                          *testing.T
	dir, staging               string
	live, staged, aside, lock  string
	retireStatus, installState string
}

const (
	oldContent = "old database"
	newContent = "new database"
)

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	staging := filepath.Join(dir, "restore-"+domaintest.NewSequentialIDs().NewID().String())
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	r := &rig{
		t: t, dir: dir, staging: staging,
		live: filepath.Join(dir, "live.db"), staged: filepath.Join(staging, "live.db"),
		aside: filepath.Join(dir, "pre-restore-T", "live.db"), lock: filepath.Join(dir, "live.db.lock"),
		retireStatus: "planned", installState: "planned",
	}
	mustWrite(t, r.lock, []byte("4242\n"))
	return r
}

func (r *rig) journal(state string) jfile {
	return jfile{
		ID: "rig", State: state, Staging: r.staging,
		Moves: []jmove{
			{Kind: "retire", From: r.live, To: r.aside, Status: r.retireStatus},
			{Kind: "install", From: r.staged, To: r.live, Status: r.installState, SHA256: digest([]byte(newContent))},
		},
	}
}

func (r *rig) writeJournal(j jfile) {
	r.t.Helper()
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		r.t.Fatal(err)
	}
	mustWrite(r.t, filepath.Join(r.dir, backup.JournalName), data)
}

func (r *rig) put(path, content string) {
	r.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		r.t.Fatal(err)
	}
	mustWrite(r.t, path, []byte(content))
}

// content returns the file's text, or "<absent>".
func (r *rig) content(path string) string {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "<absent>"
	}
	if err != nil {
		r.t.Fatal(err)
	}
	return string(data)
}

func (r *rig) assertLockUntouched() {
	r.t.Helper()
	if got := r.content(r.lock); got != "4242\n" {
		r.t.Errorf("the database lock file changed or moved: %q", got)
	}
}

func TestRecoverFinishesOrDiscardsFromTheStateOnDisk(t *testing.T) {
	const absent = "<absent>"
	cases := []struct {
		name                       string
		state                      string
		retire, install            string
		live, staged, aside        string // content before; absent = no file
		wantErr                    bool
		wantLive, wantAside        string
		wantStaged                 string
		wantLeftoverStagingAndJour bool // refusal keeps the evidence
	}{
		{
			name: "no move past planned is discarded", retire: "planned", install: "planned",
			live: oldContent, staged: newContent, aside: absent,
			wantLive: oldContent, wantAside: absent, wantStaged: absent,
		},
		{
			name: "retire intent, nothing moved yet", retire: "intent", install: "planned",
			live: oldContent, staged: newContent, aside: absent,
			wantLive: newContent, wantAside: oldContent, wantStaged: absent,
		},
		{
			name: "retire intent, rename happened but was not recorded", retire: "intent", install: "planned",
			live: absent, staged: newContent, aside: oldContent,
			wantLive: newContent, wantAside: oldContent, wantStaged: absent,
		},
		{
			name: "retire intent, both exist and are identical", retire: "intent", install: "planned",
			live: oldContent, staged: newContent, aside: oldContent,
			wantLive: newContent, wantAside: oldContent, wantStaged: absent,
		},
		{
			name: "retire done, install planned", retire: "done", install: "planned",
			live: absent, staged: newContent, aside: oldContent,
			wantLive: newContent, wantAside: oldContent, wantStaged: absent,
		},
		{
			name: "install intent, not moved", retire: "done", install: "intent",
			live: absent, staged: newContent, aside: oldContent,
			wantLive: newContent, wantAside: oldContent, wantStaged: absent,
		},
		{
			name: "install intent, moved but not recorded", retire: "done", install: "intent",
			live: newContent, staged: absent, aside: oldContent,
			wantLive: newContent, wantAside: oldContent, wantStaged: absent,
		},
		{
			name: "install intent, both exist and the staged copy is the checksummed one", retire: "done", install: "intent",
			live: "unexpected", staged: newContent, aside: oldContent,
			wantLive: newContent, wantAside: oldContent, wantStaged: absent,
		},
		{
			name: "install intent, both exist and the staged copy does not match", retire: "done", install: "intent",
			live: "unexpected", staged: "tampered", aside: oldContent,
			wantErr: true, wantLive: "unexpected", wantAside: oldContent, wantStaged: "tampered", wantLeftoverStagingAndJour: true,
		},
		{
			name: "install intent, landed file is not the checksummed one", retire: "done", install: "intent",
			live: "something else", staged: absent, aside: oldContent,
			wantErr: true, wantLive: "something else", wantAside: oldContent, wantStaged: absent, wantLeftoverStagingAndJour: true,
		},
		{
			name: "install intent, neither side exists", retire: "done", install: "intent",
			live: absent, staged: absent, aside: oldContent,
			wantErr: true, wantLive: absent, wantAside: oldContent, wantStaged: absent, wantLeftoverStagingAndJour: true,
		},
		{
			name: "retire intent, both exist and differ", retire: "intent", install: "planned",
			live: oldContent, staged: newContent, aside: "someone else's file",
			wantErr: true, wantLive: oldContent, wantAside: "someone else's file", wantStaged: newContent, wantLeftoverStagingAndJour: true,
		},
		{
			name: "everything done but the journal not yet deleted", state: "complete", retire: "done", install: "done",
			live: newContent, staged: absent, aside: oldContent,
			wantLive: newContent, wantAside: oldContent, wantStaged: absent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.retireStatus, r.installState = tc.retire, tc.install
			for path, content := range map[string]string{r.live: tc.live, r.staged: tc.staged, r.aside: tc.aside} {
				if content != absent {
					r.put(path, content)
				}
			}
			state := tc.state
			if state == "" {
				state = "staged"
			}
			r.writeJournal(r.journal(state))

			err := backup.Recover(r.dir)

			if (err != nil) != tc.wantErr {
				t.Fatalf("Recover error = %v, want error: %v", err, tc.wantErr)
			}
			if tc.wantErr {
				var refused *backup.RefusedError
				if !errors.As(err, &refused) {
					t.Errorf("error = %T %v, want a *RefusedError", err, err)
				}
			}
			for path, want := range map[string]string{r.live: tc.wantLive, r.aside: tc.wantAside, r.staged: tc.wantStaged} {
				if got := r.content(path); got != want {
					t.Errorf("%s = %q, want %q", path, got, want)
				}
			}
			journalLeft := r.content(filepath.Join(r.dir, backup.JournalName)) != absent
			if journalLeft != tc.wantLeftoverStagingAndJour {
				t.Errorf("journal present = %v, want %v", journalLeft, tc.wantLeftoverStagingAndJour)
			}
			r.assertLockUntouched()
			if !tc.wantErr {
				if err := backup.Recover(r.dir); err != nil {
					t.Errorf("second Recover = %v, want a no-op", err)
				}
				assertNoRestoreLeftovers(t, r.dir)
			}
		})
	}
}

func TestRecoverWithoutJournalDiscardsStagingOnly(t *testing.T) {
	r := newRig(t)
	r.put(r.live, oldContent)
	r.put(r.staged, newContent)
	r.put(filepath.Join(r.dir, backup.JournalName+".tmp"), "half a journal")
	notStaging := filepath.Join(r.dir, "restore-notes")
	r.put(filepath.Join(notStaging, "keep"), "mine")
	r.put(filepath.Join(r.dir, "pre-restore-keep", "file"), "mine")

	if err := backup.Recover(r.dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	if got := r.content(r.live); got != oldContent {
		t.Errorf("live = %q", got)
	}
	if _, err := os.Stat(r.staging); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staging directory remains: %v", err)
	}
	if r.content(filepath.Join(notStaging, "keep")) != "mine" || r.content(filepath.Join(r.dir, "pre-restore-keep", "file")) != "mine" {
		t.Error("recovery removed directories that are not restore staging")
	}
	if got := r.content(filepath.Join(r.dir, backup.JournalName+".tmp")); got != "<absent>" {
		t.Errorf("temporary journal remains: %q", got)
	}
}

func TestRecoverTreatsAnUnreadableJournalAsEvidenceNotInstruction(t *testing.T) {
	good := func(r *rig) []byte {
		data, err := json.MarshalIndent(r.journal("staged"), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	prepare := func(r *rig) {
		r.put(r.live, oldContent)
		r.put(filepath.Join(r.staging, backup.DatabaseName), newContent)
	}
	assertDiscarded := func(t *testing.T, r *rig, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("Recover = %v, want the staged restore discarded", err)
		}
		if got := r.content(r.live); got != oldContent {
			t.Errorf("live = %q", got)
		}
		assertNoRestoreLeftovers(t, r.dir)
		r.assertLockUntouched()
	}

	t.Run("truncated at every length", func(t *testing.T) {
		length := len(good(newRig(t)))
		for cut := 0; cut < length; cut += 3 {
			r := newRig(t)
			prepare(r)
			mustWrite(t, filepath.Join(r.dir, backup.JournalName), good(r)[:cut])
			assertDiscarded(t, r, backup.Recover(r.dir))
		}
	})
	for name, body := range map[string]string{
		"garbage":                     "\x00\x01 not json",
		"unknown field":               `{"id":"x","state":"staged","staging":"s","moves":[],"extra":1}`,
		"empty object":                `{}`,
		"relative path":               `{"id":"x","state":"staged","staging":"relative","moves":[]}`,
		"staging outside data dir":    `{"id":"x","state":"staged","staging":"/etc/restore-x","moves":[]}`,
		"status order makes no sense": `PLACEHOLDER`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			prepare(r)
			if body == "PLACEHOLDER" {
				r.retireStatus, r.installState = "planned", "done"
				body = string(good(r))
			}
			mustWrite(t, filepath.Join(r.dir, backup.JournalName), []byte(body))
			assertDiscarded(t, r, backup.Recover(r.dir))
		})
	}
	t.Run("a journal that names a lock file is never executed", func(t *testing.T) {
		r := newRig(t)
		prepare(r)
		j := r.journal("staged")
		j.Moves = []jmove{{Kind: "retire", From: r.lock, To: filepath.Join(r.dir, "pre-restore-T", "live.db.lock"), Status: "intent"}}
		r.writeJournal(j)

		err := backup.Recover(r.dir)

		assertDiscarded(t, r, err)
	})
}

func TestRecoverRefusesAnUnreadableJournalWhenFilesMayHaveMoved(t *testing.T) {
	cases := map[string]func(r *rig){
		"live files already in pre-restore": func(r *rig) {
			r.put(filepath.Join(r.staging, backup.DatabaseName), newContent)
			r.put(r.aside, oldContent)
		},
		"staged database is gone": func(r *rig) { r.put(filepath.Join(r.staging, "other"), "x") },
		"no staging directory":    func(r *rig) { mustRemoveAll(t, r.staging) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.put(r.live, oldContent)
			setup(r)
			mustWrite(t, filepath.Join(r.dir, backup.JournalName), []byte("{torn"))
			before := treeOf(t, r.dir)

			err := backup.Recover(r.dir)

			var refused *backup.RefusedError
			if !errors.As(err, &refused) || refused.Instructions == "" {
				t.Fatalf("Recover = %v, want a *RefusedError with instructions", err)
			}
			if after := treeOf(t, r.dir); !sameTree(before, after) {
				t.Errorf("recovery changed files while refusing.\nbefore: %v\nafter: %v", keysOf(before), keysOf(after))
			}
		})
	}
}
