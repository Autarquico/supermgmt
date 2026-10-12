package installer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// The write-ahead journal of an appliance install (ADR-0026). Every entry is
// appended and fsynced before the side effect it announces, so a crash at any
// point leaves a journal that names everything that might exist.

const (
	journalDirPrefix = "supermgmt-installer-"
	journalTmpRoot   = "/var/tmp"
	journalFile      = "journal.jsonl"
)

type journalPhase string

const (
	phasePending journalPhase = "pending"
	phaseDone    journalPhase = "done"
	phaseUndone  journalPhase = "undone"
)

// Journal resources. Names always carry the install id, except the LXC (its
// VMID is proven by the container description) and paths.
const (
	resJournal      = "journal"
	resLXC          = "lxc"
	resUser         = "user"
	resRole         = "role"
	resACL          = "acl"
	resToken        = "token"
	resHostTemp     = "hosttemp"
	resBootstrapDir = "bootstrapdir"
	resTemplate     = "template"
	resCommitted    = "committed"
)

type journalEntry struct {
	Seq      int          `json:"seq"`
	Step     string       `json:"step"`
	Phase    journalPhase `json:"phase"`
	Resource string       `json:"resource"`
	Name     string       `json:"name"`
}

type journal struct {
	files   Files
	id      string
	dir     string
	entries []journalEntry // folded: the latest line of each seq, in seq order
}

func journalDirFor(id string) string { return path.Join(journalTmpRoot, journalDirPrefix+id) }

func journalIDOf(dir string) string { return strings.TrimPrefix(path.Base(dir), journalDirPrefix) }

func (j *journal) path() string { return path.Join(j.dir, journalFile) }

// createJournal makes the journal directory (it must not exist) and makes both
// the directory and the first entry durable before returning.
func createJournal(files Files, id string) (*journal, error) {
	j := &journal{files: files, id: id, dir: journalDirFor(id)}
	if files.Exists(j.dir) {
		return nil, fmt.Errorf("journal directory %s already exists", j.dir)
	}
	if err := files.MkdirAll(j.dir, 0o700, Owner{}); err != nil {
		return nil, err
	}
	if err := files.SyncDir(journalTmpRoot); err != nil {
		return nil, err
	}
	if _, err := j.begin("S0", resJournal, id); err != nil {
		return nil, err
	}
	if err := files.SyncDir(j.dir); err != nil {
		return nil, err
	}
	return j, nil
}

// openJournal reads a journal left by an earlier run. A torn last line is
// discarded and the file rewritten whole, so later appends stay well formed.
func openJournal(files Files, dir string) (*journal, error) {
	j := &journal{files: files, id: journalIDOf(dir), dir: dir}
	raw, err := files.ReadFile(j.path())
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	torn := lines[len(lines)-1] != "" // an unterminated last line
	if torn {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var valid bytes.Buffer
	for i, line := range lines {
		var e journalEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			if i != len(lines)-1 {
				return nil, fmt.Errorf("journal %s is corrupt at line %d", j.path(), i+1)
			}
			torn = true
			break
		}
		j.fold(e)
		valid.WriteString(line + "\n")
	}
	if torn {
		if err := files.WriteFile(j.path(), valid.Bytes(), 0o600, Owner{}); err != nil {
			return nil, err
		}
		if err := files.SyncDir(j.dir); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func (j *journal) fold(e journalEntry) {
	for i := range j.entries {
		if j.entries[i].Seq == e.Seq {
			j.entries[i] = e
			return
		}
	}
	j.entries = append(j.entries, e)
}

func (j *journal) append(e journalEntry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := j.files.AppendSync(j.path(), append(line, '\n')); err != nil {
		return err
	}
	j.fold(e)
	return nil
}

// begin records the intent to create resource name, before it is created.
func (j *journal) begin(step, resource, name string) (int, error) {
	seq := len(j.entries) + 1
	return seq, j.append(journalEntry{Seq: seq, Step: step, Phase: phasePending, Resource: resource, Name: name})
}

func (j *journal) mark(seq int, phase journalPhase) error {
	for _, e := range j.entries {
		if e.Seq == seq {
			e.Phase = phase
			return j.append(e)
		}
	}
	return fmt.Errorf("journal has no entry %d", seq)
}

func (j *journal) first(resource string) (journalEntry, bool) {
	for _, e := range j.entries {
		if e.Resource == resource {
			return e, true
		}
	}
	return journalEntry{}, false
}

func (j *journal) isCommitted() bool {
	_, ok := j.first(resCommitted)
	return ok
}

func (j *journal) commit() error {
	_, err := j.begin("S16", resCommitted, j.id)
	return err
}

// toUndo lists the entries that may still hold a resource, newest first.
func (j *journal) toUndo() []journalEntry {
	var out []journalEntry
	for i := len(j.entries) - 1; i >= 0; i-- {
		e := j.entries[i]
		if e.Phase != phaseUndone && e.Resource != resJournal && e.Resource != resCommitted {
			out = append(out, e)
		}
	}
	return out
}

// remove deletes the journal directory and makes the deletion durable.
func (j *journal) remove() error {
	if err := j.files.RemoveAll(j.dir); err != nil {
		return err
	}
	return j.files.SyncDir(journalTmpRoot)
}
