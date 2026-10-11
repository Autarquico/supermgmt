package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
)

// Size caps of phase A (spec §29.2, ADR-0020).
const (
	maxDatabaseBytes = 4 << 30
	maxMemberBytes   = 16 << 20
	maxTotalBytes    = 8 << 30
)

// limits are the decompression caps; tests shrink them.
type limits struct{ database, member, total int64 }

func defaultLimits() limits {
	return limits{database: maxDatabaseBytes, member: maxMemberBytes, total: maxTotalBytes}
}

func (l limits) capOf(member string) int64 {
	if member == DatabaseName {
		return l.database
	}
	return l.member
}

// env carries what tests inject. crash only has effect under the crashpoints
// build tag (see crashpoints_on.go); the zero value is the production setup.
type env struct {
	limits limits
	crash  func(point string) error
}

func (e env) withDefaults() env {
	if e.limits == (limits{}) {
		e.limits = defaultLimits()
	}
	return e
}

type moveAction int

const (
	actionRename moveAction = iota
	actionLanded
)

const recoveryHelp = "Nothing was changed. Inspect restore.journal, restore-* and pre-restore-* in the data directory; " +
	"if the live files are the ones you want, delete restore.journal and the restore-* directories; " +
	"if pre-restore-* holds your previous files, move them back by hand"

// recoverRestore is Recover with injectable crash points.
func recoverRestore(dataDir string, e env) error {
	j, found, err := readJournal(dataDir)
	var torn *tornJournalError
	switch {
	case errors.As(err, &torn):
		return e.recoverTorn(dataDir, torn)
	case err != nil:
		return err
	case !found:
		return e.discardLeftovers(dataDir)
	case j.untouched():
		if err := e.removeJournal(dataDir); err != nil {
			return err
		}
		return e.discardLeftovers(dataDir)
	}
	return e.forward(dataDir, j)
}

// forward finishes a partially moved restore: the staged files are already
// neutralized and complete, so the only safe direction is ahead.
func (e env) forward(dataDir string, j journal) error {
	for i := range j.Moves {
		if j.Moves[i].Status == statusDone {
			continue
		}
		if err := e.advance(dataDir, &j, i); err != nil {
			return err
		}
	}
	if j.State != modeComplete {
		j.State = modeComplete
		if err := e.writeJournal(dataDir, j); err != nil {
			return err
		}
	}
	if err := e.removeJournal(dataDir); err != nil {
		return err
	}
	return e.discardLeftovers(dataDir)
}

// advance performs move i: intent is recorded before the rename and done
// after both directories are durable. It decides from what is on disk, so it
// is safe to run again after a crash at any point.
func (e env) advance(dataDir string, j *journal, i int) error {
	m := &j.Moves[i]
	if m.Status == statusPlanned {
		m.Status = statusIntent
		if err := e.writeJournal(dataDir, *j); err != nil {
			return err
		}
		if err := e.hit("intent-written"); err != nil {
			return err
		}
	}
	action, err := decide(*m)
	if err != nil {
		return err
	}
	if action == actionRename {
		if err := mkdirDurable(filepath.Dir(m.To)); err != nil {
			return err
		}
		if err := e.hit("before-rename"); err != nil {
			return err
		}
		if err := os.Rename(m.From, m.To); err != nil {
			return fmt.Errorf("move %s to %s: %w", m.From, m.To, err)
		}
		if err := e.hit("renamed"); err != nil {
			return err
		}
	}
	if err := syncMoveDirs(*m); err != nil {
		return err
	}
	if err := e.hit("directories-synced"); err != nil {
		return err
	}
	m.Status = statusDone
	return e.writeJournal(dataDir, *j)
}

// decide reads the source and destination to learn what an intent became.
func decide(m journalMove) (moveAction, error) {
	src, err := exists(m.From)
	if err != nil {
		return 0, fmt.Errorf("look at %s: %w", m.From, err)
	}
	dst, err := exists(m.To)
	if err != nil {
		return 0, fmt.Errorf("look at %s: %w", m.To, err)
	}
	switch {
	case src && !dst:
		return actionRename, nil
	case !src && dst:
		return actionLanded, verifyLanded(m)
	case !src && !dst:
		return 0, refuse(recoveryHelp, "neither %s nor %s exists", m.From, m.To)
	}
	return resolveBoth(m)
}

// verifyLanded checks that a file that arrived is the one the plan expected.
func verifyLanded(m journalMove) error {
	if m.Kind == kindRetire || m.SHA256 == "" {
		return nil
	}
	sum, err := fileSHA256(m.To)
	if err != nil {
		return fmt.Errorf("checksum %s: %w", m.To, err)
	}
	if sum != m.SHA256 {
		return refuse(recoveryHelp, "%s does not match the staged checksum", m.To)
	}
	return nil
}

// resolveBoth handles a source and a destination that both exist. The rename
// proceeds only when it replaces an identical file or when the staged copy is
// the one the journal checksummed; anything else is a surprise, never a guess.
func resolveBoth(m journalMove) (moveAction, error) {
	from, err := fileSHA256(m.From)
	if err != nil {
		return 0, fmt.Errorf("checksum %s: %w", m.From, err)
	}
	to, err := fileSHA256(m.To)
	if err != nil {
		return 0, fmt.Errorf("checksum %s: %w", m.To, err)
	}
	if from == to || (m.Kind == kindInstall && m.SHA256 != "" && from == m.SHA256) {
		return actionRename, nil
	}
	return 0, refuse(recoveryHelp, "both %s and %s exist and differ", m.From, m.To)
}

func syncMoveDirs(m journalMove) error {
	from, to := filepath.Dir(m.From), filepath.Dir(m.To)
	if err := syncDir(from); err != nil {
		return err
	}
	if to == from {
		return nil
	}
	return syncDir(to)
}

// mkdirDurable creates dir and any missing parent, syncing each new entry.
func mkdirDurable(dir string) error {
	present, err := exists(dir)
	if err != nil || present {
		return err
	}
	parent := filepath.Dir(dir)
	if err := mkdirDurable(parent); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	return syncDir(parent)
}

// discardLeftovers removes the temporary journal and every restore-* staging
// directory: with no journal naming them they hold nothing the live state needs.
func (e env) discardLeftovers(dataDir string) error {
	if err := os.Remove(filepath.Join(dataDir, journalTempName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove temporary journal: %w", err)
	}
	stagings, err := stagingDirs(dataDir)
	if err != nil {
		return err
	}
	for _, dir := range stagings {
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("discard staging directory: %w", err)
		}
	}
	if err := syncDir(dataDir); err != nil {
		return err
	}
	return e.hit("leftovers-discarded")
}

// stagingDirs lists restore-<id> directories of dataDir.
func stagingDirs(dataDir string) ([]string, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, fmt.Errorf("list data directory: %w", err)
	}
	var out []string
	for _, entry := range entries {
		id, isStaging := strings.CutPrefix(entry.Name(), stagingPrefix)
		if !isStaging || !entry.IsDir() {
			continue
		}
		if _, err := domain.ParseID(id); err == nil {
			out = append(out, filepath.Join(dataDir, entry.Name()))
		}
	}
	return out, nil
}

// recoverTorn handles a journal that cannot be read whole. It discards the
// restore only when the evidence proves no live file moved: every staging
// directory still holds its database and no pre-restore directory has content.
func (e env) recoverTorn(dataDir string, torn *tornJournalError) error {
	stagings, err := stagingDirs(dataDir)
	if err != nil {
		return err
	}
	if len(stagings) == 0 {
		return refuse(recoveryHelp, "%v and no staging directory remains", torn)
	}
	for _, dir := range stagings {
		if present, err := exists(filepath.Join(dir, DatabaseName)); err != nil || !present {
			return refuse(recoveryHelp, "%v and %s no longer holds the staged database", torn, dir)
		}
	}
	moved, err := preRestoreHasContent(dataDir)
	if err != nil {
		return err
	}
	if moved {
		return refuse(recoveryHelp, "%v and live files were already moved to a pre-restore directory", torn)
	}
	if err := e.removeJournal(dataDir); err != nil {
		return err
	}
	return e.discardLeftovers(dataDir)
}

func preRestoreHasContent(dataDir string) (bool, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return false, fmt.Errorf("list data directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), preRestorePrefix) {
			continue
		}
		inside, err := os.ReadDir(filepath.Join(dataDir, entry.Name()))
		if err != nil {
			return false, fmt.Errorf("list %s: %w", entry.Name(), err)
		}
		if len(inside) > 0 {
			return true, nil
		}
	}
	return false, nil
}
