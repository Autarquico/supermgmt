package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type (
	moveKind    string
	moveStatus  string
	journalMode string
)

// A restore moves files in three kinds of steps, always in this order: retire
// the live files into pre-restore-<ts>/, install the staged files, promote
// pending KEKs (ADR-0020, spec §29.2 phase B).
const (
	kindRetire  moveKind = "retire"
	kindInstall moveKind = "install"
	kindPromote moveKind = "promote"

	statusPlanned moveStatus = "planned"
	statusIntent  moveStatus = "intent"
	statusDone    moveStatus = "done"

	modeStaged   journalMode = "staged"
	modeComplete journalMode = "complete"

	stagingPrefix    = "restore-"
	preRestorePrefix = "pre-restore-"
	lockSuffix       = ".lock"
	journalTempName  = JournalName + ".tmp"
)

// journalMove is one rename. SHA256 is the digest the source must have for the
// staged copy to win over an unexpected file at the destination.
type journalMove struct {
	Kind   moveKind   `json:"kind"`
	From   string     `json:"from"`
	To     string     `json:"to"`
	Status moveStatus `json:"status"`
	SHA256 string     `json:"sha256,omitempty"`
}

// journal is restore.journal. It is only ever replaced atomically.
type journal struct {
	ID      string        `json:"id"`
	State   journalMode   `json:"state"`
	Staging string        `json:"staging"`
	Moves   []journalMove `json:"moves"`
}

// RefusedError reports a state recovery will not guess about. The live files
// are left as they are; Instructions say what the operator can do.
type RefusedError struct {
	Reason       string
	Instructions string
}

func (e *RefusedError) Error() string {
	return "restore refused: " + e.Reason + ". " + e.Instructions
}

func refuse(instructions, format string, args ...any) *RefusedError {
	return &RefusedError{Reason: fmt.Sprintf(format, args...), Instructions: instructions}
}

func journalPath(dataDir string) string { return filepath.Join(dataDir, JournalName) }

type tornJournalError struct{ cause error }

func (e *tornJournalError) Error() string { return "restore journal is unreadable: " + e.cause.Error() }
func (e *tornJournalError) Unwrap() error { return e.cause }

// readJournal returns the journal in dataDir. found is false when there is
// none. A journal that cannot be read back whole is a *tornJournalError.
func readJournal(dataDir string) (j journal, found bool, err error) {
	data, err := os.ReadFile(journalPath(dataDir))
	if errors.Is(err, fs.ErrNotExist) {
		return journal{}, false, nil
	}
	if err != nil {
		return journal{}, false, fmt.Errorf("read restore journal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return journal{}, true, &tornJournalError{cause: err}
	}
	if err := j.validate(dataDir); err != nil {
		return journal{}, true, &tornJournalError{cause: err}
	}
	return j, true, nil
}

// validate rejects a journal this binary could not have written: recovery
// renames what the journal says, so it must not trust a damaged one.
func (j journal) validate(dataDir string) error {
	if j.ID == "" || (j.State != modeStaged && j.State != modeComplete) {
		return errors.New("missing id or unknown state")
	}
	if !validStaging(dataDir, j.Staging) {
		return fmt.Errorf("staging %q is not a restore-* directory of the data directory", j.Staging)
	}
	previous := statusDone
	for i, m := range j.Moves {
		if err := m.validate(); err != nil {
			return fmt.Errorf("move %d: %w", i, err)
		}
		if previous != statusDone && m.Status != statusPlanned {
			return fmt.Errorf("move %d is %s after a %s move", i, m.Status, previous)
		}
		previous = m.Status
	}
	if j.State == modeComplete && j.pending() {
		return errors.New("complete journal has moves that are not done")
	}
	return nil
}

func validStaging(dataDir, staging string) bool {
	return filepath.IsAbs(staging) && filepath.Clean(staging) == staging &&
		filepath.Dir(staging) == filepath.Clean(dataDir) &&
		strings.HasPrefix(filepath.Base(staging), stagingPrefix)
}

func (m journalMove) validate() error {
	switch m.Kind {
	case kindRetire, kindInstall, kindPromote:
	default:
		return fmt.Errorf("unknown kind %q", m.Kind)
	}
	switch m.Status {
	case statusPlanned, statusIntent, statusDone:
	default:
		return fmt.Errorf("unknown status %q", m.Status)
	}
	for _, p := range []string{m.From, m.To} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("path %q is not absolute and clean", p)
		}
		if strings.HasSuffix(p, lockSuffix) {
			return fmt.Errorf("path %q is a lock file; restore never moves locks", p)
		}
	}
	if m.SHA256 != "" {
		if raw, err := hex.DecodeString(m.SHA256); err != nil || len(raw) != sha256.Size {
			return errors.New("sha256 is not a digest")
		}
	}
	return nil
}

func (j journal) pending() bool {
	return slices.ContainsFunc(j.Moves, func(m journalMove) bool { return m.Status != statusDone })
}

// untouched reports that no rename can have happened: no move reached intent.
func (j journal) untouched() bool {
	return !slices.ContainsFunc(j.Moves, func(m journalMove) bool { return m.Status != statusPlanned })
}

// writeJournal replaces the journal atomically: temp file, fsync, rename,
// directory fsync (ADR-0020).
func (e env) writeJournal(dataDir string, j journal) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("encode restore journal: %w", err)
	}
	if err := writeFileSynced(filepath.Join(dataDir, journalTempName), data); err != nil {
		return fmt.Errorf("write restore journal: %w", err)
	}
	if err := e.hit("journal-temp-synced"); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(dataDir, journalTempName), journalPath(dataDir)); err != nil {
		return fmt.Errorf("replace restore journal: %w", err)
	}
	if err := e.hit("journal-renamed"); err != nil {
		return err
	}
	if err := syncDir(dataDir); err != nil {
		return err
	}
	return e.hit("journal-dir-synced")
}

// removeJournal deletes the journal and makes the deletion durable.
func (e env) removeJournal(dataDir string) error {
	if err := os.Remove(journalPath(dataDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete restore journal: %w", err)
	}
	if err := e.hit("journal-removed"); err != nil {
		return err
	}
	if err := syncDir(dataDir); err != nil {
		return err
	}
	return e.hit("journal-removal-synced")
}

func writeFileSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // path is inside the private data directory
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // staged file of this restore
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // file named by a validated journal
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// exists reports whether path is present (a dangling symlink counts).
func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
