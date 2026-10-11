package secrets

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ArchiveKEKs tells which KEKs the committed backup archives list in their
// manifests (ADR-0020). An archive whose manifest cannot be read is an error,
// never an omission: retirement must refuse rather than guess.
type ArchiveKEKs interface {
	ArchivedKEKIDs(ctx context.Context) ([]domain.ID, error)
}

// KeyAdmin rotates, retires and exports master keys (spec §10, ADR-0021). Every
// operation runs under keyOps and publishes its in-memory result only after the
// database transaction committed.
type KeyAdmin struct {
	keys     *FileKeys
	repo     KeyRepo
	ids      domain.IDGenerator
	archives ArchiveKEKs
	random   io.Reader
}

// NewKeyAdmin builds the administrator over keys opened from the same
// directory and database as repo.
func NewKeyAdmin(keys *FileKeys, repo KeyRepo, ids domain.IDGenerator, archives ArchiveKEKs) *KeyAdmin {
	return &KeyAdmin{keys: keys, repo: repo, ids: ids, archives: archives, random: rand.Reader}
}

// Rotation reports a completed master-key rotation.
type Rotation struct {
	Active    domain.ID
	Previous  domain.ID
	Rewrapped int
}

// Rotate creates a new KEK, rewraps every data key under it in one database
// transaction and makes it active. Before the commit nothing changes (an
// unreferenced key file may remain); after it the new state is durable and the
// old key stays on disk until Retire.
func (a *KeyAdmin) Rotate(ctx context.Context) (Rotation, error) {
	a.keys.ops.Lock()
	defer a.keys.ops.Unlock()
	current := a.keys.snap.Load()

	newID := a.ids.NewID()
	newKEK := make([]byte, keySize)
	defer zero(newKEK)
	if _, err := io.ReadFull(a.random, newKEK); err != nil {
		return Rotation{}, fmt.Errorf("generate kek: %w", err)
	}
	if err := writeKeyFile(a.keys.dir, newID, newKEK); err != nil {
		return Rotation{}, err
	}
	check, err := newCheckRecord(newKEK, newID, a.random)
	if err != nil {
		return Rotation{}, err
	}
	settings, err := jsonSettings(map[string]string{
		settingCheckPref + newID.String(): check,
		settingActiveKEK:                  newID.String(),
	})
	if err != nil {
		return Rotation{}, err
	}
	rewrapped := 0
	err = a.repo.UpdateKeys(ctx, func(rows []Record) (KeyChange, error) {
		moved, err := rewrapRows(rows, current.keys, newID, newKEK, a.random)
		rewrapped = len(moved)
		return KeyChange{Rewrapped: moved, Settings: settings}, err
	})
	if err != nil {
		return Rotation{}, fmt.Errorf("rotate master key: %w", err)
	}
	next := maps.Clone(current.keys)
	next[newID] = slices.Clone(newKEK)
	a.keys.publishLocked(&keySnapshot{active: newID, keys: next})
	return Rotation{Active: newID, Previous: current.active, Rewrapped: rewrapped}, nil
}

func rewrapRows(rows []Record, loaded map[domain.ID][]byte, newID domain.ID, newKEK []byte, random io.Reader) ([]Record, error) {
	moved := make([]Record, 0, len(rows))
	for _, row := range rows {
		old, ok := loaded[row.KEKID]
		if !ok {
			return nil, smerr.New(smerr.CodeInternal, "", fmt.Sprintf("kek %s of secret %s is not loaded", row.KEKID, row.Name))
		}
		dek, err := gcmOpen(old, row.WrappedDEK, aadWrap(row.ID, row.KEKID))
		if err != nil {
			return nil, fmt.Errorf("unwrap data key of secret %s: %w", row.Name, errUndecryptable)
		}
		wrapped, err := gcmSeal(newKEK, dek, aadWrap(row.ID, newID), random)
		zero(dek)
		if err != nil {
			return nil, fmt.Errorf("rewrap data key of secret %s: %w", row.Name, err)
		}
		row.KEKID, row.WrappedDEK = newID, wrapped
		moved = append(moved, row)
	}
	return moved, nil
}

// Retire removes a KEK that nothing needs any more. It refuses the active key,
// a key a secret row, a committed archive manifest or an open backup
// reservation references, and any state it cannot read.
func (a *KeyAdmin) Retire(ctx context.Context, id domain.ID) error {
	a.keys.ops.Lock()
	defer a.keys.ops.Unlock()
	current := a.keys.snap.Load()
	if _, loaded := current.keys[id]; !loaded {
		return smerr.New(smerr.CodeNotFound, "", "no such key is loaded: "+id.String())
	}
	if err := a.requireUnused(ctx, current, id); err != nil {
		return err
	}
	err := a.repo.UpdateKeys(ctx, func(rows []Record) (KeyChange, error) {
		for _, row := range rows {
			if row.KEKID == id {
				return KeyChange{}, inUse(id, "secret "+row.Name)
			}
		}
		return KeyChange{DeleteSettings: []string{settingCheckPref + id.String()}}, nil
	})
	if err != nil {
		return fmt.Errorf("retire key %s: %w", id, err)
	}
	remaining := maps.Clone(current.keys)
	delete(remaining, id)
	a.keys.publishLocked(&keySnapshot{active: current.active, keys: remaining})
	if err := os.Remove(keyPath(a.keys.dir, id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("key %s is retired but its file could not be removed: %w", id, err)
	}
	return nil
}

func (a *KeyAdmin) requireUnused(ctx context.Context, current *keySnapshot, id domain.ID) error {
	if id == current.active {
		return inUse(id, "it is the active key")
	}
	if a.keys.reservedLocked(id) {
		return inUse(id, "a backup in progress")
	}
	archived, err := a.archives.ArchivedKEKIDs(ctx)
	if err != nil {
		return smerr.Wrap(err, smerr.CodeConflict, "", "cannot tell which backups list the key; refusing to retire it")
	}
	if slices.Contains(archived, id) {
		return inUse(id, "a backup archive")
	}
	return nil
}

func inUse(id domain.ID, by string) error {
	return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("key %s is still referenced by %s", id, by))
}

// Export wraps a loaded KEK under passphrase as an SMKEY1 file.
func (a *KeyAdmin) Export(_ context.Context, id domain.ID, passphrase string) ([]byte, error) {
	a.keys.ops.Lock()
	defer a.keys.ops.Unlock()
	kek, ok := a.keys.Key(id)
	if !ok {
		return nil, smerr.New(smerr.CodeNotFound, "", "no such key is loaded: "+id.String())
	}
	return EncodeKeyExport(id, kek, passphrase)
}

// ExportKeyOffline is Export for a stopped service (spec §10): it reads the key
// file and verifies it against its check record. The caller holds the
// database lock.
func ExportKeyOffline(ctx context.Context, dir string, repo Repo, id domain.ID, passphrase string) ([]byte, error) {
	if err := prepareDir(dir); err != nil {
		return nil, err
	}
	kek, err := loadVerified(ctx, dir, repo, id)
	if err != nil {
		return nil, smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("key %s cannot be exported: %v", id, err))
	}
	defer zero(kek)
	return EncodeKeyExport(id, kek, passphrase)
}

// ImportedKey reports where an imported key landed.
type ImportedKey struct {
	KEKID domain.ID
	// Active is true when the key was verified against the database and is now
	// "<id>.key"; false when it waits as "<id>.key.pending" for a restore.
	Active bool
}

const pendingSuffix = ".pending"

// ImportKey implements `sm secrets import-key --offline` (spec §10): it
// authenticates the export, stages the key as "<id>.key.pending" (0600) and,
// when repo is non-nil and its database references the key, verifies it
// against the check record and renames it to "<id>.key". A key that fails the
// check is deleted, not kept. The daemon never loads ".pending" files.
func ImportKey(ctx context.Context, dir string, repo Repo, export []byte, passphrase string) (ImportedKey, error) {
	id, kek, err := DecodeKeyExport(export, passphrase)
	if err != nil {
		return ImportedKey{}, err
	}
	defer zero(kek)
	if err := prepareDir(dir); err != nil {
		return ImportedKey{}, err
	}
	if _, err := os.Lstat(keyPath(dir, id)); err == nil {
		return ImportedKey{}, smerr.New(smerr.CodeConflict, "", fmt.Sprintf("key %s is already installed", id))
	}
	pending := keyPath(dir, id) + pendingSuffix
	if err := os.Remove(pending); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ImportedKey{}, fmt.Errorf("replace stale pending key: %w", err)
	}
	if err := writeKeyFileAt(dir, pending, kek); err != nil {
		return ImportedKey{}, err
	}
	imported := ImportedKey{KEKID: id}
	if repo == nil {
		return imported, nil
	}
	if _, found, err := repo.Setting(ctx, settingCheckPref+id.String()); err != nil || !found {
		return imported, err
	}
	if err := verifyCheckRecord(ctx, repo, kek, id); err != nil {
		_ = os.Remove(pending)
		return ImportedKey{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("key %s does not match this database: %v", id, err))
	}
	if err := os.Rename(pending, keyPath(dir, id)); err != nil {
		return ImportedKey{}, fmt.Errorf("activate imported key: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return ImportedKey{}, fmt.Errorf("sync keys dir: %w", err)
	}
	imported.Active = true
	return imported, nil
}
