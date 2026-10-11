package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// KeyReserver protects the KEKs an archive will need from retirement while it
// is being made (ADR-0020, ADR-0021): *secrets.FileKeys.
type KeyReserver interface {
	Reserve() *secrets.Reservation
}

// Entry is a committed archive in the backup directory.
type Entry struct {
	Name     string
	Size     int64
	Manifest Manifest
}

// Archives is the catalog of committed archives in one directory. A file is
// committed once it carries the archive extension: creation publishes by
// rename, so temporary files never count.
type Archives struct {
	Dir string
}

var _ secrets.ArchiveKEKs = Archives{}

// List reads the manifest of every committed archive, oldest first. An
// archive whose manifest cannot be read fails the listing, naming the file:
// callers that decide something from the catalog (retiring a KEK) must not
// act on a partial view.
func (a Archives) List() ([]Entry, error) {
	names, err := a.names()
	if err != nil {
		return nil, err
	}
	var (
		entries  []Entry
		problems []error
	)
	for _, name := range names {
		entry, err := a.read(name)
		if err != nil {
			problems = append(problems, fmt.Errorf("backup archive %s: %w", name, err))
			continue
		}
		entries = append(entries, entry)
	}
	return entries, errors.Join(problems...)
}

func (a Archives) names() ([]string, error) {
	dirEntries, err := os.ReadDir(a.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list backup directory: %w", err)
	}
	var names []string
	for _, e := range dirEntries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), Extension) {
			names = append(names, e.Name())
		}
	}
	slices.SortFunc(names, compareArchiveNames)
	return names, nil
}

func (a Archives) read(name string) (Entry, error) {
	f, err := os.Open(filepath.Join(a.Dir, name)) //nolint:gosec // name comes from listing the configured backup directory
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	m, err := ReadManifest(f)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Name: name, Size: info.Size(), Manifest: m}, nil
}

// ArchivedKEKIDs lists the KEKs any committed archive names in its manifest,
// sorted. It implements secrets.ArchiveKEKs: an unreadable manifest is an
// error, so retirement refuses instead of guessing.
func (a Archives) ArchivedKEKIDs(ctx context.Context) ([]domain.ID, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := a.List()
	if err != nil {
		return nil, err
	}
	var ids []domain.ID
	for _, e := range entries {
		ids = append(ids, e.Manifest.KEKIDs...)
	}
	return sortedIDs(ids), nil
}
