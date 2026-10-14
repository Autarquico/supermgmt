package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	namePrefix      = "supermgmt-"
	timestampLayout = "20060102T150405Z"
	workPrefix      = ".work-"
	maxKnownHosts   = 16 << 20
)

var (
	unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	archiveName     = regexp.MustCompile(`^supermgmt-.+-(\d{8}T\d{6}Z)` + regexp.QuoteMeta(Extension) + `$`)
)

// Source takes the consistent database copy an archive is made from
// (*database.DB).
type Source interface {
	SnapshotTo(ctx context.Context, path string) (database.Snapshot, error)
}

// CreateOptions describes one archive.
type CreateOptions struct {
	Dir            string // backup.directory
	Instance       string // instance name, part of the file name
	KnownHostsPath string // included when the file exists
	SMVersion      string
	Clock          domain.Clock
	Source         Source
	Keys           KeyReserver
}

// Created is a committed archive.
type Created struct {
	Name     string
	Path     string
	Size     int64
	Manifest Manifest
}

// Create writes one archive into o.Dir (spec §29.1, ADR-0020).
//
// It reserves the loaded KEKs before it reads the database, so a key the
// snapshot may reference cannot be retired until the archive is published or
// abandoned. The archive is built in a private work directory inside o.Dir
// and published with fsync, rename and a directory fsync; only then is the
// reservation released. KEK files are never members. One Create at a time per
// directory: it removes work directories a crashed run left behind.
func Create(ctx context.Context, o CreateOptions) (Created, error) {
	if err := o.validate(); err != nil {
		return Created{}, err
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return Created{}, fmt.Errorf("create backup directory: %w", err)
	}
	if err := removeStaleWork(o.Dir); err != nil {
		return Created{}, err
	}
	reservation := o.Keys.Reserve()
	defer reservation.Release()

	work, err := os.MkdirTemp(o.Dir, workPrefix)
	if err != nil {
		return Created{}, fmt.Errorf("create work directory: %w", err)
	}
	defer os.RemoveAll(work)

	databasePath := filepath.Join(work, DatabaseName)
	snapshot, err := o.Source.SnapshotTo(ctx, databasePath)
	if err != nil {
		return Created{}, err
	}
	if snapshot.Config.Generation < 1 {
		return Created{}, smerr.New(smerr.CodeConflict, "", "no configuration has been activated yet; there is nothing consistent to archive")
	}
	members, err := o.members(databasePath, snapshot.Config)
	if err != nil {
		return Created{}, err
	}
	manifest := Manifest{
		FormatVersion:    FormatVersion,
		SMVersion:        o.SMVersion,
		SchemaVersion:    snapshot.SchemaVersion,
		CreatedAt:        o.Clock.Now().UTC().Truncate(time.Second),
		KEKIDs:           append([]domain.ID{}, reservation.KEKIDs()...),
		ConfigGeneration: snapshot.Config.Generation,
	}
	manifest.CreatedAt = o.firstFreeSecond(manifest.CreatedAt)
	return publish(o.Dir, work, o.archiveName(manifest.CreatedAt), manifest, members)
}

func (o CreateOptions) archiveName(createdAt time.Time) string {
	return fmt.Sprintf("%s%s-%s%s", namePrefix, sanitizeInstance(o.Instance), createdAt.Format(timestampLayout), Extension)
}

// firstFreeSecond keeps two archives made within one second apart: names carry
// second resolution, and the later one must not be refused (a retaken
// pre-upgrade backup follows its crashed twin at once).
func (o CreateOptions) firstFreeSecond(createdAt time.Time) time.Time {
	for {
		if _, err := os.Lstat(filepath.Join(o.Dir, o.archiveName(createdAt))); err != nil {
			return createdAt
		}
		createdAt = createdAt.Add(time.Second)
	}
}

func (o CreateOptions) validate() error {
	switch {
	case o.Dir == "":
		return errors.New("backup directory is required")
	case o.Clock == nil || o.Source == nil || o.Keys == nil:
		return errors.New("backup needs a clock, a database source and a key reserver")
	}
	return nil
}

func sanitizeInstance(name string) string {
	clean := strings.Trim(unsafeNameChars.ReplaceAllString(name, "-"), "-.")
	if clean == "" {
		return "instance"
	}
	return clean
}

func (o CreateOptions) members(databasePath string, config database.ConfigSnapshot) ([]Member, error) {
	members := []Member{
		FileMember(DatabaseName, databasePath),
		BytesMember(ConfigName, config.Config),
	}
	if len(config.Policy) > 0 {
		members = append(members, BytesMember(PolicyName, config.Policy))
	}
	knownHosts, err := o.knownHosts()
	if err != nil {
		return nil, err
	}
	if knownHosts != nil {
		members = append(members, BytesMember(KnownHostsName, knownHosts))
	}
	return members, nil
}

// knownHosts returns the file's bytes, or nil when there is none.
func (o CreateOptions) knownHosts() ([]byte, error) {
	if o.KnownHostsPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(o.KnownHostsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read known_hosts: %w", err)
	}
	if len(data) > maxKnownHosts {
		return nil, fmt.Errorf("known_hosts is larger than %d bytes", maxKnownHosts)
	}
	return data, nil
}

// publish writes the archive to a 0600 file in work, fsyncs it, renames it
// into dir and fsyncs dir.
func publish(dir, work, name string, m Manifest, members []Member) (Created, error) {
	temp := filepath.Join(work, "archive.partial")
	if err := writeFile(temp, m, members); err != nil {
		return Created{}, err
	}
	final := filepath.Join(dir, name)
	if _, err := os.Lstat(final); err == nil {
		return Created{}, smerr.New(smerr.CodeConflict, "", "a backup named "+name+" already exists")
	}
	if err := os.Rename(temp, final); err != nil {
		return Created{}, fmt.Errorf("publish archive: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return Created{}, err
	}
	entry, err := Archives{Dir: dir}.read(name)
	if err != nil {
		return Created{}, fmt.Errorf("verify published archive: %w", err)
	}
	return Created{Name: name, Path: final, Size: entry.Size, Manifest: entry.Manifest}, nil
}

func writeFile(path string, m Manifest, members []Member) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path is inside the private work directory
	if err != nil {
		return fmt.Errorf("create archive file: %w", err)
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	w, err := NewWriter(f)
	if err != nil {
		return err
	}
	if err := w.WriteArchive(m, members); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync archive: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // dir is the configured backup directory
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func removeStaleWork(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list backup directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), workPrefix) {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return fmt.Errorf("remove stale work directory: %w", err)
			}
		}
	}
	return nil
}

// Prune deletes the oldest archives this package made in dir, keeping the
// newest keep, and returns the names it removed (spec §29.1 retention).
// Other files, including archives copied in by hand, are never touched.
func Prune(dir string, keep int) ([]string, error) {
	if keep < 1 {
		return nil, fmt.Errorf("retention %d would delete every backup", keep)
	}
	names, err := Archives{Dir: dir}.names()
	if err != nil {
		return nil, err
	}
	names = slices.DeleteFunc(names, func(n string) bool { return archiveName.FindString(n) == "" })
	if len(names) <= keep {
		return nil, nil
	}
	var removed []string
	for _, name := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return removed, fmt.Errorf("remove backup %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, syncDir(dir)
}

// compareArchiveNames orders by the timestamp in the name, then by name.
func compareArchiveNames(a, b string) int {
	if c := strings.Compare(archiveTimestamp(a), archiveTimestamp(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func archiveTimestamp(name string) string {
	if m := archiveName.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}
