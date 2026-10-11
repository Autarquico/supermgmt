package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// RestoredConfigDir is where the archive's config files are placed, inside the
// data directory: the restore runs as the service user, which cannot write the
// system configuration directory, so the operator reviews and copies them.
const RestoredConfigDir = "restored-config"

const (
	restoredConfigName = "config.yaml"
	restoredPolicyName = "policies.yaml"
	neutralName        = "neutral.db"
)

// restore is Restore with injectable limits and crash points.
func restore(ctx context.Context, o RestoreOptions, e env) error {
	e = e.withDefaults()
	if err := o.validate(); err != nil {
		return err
	}
	archive, err := openArchive(o.Archive)
	if err != nil {
		return err
	}
	defer archive.Close()
	if err := o.checkLayout(); err != nil {
		return err
	}
	staging := filepath.Join(o.DataDir, stagingPrefix+o.IDs.NewID().String())
	if err := os.Mkdir(staging, 0o700); err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	moves, err := e.stage(ctx, o, archive, staging)
	if err != nil {
		_ = os.RemoveAll(staging) // phase A: live files were never touched
		return fmt.Errorf("restore rejected, nothing was changed: %w", err)
	}
	return e.activate(o.DataDir, staging, moves)
}

func (o RestoreOptions) validate() error {
	for name, p := range map[string]string{"archive": o.Archive, "data directory": o.DataDir, "keys directory": o.KeysDir, "database path": o.DBPath} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("restore: %s %q must be an absolute, clean path", name, p))
		}
	}
	if o.Clock == nil || o.IDs == nil {
		return errors.New("restore needs a clock and an id generator")
	}
	return nil
}

func openArchive(path string) (*os.File, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied archive path
	if err != nil {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("cannot read the archive: %v", err))
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("%s is not a regular file", path))
	}
	return f, nil
}

// checkLayout verifies the directories a restore renames between share one
// filesystem (a rename across filesystems cannot be atomic) and that no
// earlier restore is unfinished.
func (o RestoreOptions) checkLayout() error {
	if present, err := exists(journalPath(o.DataDir)); err != nil || present {
		if err != nil {
			return err
		}
		return refuse("Start the daemon or run `sm backup restore --offline` again so it recovers first", "an earlier restore is unfinished (%s exists)", JournalName)
	}
	dbDir := filepath.Dir(o.DBPath)
	dataDev, err := deviceOf(o.DataDir)
	if err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	dbDev, err := deviceOf(dbDir)
	if err != nil {
		return fmt.Errorf("database directory: %w", err)
	}
	if dataDev != dbDev {
		return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf(
			"the database directory %s and the data directory %s are on different filesystems; a restore cannot move files between them atomically", dbDir, o.DataDir))
	}
	return nil
}

func deviceOf(dir string) (uint64, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("device information is unavailable on this platform")
	}
	return uint64(st.Dev), nil //nolint:gosec,unconvert,nolintlint // Dev is signed on darwin, unsigned on linux
}

// stage runs phase A and C on a private copy and returns the moves of phase B.
func (e env) stage(ctx context.Context, o RestoreOptions, archive *os.File, staging string) ([]journalMove, error) {
	latest, err := database.LatestSchemaVersion()
	if err != nil {
		return nil, err
	}
	members, err := e.extract(ctx, archive, staging, latest)
	if err != nil {
		return nil, err
	}
	databasePath := stagedPath(staging, DatabaseName)
	if err := checkStagedDatabase(ctx, databasePath, members.manifest, latest); err != nil {
		return nil, err
	}
	promotions, err := e.neutralizeStaged(ctx, o, staging, databasePath)
	if err != nil {
		return nil, err
	}
	return planMoves(o, staging, members, promotions)
}

func checkStagedDatabase(ctx context.Context, path string, m Manifest, latest int) error {
	found, err := database.Inspect(ctx, path)
	switch {
	case err != nil:
		return fmt.Errorf("inspect the staged database: %w", err)
	case !found.HasSchema:
		return errors.New("the staged database has no schema")
	case len(found.IntegrityFindings) > 0:
		return fmt.Errorf("the staged database failed its integrity check: %v", found.IntegrityFindings)
	case found.SchemaVersion > latest:
		return fmt.Errorf("the staged database is at schema version %d, newer than this binary supports (%d)", found.SchemaVersion, latest)
	case found.SchemaVersion != m.SchemaVersion:
		return fmt.Errorf("the staged database is at schema version %d but the manifest says %d", found.SchemaVersion, m.SchemaVersion)
	}
	return nil
}

// neutralizeStaged opens the staged database, checks the keys against it,
// migrates it forward, neutralizes it, and replaces it with a clean
// single-file copy (rollback-journal mode, no -wal), fsynced.
func (e env) neutralizeStaged(ctx context.Context, o RestoreOptions, staging, databasePath string) ([]keyPromotion, error) {
	db, err := database.Open(ctx, databasePath, database.Options{Clock: o.Clock})
	if err != nil {
		return nil, fmt.Errorf("open the staged database: %w", err)
	}
	promotions, err := e.neutralizeOpen(ctx, o, db, staging)
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := db.Close(); err != nil {
		return nil, fmt.Errorf("close the staged database: %w", err)
	}
	return promotions, settleDatabase(staging, databasePath)
}

func (env) neutralizeOpen(ctx context.Context, o RestoreOptions, db *database.DB, staging string) ([]keyPromotion, error) {
	promotions, err := checkKeys(ctx, db.Reader(), o.IDs, o.KeysDir, staging)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate the staged database: %w", err)
	}
	if err := neutralize(ctx, db, o.Clock, o.IDs); err != nil {
		return nil, fmt.Errorf("neutralize the staged database: %w", err)
	}
	if _, err := db.SnapshotTo(ctx, filepath.Join(staging, neutralName)); err != nil {
		return nil, fmt.Errorf("write the neutralized database: %w", err)
	}
	return promotions, nil
}

// settleDatabase swaps the staged database for its neutralized single-file
// copy and makes the result durable.
func settleDatabase(staging, databasePath string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Remove(databasePath + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove the un-neutralized staged database: %w", err)
		}
	}
	neutral := filepath.Join(staging, neutralName)
	if err := os.Chmod(neutral, 0o600); err != nil { // the copy gets the process umask; the database is owner-only
		return fmt.Errorf("secure the neutralized database: %w", err)
	}
	if err := syncFile(neutral); err != nil {
		return fmt.Errorf("sync the neutralized database: %w", err)
	}
	if err := os.Rename(neutral, databasePath); err != nil {
		return fmt.Errorf("place the neutralized database: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if present, _ := exists(databasePath + suffix); present {
			return fmt.Errorf("the neutralized database left a %s file", suffix)
		}
	}
	return syncDir(staging)
}

// planMoves lists phase B: retire what is live, install what was staged,
// promote pending keys.
func planMoves(o RestoreOptions, staging string, members staged, promotions []keyPromotion) ([]journalMove, error) {
	pre, err := freshPreRestoreDir(o)
	if err != nil {
		return nil, err
	}
	installs, err := installMoves(o, staging, members)
	if err != nil {
		return nil, err
	}
	retires, err := retireMoves(o, pre, members)
	if err != nil {
		return nil, err
	}
	moves := slices.Concat(retires, installs)
	for _, p := range promotions {
		from := filepath.Join(o.KeysDir, p.id.String()+pendingSuffix)
		moves = append(moves, journalMove{Kind: kindPromote, From: from, To: filepath.Join(o.KeysDir, p.id.String()+keySuffix), Status: statusPlanned, SHA256: p.sha256})
	}
	return moves, nil
}

func freshPreRestoreDir(o RestoreOptions) (string, error) {
	stamp := o.Clock.Now().UTC().Format(timestampLayout)
	for n := 0; ; n++ {
		name := preRestorePrefix + stamp
		if n > 0 {
			name = fmt.Sprintf("%s-%d", name, n)
		}
		dir := filepath.Join(o.DataDir, name)
		present, err := exists(dir)
		if err != nil {
			return "", err
		}
		if !present {
			return dir, nil
		}
	}
}

func installMoves(o RestoreOptions, staging string, members staged) ([]journalMove, error) {
	databaseSum, err := fileSHA256(stagedPath(staging, DatabaseName))
	if err != nil {
		return nil, fmt.Errorf("checksum the neutralized database: %w", err)
	}
	configDir := filepath.Join(o.DataDir, RestoredConfigDir)
	targets := []struct{ member, to, sum string }{
		{DatabaseName, o.DBPath, databaseSum},
		{KnownHostsName, filepath.Join(o.DataDir, KnownHostsName), members.manifest.SHA256[KnownHostsName]},
		{ConfigName, filepath.Join(configDir, restoredConfigName), members.manifest.SHA256[ConfigName]},
		{PolicyName, filepath.Join(configDir, restoredPolicyName), members.manifest.SHA256[PolicyName]},
	}
	var moves []journalMove
	for _, t := range targets {
		if members.members[t.member] {
			moves = append(moves, journalMove{Kind: kindInstall, From: stagedPath(staging, t.member), To: t.to, Status: statusPlanned, SHA256: t.sum})
		}
	}
	return moves, nil
}

// retireMoves moves aside every live file a staged one replaces, and the
// database's -wal and -shm always (a stale -wal beside a new database would be
// replayed into it). The <db>.lock file is not in the list: it is never moved.
func retireMoves(o RestoreOptions, pre string, members staged) ([]journalMove, error) {
	configDir := filepath.Join(o.DataDir, RestoredConfigDir)
	candidates := []struct{ live, aside string }{
		{o.DBPath, filepath.Base(o.DBPath)},
		{o.DBPath + "-wal", filepath.Base(o.DBPath) + "-wal"},
		{o.DBPath + "-shm", filepath.Base(o.DBPath) + "-shm"},
		{filepath.Join(configDir, restoredConfigName), filepath.Join(RestoredConfigDir, restoredConfigName)},
		{filepath.Join(configDir, restoredPolicyName), filepath.Join(RestoredConfigDir, restoredPolicyName)},
	}
	if members.members[KnownHostsName] {
		candidates = append(candidates, struct{ live, aside string }{filepath.Join(o.DataDir, KnownHostsName), KnownHostsName})
	}
	var moves []journalMove
	for _, c := range candidates {
		present, err := exists(c.live)
		if err != nil {
			return nil, fmt.Errorf("look at %s: %w", c.live, err)
		}
		if present {
			moves = append(moves, journalMove{Kind: kindRetire, From: c.live, To: filepath.Join(pre, c.aside), Status: statusPlanned})
		}
	}
	return moves, nil
}

// activate is phase B: make the staged files durable, write the journal (the
// commit point), then run the moves.
func (e env) activate(dataDir, staging string, moves []journalMove) error {
	for _, dir := range []string{filepath.Join(staging, "config"), staging, dataDir} {
		if present, _ := exists(dir); !present {
			continue
		}
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	if err := e.hit("staged-durable"); err != nil {
		return err
	}
	j := journal{ID: filepath.Base(staging)[len(stagingPrefix):], State: modeStaged, Staging: staging, Moves: moves}
	if err := e.writeJournal(dataDir, j); err != nil {
		return err
	}
	if err := e.forward(dataDir, j); err != nil {
		return fmt.Errorf("restore interrupted; the next start (or `sm backup restore --offline`) finishes it: %w", err)
	}
	return nil
}

func sumHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
