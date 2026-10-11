package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	keySuffix     = ".key"
	pendingSuffix = ".key.pending"
	keyBytes      = 32
	keyCheckDir   = "keycheck"
	activeKEKKey  = "active_kek_id"
)

// keyPromotion is a KEK that only exists as <id>.key.pending and becomes
// <id>.key in phase B (spec §29.2 step 3).
type keyPromotion struct {
	id     domain.ID
	sha256 string
}

// stagedSecrets is a read-only secrets.Repo over the staged database: the key
// check must never write to it.
type stagedSecrets struct{ q database.Querier }

var _ secrets.Repo = stagedSecrets{}

var errStagedReadOnly = errors.New("the staged database is read-only during the key check")

func (stagedSecrets) Put(context.Context, secrets.Record) error { return errStagedReadOnly }

func (stagedSecrets) Get(context.Context, string, int) (secrets.Record, error) {
	return secrets.Record{}, errStagedReadOnly
}

func (stagedSecrets) PutSettings(context.Context, map[string]string) error { return errStagedReadOnly }

func (s stagedSecrets) ReferencedKEKs(ctx context.Context) ([]domain.ID, error) {
	return database.ReferencedKEKIDs(ctx, s.q)
}

func (s stagedSecrets) Setting(ctx context.Context, key string) (string, bool, error) {
	setting, err := database.GetSetting(ctx, s.q, key)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(setting.Value), true, nil
}

// checkKeys is phase A step 3: every KEK the staged database needs must have
// a key file in keysDir (<id>.key, or <id>.key.pending from an offline import)
// that passes the check record stored in the staged database. It reuses the
// daemon's own loader on a private copy of the candidate files, so the verdict
// is the one the daemon will reach, and writes nothing to keysDir.
func checkKeys(ctx context.Context, q database.Querier, ids domain.IDGenerator, keysDir, staging string) ([]keyPromotion, error) {
	repo := stagedSecrets{q: q}
	_, hasActive, err := repo.Setting(ctx, activeKEKKey)
	if err != nil {
		return nil, fmt.Errorf("read the staged active key: %w", err)
	}
	referenced, err := repo.ReferencedKEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the keys the staged database references: %w", err)
	}
	if !hasActive && len(referenced) == 0 {
		return nil, nil // an instance that never created a KEK needs none
	}
	candidates, err := readCandidates(keysDir)
	if err != nil {
		return nil, err
	}
	checkDir := filepath.Join(staging, keyCheckDir)
	defer os.RemoveAll(checkDir)
	if err := os.Mkdir(checkDir, 0o700); err != nil {
		return nil, fmt.Errorf("create key check directory: %w", err)
	}
	if err := os.Chmod(checkDir, 0o700); err != nil { //nolint:gosec // a private directory needs its search bit
		return nil, fmt.Errorf("secure key check directory: %w", err)
	}
	for id, c := range candidates {
		if err := os.WriteFile(filepath.Join(checkDir, id.String()+keySuffix), c.bytes, 0o600); err != nil {
			return nil, fmt.Errorf("copy key %s for the check: %w", id, err)
		}
	}
	loaded, err := secrets.OpenFileKeys(ctx, checkDir, repo, ids)
	if err != nil {
		return nil, fmt.Errorf("key check of the staged database failed: %w", err)
	}
	return promotionsFor(candidates, loaded), nil
}

// candidate is the key file the check will use for one id.
type candidate struct {
	bytes   []byte
	pending bool
}

// readCandidates collects <id>.key and <id>.key.pending files that the daemon
// could use, preferring .key. Files the daemon would refuse (symlink, wrong
// mode or owner, wrong size) are left out so the check names them as missing.
func readCandidates(keysDir string) (map[domain.ID]candidate, error) {
	entries, err := os.ReadDir(keysDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read keys directory %s: %w", keysDir, err)
	}
	out := map[domain.ID]candidate{}
	for _, entry := range entries {
		id, pending, ok := keyFileID(entry.Name())
		if !ok {
			continue
		}
		data, err := readKeyFile(filepath.Join(keysDir, entry.Name()))
		if err != nil {
			continue
		}
		if prior, dup := out[id]; dup && !prior.pending {
			continue
		}
		out[id] = candidate{bytes: data, pending: pending}
	}
	return out, nil
}

func keyFileID(name string) (id domain.ID, pending, ok bool) {
	stem, isPending := strings.CutSuffix(name, pendingSuffix)
	if !isPending {
		var isKey bool
		if stem, isKey = strings.CutSuffix(name, keySuffix); !isKey {
			return "", false, false
		}
	}
	id, err := domain.ParseID(stem)
	return id, isPending, err == nil
}

// readKeyFile reads a KEK file under the rules the daemon applies to it.
func readKeyFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // listed from the configured keys directory
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, isUnix := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != keyBytes || !isUnix || int(st.Uid) != os.Getuid() {
		return nil, errors.New("key file is not usable")
	}
	data := make([]byte, keyBytes)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	return data, nil
}

// promotionsFor lists the keys the staged database needs that exist only as
// pending files; loaded holds exactly the keys that passed the check.
func promotionsFor(candidates map[domain.ID]candidate, loaded *secrets.FileKeys) []keyPromotion {
	var out []keyPromotion
	for id, c := range candidates {
		if _, needed := loaded.Key(id); needed && c.pending {
			out = append(out, keyPromotion{id: id, sha256: sumHex(c.bytes)})
		}
	}
	slices.SortFunc(out, func(a, b keyPromotion) int { return strings.Compare(a.id.String(), b.id.String()) })
	return out
}
