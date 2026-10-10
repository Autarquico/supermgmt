package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	settingActiveKEK = "active_kek_id"
	settingCheckPref = "kek_check."
	keyFileSuffix    = ".key"
)

// KeysUnavailableError means a KEK the database refers to cannot be used. The
// daemon fails fast with it (exit 4, ADR-0016) naming the ids and reasons.
type KeysUnavailableError struct {
	IDs      []domain.ID
	Problems []string
}

func (e *KeysUnavailableError) Error() string {
	return "encryption keys unavailable: " + strings.Join(e.Problems, "; ")
}

// FileKeys is the file-backed KEK provider (spec §10): every referenced KEK,
// loaded and verified once at startup.
type FileKeys struct {
	active domain.ID
	keys   map[domain.ID][]byte
}

// Active returns the id and bytes of the KEK that wraps new data keys.
func (k *FileKeys) Active() (domain.ID, []byte) { return k.active, k.keys[k.active] }

// Format keeps master-key bytes out of every fmt verb (%v, %+v, %#v, %s).
func (*FileKeys) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "secrets.FileKeys{[REDACTED]}")
}

// Key returns a loaded KEK by id.
func (k *FileKeys) Key(id domain.ID) ([]byte, bool) {
	key, ok := k.keys[id]
	return key, ok
}

// OpenFileKeys prepares dir, creates the first KEK when the instance has none,
// and verifies every KEK referenced by settings or secrets against its check
// record. A KEK problem is a *KeysUnavailableError; nothing is guessed or skipped.
func OpenFileKeys(ctx context.Context, dir string, repo Repo, ids domain.IDGenerator) (*FileKeys, error) {
	if err := prepareDir(dir); err != nil {
		return nil, err
	}
	active, found, err := activeKEK(ctx, repo)
	if err != nil {
		return nil, err
	}
	if !found {
		if active, err = createFirstKEK(ctx, dir, repo, ids); err != nil {
			return nil, err
		}
	}
	return loadReferenced(ctx, dir, repo, active)
}

func activeKEK(ctx context.Context, repo Repo) (domain.ID, bool, error) {
	raw, found, err := repo.Setting(ctx, settingActiveKEK)
	if err != nil || !found {
		return "", false, err
	}
	var text string
	if err := json.Unmarshal([]byte(raw), &text); err != nil {
		return "", false, fmt.Errorf("settings.%s is not a JSON string: %w", settingActiveKEK, err)
	}
	id, err := domain.ParseID(text)
	if err != nil {
		return "", false, fmt.Errorf("settings.%s: %w", settingActiveKEK, err)
	}
	return id, true, nil
}

func createFirstKEK(ctx context.Context, dir string, repo Repo, ids domain.IDGenerator) (domain.ID, error) {
	existing, err := repo.ReferencedKEKs(ctx)
	if err != nil {
		return "", fmt.Errorf("list referenced keks: %w", err)
	}
	if len(existing) > 0 {
		return "", &KeysUnavailableError{IDs: existing, Problems: []string{
			"secrets exist but settings." + settingActiveKEK + " is missing",
		}}
	}
	id := ids.NewID()
	kek := make([]byte, keySize)
	defer zero(kek)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return "", fmt.Errorf("generate kek: %w", err)
	}
	if err := writeKeyFile(dir, id, kek); err != nil {
		return "", err
	}
	check, err := newCheckRecord(kek, id, rand.Reader)
	if err != nil {
		return "", err
	}
	// The active pointer goes last: a crash before it leaves an unreferenced
	// key file, and the next start simply creates another KEK.
	if err := putJSONSetting(ctx, repo, settingCheckPref+id.String(), check); err != nil {
		return "", err
	}
	if err := putJSONSetting(ctx, repo, settingActiveKEK, id.String()); err != nil {
		return "", err
	}
	return id, nil
}

func putJSONSetting(ctx context.Context, repo Repo, key, value string) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := repo.PutSetting(ctx, key, string(raw)); err != nil {
		return fmt.Errorf("store setting %s: %w", key, err)
	}
	return nil
}

func newCheckRecord(kek []byte, id domain.ID, random io.Reader) (string, error) {
	blob, err := gcmSeal(kek, []byte(labelKEKCheck), aadKEKCheck(id), random)
	if err != nil {
		return "", fmt.Errorf("seal kek check: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

func loadReferenced(ctx context.Context, dir string, repo Repo, active domain.ID) (*FileKeys, error) {
	referenced, err := repo.ReferencedKEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list referenced keks: %w", err)
	}
	wanted := []domain.ID{active}
	for _, id := range referenced {
		if !slices.Contains(wanted, id) {
			wanted = append(wanted, id)
		}
	}
	keys := &FileKeys{active: active, keys: map[domain.ID][]byte{}}
	failure := &KeysUnavailableError{}
	for _, id := range wanted {
		key, err := loadVerified(ctx, dir, repo, id)
		if err != nil {
			failure.IDs = append(failure.IDs, id)
			failure.Problems = append(failure.Problems, fmt.Sprintf("kek %s: %v", id, err))
			continue
		}
		keys.keys[id] = key
	}
	if len(failure.IDs) > 0 {
		return nil, failure
	}
	return keys, nil
}

func loadVerified(ctx context.Context, dir string, repo Repo, id domain.ID) ([]byte, error) {
	key, err := readKeyFile(dir, id)
	if err != nil {
		return nil, err
	}
	if err := verifyCheckRecord(ctx, repo, key, id); err != nil {
		zero(key)
		return nil, err
	}
	return key, nil
}

func verifyCheckRecord(ctx context.Context, repo Repo, key []byte, id domain.ID) error {
	raw, found, err := repo.Setting(ctx, settingCheckPref+id.String())
	if err != nil {
		return fmt.Errorf("read check record: %w", err)
	}
	if !found {
		return errors.New("check record missing")
	}
	var encoded string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil {
		return errors.New("check record malformed")
	}
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("check record malformed")
	}
	plain, err := gcmOpen(key, blob, aadKEKCheck(id))
	if err != nil || string(plain) != labelKEKCheck {
		return errors.New("key does not match its check record")
	}
	return nil
}

// prepareDir creates dir with mode exactly 0700 when absent, and refuses an
// existing one that is not a real directory owned by us with no group/other access.
func prepareDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create keys dir: %w", err)
		}
		// The daemon's umask (0177) may have narrowed the mode below traversable.
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs its search bit
			return fmt.Errorf("chmod keys dir: %w", err)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat keys dir: %w", err)
	}
	if problem := dirProblem(info, os.Getuid()); problem != "" {
		return &KeysUnavailableError{Problems: []string{"keys dir " + dir + ": " + problem}}
	}
	return nil
}

func dirProblem(info fs.FileInfo, uid int) string {
	switch {
	case !info.IsDir():
		return "not a directory (symlinks are refused)"
	case info.Mode().Perm() != 0o700:
		return fmt.Sprintf("mode %04o, want 0700", info.Mode().Perm())
	case ownerOf(info) != uid:
		return "not owned by the daemon user"
	}
	return ""
}

func writeKeyFile(dir string, id domain.ID, key []byte) error {
	path := keyPath(dir, id)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // path is dir + a validated UUID
	if err != nil {
		return fmt.Errorf("create kek file: %w", err)
	}
	if err := writeAndSync(f, key); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write kek file: %w", err)
	}
	return nil
}

func writeAndSync(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func keyPath(dir string, id domain.ID) string {
	return filepath.Join(dir, id.String()+keyFileSuffix)
}

// readKeyFile loads <id>.key: opened O_NOFOLLOW, a regular file owned by the
// daemon user, no group/other bits, exactly 32 bytes. ".pending" files are
// never consulted because only "<id>.key" is ever opened.
func readKeyFile(dir string, id domain.ID) ([]byte, error) {
	f, err := os.OpenFile(keyPath(dir, id), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, errors.New("key file missing")
	case errors.Is(err, syscall.ELOOP):
		return nil, errors.New("key file is a symlink")
	case err != nil:
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if problem := keyFileProblem(info, os.Getuid()); problem != "" {
		return nil, errors.New(problem)
	}
	key := make([]byte, keySize)
	if _, err := io.ReadFull(f, key); err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return key, nil
}

func keyFileProblem(info fs.FileInfo, uid int) string {
	switch {
	case !info.Mode().IsRegular():
		return "key file is not a regular file"
	case info.Mode().Perm()&0o077 != 0:
		return fmt.Sprintf("key file mode %04o grants group/other access", info.Mode().Perm())
	case ownerOf(info) != uid:
		return "key file is not owned by the daemon user"
	case info.Size() != keySize:
		return fmt.Sprintf("key file is %d bytes, want %d", info.Size(), keySize)
	}
	return ""
}

func ownerOf(info fs.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
