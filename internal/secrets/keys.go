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
	"sync"
	"sync/atomic"
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

// keySnapshot is an immutable view of the loaded KEKs. A key operation builds
// a new one and publishes it only after its database transaction committed.
type keySnapshot struct {
	active domain.ID
	keys   map[domain.ID][]byte
}

// FileKeys is the file-backed KEK provider (spec §10): every referenced KEK,
// loaded and verified once at startup, then changed only by KeyAdmin.
//
// Readers (Active, Key) are lock-free. The unexported ops mutex is the
// process-wide keyOps of ADR-0021: it serializes rotate, retire, export,
// Store.Put and backup reservations.
type FileKeys struct {
	dir  string
	snap atomic.Pointer[keySnapshot]

	ops          sync.Mutex
	reservations map[*Reservation]struct{} // guarded by ops
}

func newFileKeys(dir string, snap *keySnapshot) *FileKeys {
	k := &FileKeys{dir: dir, reservations: map[*Reservation]struct{}{}}
	k.snap.Store(snap)
	return k
}

// Active returns the id and bytes of the KEK that wraps new data keys.
func (k *FileKeys) Active() (domain.ID, []byte) {
	s := k.snap.Load()
	return s.active, s.keys[s.active]
}

// Format keeps master-key bytes out of every fmt verb (%v, %+v, %#v, %s).
func (*FileKeys) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "secrets.FileKeys{[REDACTED]}")
}

// Key returns a loaded KEK by id.
func (k *FileKeys) Key(id domain.ID) ([]byte, bool) {
	key, ok := k.snap.Load().keys[id]
	return key, ok
}

// Reservation protects the KEKs an in-progress backup may reference from
// retirement (ADR-0020). Obtain one with FileKeys.Reserve before reading the
// database snapshot and Release it when the archive is committed or abandoned.
type Reservation struct {
	keys *FileKeys
	ids  []domain.ID // guarded by keys.ops
}

// Reserve records, under keyOps, every KEK currently loaded, plus any KEK a
// rotation loads while the reservation is open. It waits for a running key
// operation or secret write to finish, so the reservation is ordered
// strictly before or after each of them.
func (k *FileKeys) Reserve() *Reservation {
	k.ops.Lock()
	defer k.ops.Unlock()
	r := &Reservation{keys: k}
	for id := range k.snap.Load().keys {
		r.ids = append(r.ids, id)
	}
	slices.Sort(r.ids)
	k.reservations[r] = struct{}{}
	return r
}

// KEKIDs returns the reserved ids, sorted.
func (r *Reservation) KEKIDs() []domain.ID {
	r.keys.ops.Lock()
	defer r.keys.ops.Unlock()
	return slices.Clone(r.ids)
}

// Release ends the reservation; it is safe to call more than once.
func (r *Reservation) Release() {
	r.keys.ops.Lock()
	defer r.keys.ops.Unlock()
	delete(r.keys.reservations, r)
}

// publishLocked installs snap as the loaded keys. Call it after the database
// commit, with ops held.
func (k *FileKeys) publishLocked(snap *keySnapshot) {
	k.snap.Store(snap)
	for r := range k.reservations {
		for id := range snap.keys {
			if !slices.Contains(r.ids, id) {
				r.ids = append(r.ids, id)
			}
		}
		slices.Sort(r.ids)
	}
}

func (k *FileKeys) reservedLocked(id domain.ID) bool {
	for r := range k.reservations {
		if slices.Contains(r.ids, id) {
			return true
		}
	}
	return false
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
	// Check record and active pointer commit together: a crash can never leave
	// a referenced KEK without an active one.
	settings, err := jsonSettings(map[string]string{
		settingCheckPref + id.String(): check,
		settingActiveKEK:               id.String(),
	})
	if err != nil {
		return "", err
	}
	if err := repo.PutSettings(ctx, settings); err != nil {
		_ = os.Remove(keyPath(dir, id)) // nothing references it yet
		return "", fmt.Errorf("store kek settings: %w", err)
	}
	return id, nil
}

func jsonSettings(values map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(values))
	for key, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		out[key] = string(raw)
	}
	return out, nil
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
	loaded := map[domain.ID][]byte{}
	failure := &KeysUnavailableError{}
	for _, id := range wanted {
		key, err := loadVerified(ctx, dir, repo, id)
		if err != nil {
			failure.IDs = append(failure.IDs, id)
			failure.Problems = append(failure.Problems, fmt.Sprintf("kek %s: %v", id, err))
			continue
		}
		loaded[id] = key
	}
	if len(failure.IDs) > 0 {
		return nil, failure
	}
	return newFileKeys(dir, &keySnapshot{active: active, keys: loaded}), nil
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
	return writeKeyFileAt(dir, keyPath(dir, id), key)
}

func writeKeyFileAt(dir, path string, key []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // path is dir + a validated UUID
	if err != nil {
		return fmt.Errorf("create kek file: %w", err)
	}
	if err := writeAndSync(f, key); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write kek file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync keys dir: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // the keys dir, validated by prepareDir
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
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
