package secrets

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$`)

// Ref names one version of a secret. Version 0 means "the latest".
type Ref struct {
	Name    string
	Version int
}

func (r Ref) String() string {
	if r.Version == 0 {
		return r.Name
	}
	return r.Name + "@" + strconv.Itoa(r.Version)
}

// Store is the versioned secret store: each Put is a new version sealed under
// a fresh data key and the active KEK. It is safe for concurrent use.
type Store struct {
	keys   *FileKeys
	repo   Repo
	ids    domain.IDGenerator
	clock  domain.Clock
	random io.Reader

	mu      sync.Mutex // serializes version assignment; one daemon owns the database
	signers map[Ref]cryptossh.Signer
}

// Format keeps the store's key state out of every fmt verb.
func (*Store) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "secrets.Store{[REDACTED]}") }

// NewStore builds a Store over verified keys.
func NewStore(keys *FileKeys, repo Repo, ids domain.IDGenerator, clock domain.Clock) *Store {
	return &Store{keys: keys, repo: repo, ids: ids, clock: clock, random: rand.Reader, signers: map[Ref]cryptossh.Signer{}}
}

// Put stores plaintext as the next version of name. meta is stored unencrypted
// next to the row, so it must never hold secret material.
func (s *Store) Put(ctx context.Context, name string, plaintext audit.Secret, meta map[string]any) (Ref, error) {
	if !namePattern.MatchString(name) {
		return Ref{}, smerr.New(smerr.CodeInvalidArgument, "", "invalid secret name")
	}
	metadata, err := marshalMetadata(meta)
	if err != nil {
		return Ref{}, err
	}
	s.keys.ops.Lock() // keyOps: Put and a rotation never interleave, so the sealing KEK is still active at commit
	defer s.keys.ops.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	version, err := s.nextVersion(ctx, name)
	if err != nil {
		return Ref{}, err
	}
	kekID, kek := s.keys.Active()
	id := s.ids.NewID()
	payload := []byte(plaintext.Reveal())
	defer zero(payload)
	enc, err := seal(kek, kekID, id, payload, s.random)
	if err != nil {
		return Ref{}, fmt.Errorf("seal secret %s: %w", name, err)
	}
	rec := Record{
		ID: id, Name: name, Version: version, EnvelopeVersion: EnvelopeVersion, KEKID: kekID,
		WrappedDEK: enc.WrappedDEK, Ciphertext: enc.Ciphertext, MetadataJSON: metadata, CreatedAt: s.clock.Now(),
	}
	if err := s.repo.Put(ctx, rec); err != nil {
		return Ref{}, fmt.Errorf("store secret %s: %w", name, err)
	}
	return Ref{Name: name, Version: version}, nil
}

func marshalMetadata(meta map[string]any) (string, error) {
	if meta == nil {
		return "{}", nil
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return "", smerr.Wrap(err, smerr.CodeInvalidArgument, "", "secret metadata is not JSON")
	}
	return string(raw), nil
}

func (s *Store) nextVersion(ctx context.Context, name string) (int, error) {
	latest, err := s.repo.Get(ctx, name, 0)
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound && err != nil:
		return 1, nil
	case err != nil:
		return 0, fmt.Errorf("look up latest version of %s: %w", name, err)
	}
	return latest.Version + 1, nil
}

// Get decrypts one version of a secret.
func (s *Store) Get(ctx context.Context, ref Ref) (audit.Secret, error) {
	rec, err := s.repo.Get(ctx, ref.Name, ref.Version)
	if err != nil {
		return "", fmt.Errorf("load secret %s: %w", ref, err)
	}
	plaintext, err := s.decrypt(rec)
	if err != nil {
		return "", fmt.Errorf("secret %s: %w", ref, err)
	}
	defer zero(plaintext)
	return audit.Secret(plaintext), nil
}

func (s *Store) decrypt(rec Record) ([]byte, error) {
	if rec.EnvelopeVersion != EnvelopeVersion {
		return nil, smerr.New(smerr.CodeInternal, "", fmt.Sprintf("unsupported envelope version %d", rec.EnvelopeVersion))
	}
	kek, ok := s.keys.Key(rec.KEKID)
	if !ok {
		return nil, smerr.New(smerr.CodeInternal, "", fmt.Sprintf("kek %s is not loaded", rec.KEKID))
	}
	return open(kek, rec.KEKID, rec.ID, sealed{WrappedDEK: rec.WrappedDEK, Ciphertext: rec.Ciphertext})
}

// Signer returns the SSH signer of a stored private key, decrypting it on
// first use and caching it per (name, version). The plaintext buffer is zeroed
// as soon as the key is parsed.
func (s *Store) Signer(ctx context.Context, ref Ref) (cryptossh.Signer, error) {
	rec, err := s.repo.Get(ctx, ref.Name, ref.Version)
	if err != nil {
		return nil, fmt.Errorf("load secret %s: %w", ref, err)
	}
	resolved := Ref{Name: rec.Name, Version: rec.Version}
	s.mu.Lock()
	defer s.mu.Unlock()
	if signer, ok := s.signers[resolved]; ok {
		return signer, nil
	}
	plaintext, err := s.decrypt(rec)
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", resolved, err)
	}
	defer zero(plaintext)
	signer, err := cryptossh.ParsePrivateKey(plaintext)
	if err != nil {
		return nil, smerr.New(smerr.CodeInternal, "", fmt.Sprintf("secret %s is not an SSH private key", resolved))
	}
	s.signers[resolved] = signer
	return signer, nil
}
