package secrets

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// SSHIdentityName is the secret that holds the instance SSH identity
// (spec §8.4: secret://ssh/default).
const SSHIdentityName = "ssh/default"

// Identity describes the instance SSH key pair. Only public facts are exposed;
// the private key is reachable solely through Store.Signer.
type Identity struct {
	Ref               Ref
	AuthorizedKey     string // one authorized_keys line, no comment
	FingerprintSHA256 string // "SHA256:..."
	Generated         bool   // true when this call created the identity
}

type identityMetadata struct {
	PublicKey         string `json:"public_key"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

// EnsureSSHIdentity returns the instance identity, generating an Ed25519 key
// pair on first use. The caller emits the ssh_identity.generated event
// (fingerprint only) when Generated is true.
func EnsureSSHIdentity(ctx context.Context, s *Store) (Identity, error) {
	rec, err := s.repo.Get(ctx, SSHIdentityName, 0)
	switch {
	case err == nil:
		return identityOf(rec)
	case smerr.CodeOf(err) != smerr.CodeNotFound:
		return Identity{}, fmt.Errorf("look up ssh identity: %w", err)
	}
	return generateIdentity(ctx, s)
}

func identityOf(rec Record) (Identity, error) {
	var meta identityMetadata
	if err := json.Unmarshal([]byte(rec.MetadataJSON), &meta); err != nil || meta.PublicKey == "" || meta.FingerprintSHA256 == "" {
		return Identity{}, smerr.New(smerr.CodeInternal, "", "ssh identity metadata is malformed")
	}
	return Identity{
		Ref:           Ref{Name: rec.Name, Version: rec.Version},
		AuthorizedKey: meta.PublicKey, FingerprintSHA256: meta.FingerprintSHA256,
	}, nil
}

func generateIdentity(ctx context.Context, s *Store) (Identity, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate ssh identity: %w", err)
	}
	defer zero(private)
	block, err := cryptossh.MarshalPrivateKey(private, "")
	if err != nil {
		return Identity{}, fmt.Errorf("encode ssh identity: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	defer zero(pemBytes)
	sshPublic, err := cryptossh.NewPublicKey(public)
	if err != nil {
		return Identity{}, fmt.Errorf("encode ssh public key: %w", err)
	}
	meta := identityMetadata{
		PublicKey:         strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(sshPublic))),
		FingerprintSHA256: cryptossh.FingerprintSHA256(sshPublic),
	}
	ref, err := s.Put(ctx, SSHIdentityName, audit.Secret(pemBytes), map[string]any{
		"public_key": meta.PublicKey, "fingerprint_sha256": meta.FingerprintSHA256,
	})
	if err != nil {
		return Identity{}, err
	}
	return Identity{Ref: ref, AuthorizedKey: meta.PublicKey, FingerprintSHA256: meta.FingerprintSHA256, Generated: true}, nil
}
