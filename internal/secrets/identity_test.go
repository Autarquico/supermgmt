package secrets_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

func newTestKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestEnsureSSHIdentityGeneratesOnceThenReuses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	first, err := secrets.EnsureSSHIdentity(ctx, f.store)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Generated || first.Ref != (secrets.Ref{Name: "ssh/default", Version: 1}) {
		t.Fatalf("first = %+v", first)
	}
	second, err := secrets.EnsureSSHIdentity(ctx, f.store)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generated || second.Ref != first.Ref || second.AuthorizedKey != first.AuthorizedKey {
		t.Errorf("second call changed the identity: %+v", second)
	}
}

func TestIdentitySurvivesARestartOfTheStore(t *testing.T) {
	f := newFixture(t)
	first, _ := secrets.EnsureSSHIdentity(context.Background(), f.store)

	keys := mustOpenKeys(t, f.dir, f.repo, f.ids)
	restarted := secrets.NewStore(keys, f.repo, f.ids, f.clock)
	again, err := secrets.EnsureSSHIdentity(context.Background(), restarted)
	if err != nil {
		t.Fatal(err)
	}
	if again.Generated || again.Ref.Version != 1 || again.FingerprintSHA256 != first.FingerprintSHA256 {
		t.Errorf("restart regenerated the identity: %+v", again)
	}
}

func TestIdentityIsAnEd25519OpenSSHKeyWhoseSignerMatchesThePublicHalf(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, err := secrets.EnsureSSHIdentity(ctx, f.store)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id.AuthorizedKey, "ssh-ed25519 ") || strings.ContainsAny(id.AuthorizedKey, "\n") {
		t.Errorf("authorized key = %q", id.AuthorizedKey)
	}
	public, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(id.AuthorizedKey))
	if err != nil {
		t.Fatal(err)
	}
	if got := cryptossh.FingerprintSHA256(public); got != id.FingerprintSHA256 {
		t.Errorf("fingerprint %s, metadata says %s", got, id.FingerprintSHA256)
	}
	signer, err := f.store.Signer(ctx, id.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), public.Marshal()) {
		t.Error("stored private key does not match the published public key")
	}
	plain, _ := f.store.Get(ctx, id.Ref)
	if !strings.HasPrefix(plain.Reveal(), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("the private key is not stored in OpenSSH format")
	}
}

func TestMalformedIdentityMetadataIsAnError(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.store.Put(ctx, secrets.SSHIdentityName, audit.Secret(newTestKeyPEM(t)), map[string]any{"x": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.EnsureSSHIdentity(ctx, f.store); smerr.CodeOf(err) != smerr.CodeInternal || err == nil {
		t.Errorf("got %v, want an INTERNAL error", err)
	}
}

// TestNoKeyMaterialLeaksAnywhere is the plaintext rule of ADR-0016: the
// private key lives only in memory. Everything that can be printed, stored or
// returned as an error is scanned for the PEM header and the raw key bytes.
func TestNoKeyMaterialLeaksAnywhere(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, err := secrets.EnsureSSHIdentity(ctx, f.store)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := f.store.Get(ctx, id.Ref)
	if err != nil {
		t.Fatal(err)
	}
	pemText := plain.Reveal()
	body := strings.Join(strings.Split(strings.TrimSpace(pemText), "\n")[1:3], "")
	_, kek := f.keys.Active()

	var surfaces []string
	surfaces = append(surfaces, string(f.repo.Dump()))
	rec, _ := f.repo.Get(ctx, id.Ref.Name, id.Ref.Version)
	for _, value := range []any{id, id.Ref, rec, plain, f.store, f.keys} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			surfaces = append(surfaces, fmt.Sprintf(verb, value))
		}
	}
	_, tamperErr := f.store.Get(ctx, secrets.Ref{Name: "ssh/default", Version: 9})
	surfaces = append(surfaces, fmt.Sprint(tamperErr))
	f.repo.Update(id.Ref.Name, id.Ref.Version, func(r *secrets.Record) { r.Ciphertext[20] ^= 1 })
	_, undecryptable := f.store.Get(ctx, id.Ref)
	surfaces = append(surfaces, fmt.Sprint(undecryptable))

	for i, s := range surfaces {
		switch {
		case strings.Contains(s, "PRIVATE KEY"):
			t.Errorf("surface %d contains a PEM header", i)
		case strings.Contains(s, body):
			t.Errorf("surface %d contains the key body", i)
		case strings.Contains(s, string(kek)) || strings.Contains(s, fmt.Sprintf("%v", kek)):
			t.Errorf("surface %d contains the KEK", i)
		}
	}
}
