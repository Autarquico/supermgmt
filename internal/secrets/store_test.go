package secrets_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type fixture struct {
	dir   string
	repo  *secretstest.MemRepo
	ids   domain.IDGenerator
	clock *domaintest.FakeClock
	keys  *secrets.FileKeys
	store *secrets.Store
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{dir: keysDir(t), repo: secretstest.NewMemRepo(), ids: domaintest.NewSequentialIDs(), clock: domaintest.NewFakeClock(epoch)}
	f.keys = mustOpenKeys(t, f.dir, f.repo, f.ids)
	f.store = secrets.NewStore(f.keys, f.repo, f.ids, f.clock)
	return f
}

func TestPutThenGetReturnsThePlaintext(t *testing.T) {
	f := newFixture(t)
	ref, err := f.store.Put(context.Background(), "demo/token", "s3cret-value", map[string]any{"purpose": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if ref != (secrets.Ref{Name: "demo/token", Version: 1}) {
		t.Fatalf("ref = %+v", ref)
	}
	got, err := f.store.Get(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reveal() != "s3cret-value" {
		t.Error("Get did not return the stored plaintext")
	}
}

func TestEachPutIsANewVersionAndOldVersionsStayReadable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	v1, _ := f.store.Put(ctx, "demo/token", "one", nil)
	v2, err := f.store.Put(ctx, "demo/token", "two", nil)
	if err != nil {
		t.Fatal(err)
	}
	if v1.Version != 1 || v2.Version != 2 {
		t.Fatalf("versions = %d, %d", v1.Version, v2.Version)
	}
	for ref, want := range map[secrets.Ref]string{v1: "one", v2: "two", {Name: "demo/token"}: "two"} {
		got, err := f.store.Get(ctx, ref)
		if err != nil || got.Reveal() != want {
			t.Errorf("Get(%s) = %q, %v; want %q", ref, got.Reveal(), err, want)
		}
	}
}

func TestEveryVersionGetsItsOwnDEK(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, _ = f.store.Put(ctx, "demo/token", "same", nil)
	_, _ = f.store.Put(ctx, "demo/token", "same", nil)
	a, _ := f.repo.Get(ctx, "demo/token", 1)
	b, _ := f.repo.Get(ctx, "demo/token", 2)
	if bytes.Equal(a.WrappedDEK, b.WrappedDEK) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Error("two versions of the same plaintext share key material")
	}
}

func TestStoredRowUsesEnvelopeV1UnderTheActiveKEK(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.Put(context.Background(), "demo/token", "v", nil); err != nil {
		t.Fatal(err)
	}
	rec, _ := f.repo.Get(context.Background(), "demo/token", 1)
	active, _ := f.keys.Active()
	if rec.EnvelopeVersion != 1 || rec.KEKID != active || !rec.CreatedAt.Equal(epoch) || rec.MetadataJSON != "{}" {
		t.Errorf("row = %+v", rec)
	}
}

func TestPutRejectsInvalidNames(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"", "Upper", "../x", "a//b", "/abs", "trailing/", "sp ace", "a/../b"} {
		_, err := f.store.Put(context.Background(), name, "v", nil)
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("Put(%q) = %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestGetMissingSecretIsNotFound(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.Get(context.Background(), secrets.Ref{Name: "nope", Version: 1})
	if smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("got %v, want NOT_FOUND", err)
	}
}

func TestTamperedRowFailsWithoutRevealingAnything(t *testing.T) {
	f := newFixture(t)
	ref, _ := f.store.Put(context.Background(), "demo/token", "PLAINTEXT-MARKER-42", nil)
	f.repo.Update(ref.Name, ref.Version, func(r *secrets.Record) { r.Ciphertext[len(r.Ciphertext)-1] ^= 1 })

	_, err := f.store.Get(context.Background(), ref)
	if err == nil {
		t.Fatal("tampered row decrypted")
	}
	if strings.Contains(err.Error(), "PLAINTEXT-MARKER-42") {
		t.Errorf("error leaks plaintext: %v", err)
	}
}

func TestSwappingWrappedDEKsBetweenRowsFails(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, _ := f.store.Put(ctx, "demo/a", "A", nil)
	b, _ := f.store.Put(ctx, "demo/b", "B", nil)
	rowA, _ := f.repo.Get(ctx, a.Name, a.Version)
	f.repo.Update(b.Name, b.Version, func(r *secrets.Record) { r.WrappedDEK = rowA.WrappedDEK })
	if _, err := f.store.Get(ctx, b); err == nil {
		t.Error("a wrapped DEK moved between secrets still decrypted")
	}
}

func TestUnknownEnvelopeVersionIsRefused(t *testing.T) {
	f := newFixture(t)
	ref, _ := f.store.Put(context.Background(), "demo/token", "v", nil)
	f.repo.Update(ref.Name, ref.Version, func(r *secrets.Record) { r.EnvelopeVersion = 2 })
	if _, err := f.store.Get(context.Background(), ref); err == nil {
		t.Error("an unknown envelope version was read")
	}
}

// TestRewrapUnderANewKEKIsTransparent models the M2 rotate-master-key: DEKs
// are rewrapped and kek_id rewritten; the version and the plaintext stay.
func TestRewrapUnderANewKEKIsTransparent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ref, err := f.store.Put(ctx, secrets.SSHIdentityName, audit.Secret(newTestKeyPEM(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Signer(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}

	oldKEKID, oldKEK := f.keys.Active()
	newKEKID := f.ids.NewID()
	newKEK := make([]byte, 32)
	_, _ = rand.Read(newKEK)
	rewrapped := secrets.RewrapForTest(t, f.repo, ref, oldKEKID, oldKEK, newKEKID, newKEK)
	if rewrapped.KEKID != newKEKID {
		t.Fatal("test helper did not rewrap")
	}

	fresh := secrets.NewStoreWithKEKsForTest(f.repo, f.ids, f.clock, map[domain.ID][]byte{newKEKID: newKEK}, newKEKID)
	after, err := fresh.Signer(ctx, ref)
	if err != nil {
		t.Fatalf("signer after rewrap: %v", err)
	}
	if !bytes.Equal(before.PublicKey().Marshal(), after.PublicKey().Marshal()) {
		t.Error("rewrap changed the key")
	}
}

func TestSignerIsCachedPerVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	v1, _ := f.store.Put(ctx, "demo/key", audit.Secret(newTestKeyPEM(t)), nil)
	first, err := f.store.Signer(ctx, v1)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := f.store.Signer(ctx, secrets.Ref{Name: "demo/key"})
	if first != again {
		t.Error("the latest ref did not resolve to the cached v1 signer")
	}
	v2, _ := f.store.Put(ctx, "demo/key", audit.Secret(newTestKeyPEM(t)), nil)
	second, _ := f.store.Signer(ctx, v2)
	if bytes.Equal(first.PublicKey().Marshal(), second.PublicKey().Marshal()) {
		t.Error("v2 resolved to the v1 signer")
	}
	pinned, _ := f.store.Signer(ctx, v1)
	if !bytes.Equal(first.PublicKey().Marshal(), pinned.PublicKey().Marshal()) {
		t.Error("v1 stopped working after v2 was stored")
	}
}

func TestSignerRejectsASecretThatIsNotAKey(t *testing.T) {
	f := newFixture(t)
	ref, _ := f.store.Put(context.Background(), "demo/token", "NOT-A-KEY-MARKER", nil)
	_, err := f.store.Signer(context.Background(), ref)
	if err == nil {
		t.Fatal("a token parsed as an SSH key")
	}
	if strings.Contains(err.Error(), "NOT-A-KEY-MARKER") {
		t.Errorf("error leaks plaintext: %v", err)
	}
}

func TestNothingFormatsOrStoresThePlaintext(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const marker = "PLAINTEXT-MARKER-9f3a"
	ref, err := f.store.Put(ctx, "demo/token", marker, map[string]any{"purpose": "leak test"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.store.Get(ctx, ref)
	rec, _ := f.repo.Get(ctx, ref.Name, ref.Version)
	for _, value := range []any{ref, got, rec, f.store, f.keys} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if out := fmt.Sprintf(verb, value); strings.Contains(out, marker) {
				t.Errorf("%s of %T leaks the plaintext", verb, value)
			}
		}
	}
	if bytes.Contains(f.repo.Dump(), []byte(marker)) {
		t.Error("plaintext found in the stored rows")
	}
}

func TestAStagedSecretIsSealedInvisibleAndActivatedOnlyForTheApprovedValue(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	staged, err := f.store.Stage(ctx, "demo/token", "staged-value", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(f.repo.Dump(), []byte("staged-value")) {
		t.Error("the staged plaintext reached the repository")
	}
	if _, err := f.store.Get(ctx, secrets.Ref{Name: "demo/token"}); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("Get on a staged secret: %v, want NOT_FOUND", err)
	}

	wrong := staged
	wrong.CiphertextSHA256 = strings.Repeat("0", 64)
	if _, err := f.store.Activate(ctx, wrong); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("activating with another digest: %v, want CONFLICT", err)
	}
	ref, err := f.store.Activate(ctx, staged)
	if err != nil || ref != (secrets.Ref{Name: "demo/token", Version: 1}) {
		t.Fatalf("Activate = %+v, %v", ref, err)
	}
	again, err := f.store.Activate(ctx, staged)
	if err != nil || again != ref {
		t.Errorf("a repeated Activate = %+v, %v; want the same version", again, err)
	}
	if got, err := f.store.Get(ctx, ref); err != nil || got.Reveal() != "staged-value" {
		t.Errorf("activated value = %q, %v", got.Reveal(), err)
	}
}

func TestASwappedStagedRowIsNotActivated(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	approved, err := f.store.Stage(ctx, "demo/token", "approved-value", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.store.Stage(ctx, "demo/token", "other-value", nil)
	if err != nil {
		t.Fatal(err)
	}

	swapped := secrets.Staged{ID: other.ID, Name: approved.Name, CiphertextSHA256: approved.CiphertextSHA256}

	if _, err := f.store.Activate(ctx, swapped); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Fatalf("activating another row under the approved digest: %v, want CONFLICT", err)
	}
}

func TestADiscardedStagedSecretCannotBeActivated(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	staged, err := f.store.Stage(ctx, "demo/token", "v", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.store.Discard(ctx, staged.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := f.store.Activate(ctx, staged); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("Activate after Discard: %v, want NOT_FOUND", err)
	}
	if ids, _ := f.repo.ReferencedKEKs(ctx); len(ids) != 0 {
		t.Errorf("a discarded secret still references %v", ids)
	}
}

func TestStageRefusesAnInvalidName(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.Stage(context.Background(), "Bad Name", "v", nil); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("error = %v, want INVALID_ARGUMENT", err)
	}
}
