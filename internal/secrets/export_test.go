package secrets

import (
	"crypto/rand"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

type updater interface {
	Repo
	Update(name string, version int, edit func(*Record))
}

// RewrapForTest does what M2's rotate-master-key will do to one row: unwrap
// the DEK under the old KEK, wrap it under the new one, rewrite kek_id.
func RewrapForTest(t *testing.T, repo updater, ref Ref, oldID domain.ID, oldKEK []byte, newID domain.ID, newKEK []byte) Record {
	t.Helper()
	rec, err := repo.Get(t.Context(), ref.Name, ref.Version)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := gcmOpen(oldKEK, rec.WrappedDEK, aadWrap(rec.ID, oldID))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := gcmSeal(newKEK, dek, aadWrap(rec.ID, newID), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repo.Update(ref.Name, ref.Version, func(r *Record) { r.KEKID, r.WrappedDEK = newID, wrapped })
	rec.KEKID = newID
	return rec
}

// NewStoreWithKEKsForTest builds a Store that only knows the given KEKs.
func NewStoreWithKEKsForTest(repo Repo, ids domain.IDGenerator, clock domain.Clock, keys map[domain.ID][]byte, active domain.ID) *Store {
	return NewStore(&FileKeys{active: active, keys: keys}, repo, ids, clock)
}
