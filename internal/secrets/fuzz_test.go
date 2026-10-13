package secrets

import (
	"crypto/rand"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

func FuzzDecodeKeyExport(f *testing.F) {
	const passphrase = "correct horse battery"
	id := domaintest.NewSequentialIDs().NewID()
	valid, err := encodeKeyExport(id, make([]byte, keySize), passphrase, fastKDF, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte(smkeyMagic))
	f.Add(append([]byte(smkeyMagic), smkeyVersion))
	f.Add(make([]byte, maxSMKEYSize+1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, export []byte) {
		gotID, gotKEK, err := DecodeKeyExport(export, passphrase)
		if err != nil {
			if gotID != "" || gotKEK != nil {
				t.Fatalf("an error came with a key for %q", gotID)
			}
			return
		}
		if len(gotKEK) != keySize {
			t.Fatalf("decoded key has %d bytes", len(gotKEK))
		}
		if _, err := domain.ParseID(gotID.String()); err != nil {
			t.Fatalf("decoded id %q is invalid: %v", gotID, err)
		}
	})
}
