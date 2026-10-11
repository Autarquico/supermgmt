package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const testPassphrase = "correct horse battery"

var fastKDF = kdfParams{log2N: minLog2N, r: fixedR, p: 1}

func testKEK(t *testing.T) []byte {
	t.Helper()
	kek := make([]byte, keySize)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	return kek
}

func fastExport(t *testing.T, id domain.ID, kek []byte) []byte {
	t.Helper()
	export, err := encodeKeyExport(id, kek, testPassphrase, fastKDF, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return export
}

// rawHeader builds an export-shaped blob with arbitrary KDF parameters and a
// zero body, for bound checks: it must be rejected before any derivation.
func rawHeader(id domain.ID, log2N uint8, r, p uint32) []byte {
	header := concat([]byte(smkeyMagic), []byte{smkeyVersion}, lpString(id.String()), []byte{log2N},
		binary.BigEndian.AppendUint32(nil, r), binary.BigEndian.AppendUint32(nil, p),
		make([]byte, saltSize), make([]byte, nonceSize))
	return append(header, make([]byte, keySize+gcmTagSize)...)
}

func TestExportRoundTripsAtDefaultCost(t *testing.T) {
	id, kek := domaintest.NewSequentialIDs().NewID(), testKEK(t)

	export, err := EncodeKeyExport(id, kek, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	gotID, gotKEK, err := DecodeKeyExport(export, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id || !bytes.Equal(gotKEK, kek) {
		t.Error("round trip changed the id or the key")
	}
	if !bytes.HasPrefix(export, []byte("SMKEY1\x01")) || export[6+1+4+36] != defaultLog2N {
		t.Errorf("header does not follow spec §10: % x", export[:56])
	}
	if bytes.Contains(export, kek) {
		t.Error("the export contains the key in the clear")
	}
}

func TestExportNeverRepeatsSaltOrNonce(t *testing.T) {
	id, kek := domaintest.NewSequentialIDs().NewID(), testKEK(t)
	a, b := fastExport(t, id, kek), fastExport(t, id, kek)
	if bytes.Equal(a, b) {
		t.Error("two exports of one key are identical")
	}
}

func TestExportNeedsALongPassphrase(t *testing.T) {
	id, kek := domaintest.NewSequentialIDs().NewID(), testKEK(t)
	for _, passphrase := range []string{"", "short", "elevenchars", strings.Repeat("ñ", MinPassphraseLength-1)} {
		_, err := encodeKeyExport(id, kek, passphrase, fastKDF, rand.Reader)
		if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("passphrase %q: error = %v, want INVALID_ARGUMENT", passphrase, err)
		}
	}
	if _, err := encodeKeyExport(id, kek, "twelve chars", fastKDF, rand.Reader); err != nil {
		t.Errorf("12 characters refused: %v", err)
	}
	if _, err := encodeKeyExport(id, kek, strings.Repeat("ñ", MinPassphraseLength), fastKDF, rand.Reader); err != nil {
		t.Errorf("12 multi-byte characters refused: %v", err)
	}
}

func TestImportRejectsAWrongPassphraseAndAnyTamperedByte(t *testing.T) {
	id, kek := domaintest.NewSequentialIDs().NewID(), testKEK(t)
	export := fastExport(t, id, kek)

	if _, _, err := DecodeKeyExport(export, "another passphrase"); err == nil {
		t.Error("wrong passphrase accepted")
	}
	// id text, salt, nonce and body: each is covered by the AEAD or the derivation.
	idByte := len(smkeyMagic) + 1 + 4
	saltByte := len(export) - keySize - gcmTagSize - nonceSize - 1
	nonceByte := len(export) - keySize - gcmTagSize - 1
	for name, at := range map[string]int{"id": idByte + 3, "salt": saltByte, "nonce": nonceByte, "body": len(export) - 20, "tag": len(export) - 1} {
		tampered := bytes.Clone(export)
		tampered[at] ^= 0x01
		if _, _, err := DecodeKeyExport(tampered, testPassphrase); err == nil {
			t.Errorf("tampered %s byte accepted", name)
		}
	}
}

func TestImportRefusesMalformedFiles(t *testing.T) {
	id, kek := domaintest.NewSequentialIDs().NewID(), testKEK(t)
	good := fastExport(t, id, kek)
	cases := map[string][]byte{
		"empty":           nil,
		"truncated":       good[:len(good)-1],
		"trailing bytes":  append(bytes.Clone(good), 0),
		"wrong magic":     append([]byte("SMKEY2"), good[6:]...),
		"unknown version": append(append([]byte{}, good[:6]...), append([]byte{2}, good[7:]...)...),
		"oversized":       bytes.Repeat([]byte{'x'}, maxSMKEYSize+1),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := DecodeKeyExport(blob, testPassphrase); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Errorf("error = %v, want INVALID_ARGUMENT", err)
			}
		})
	}
}

func TestImportEnforcesTheCostBoundsBeforeDerivingAnything(t *testing.T) {
	id := domaintest.NewSequentialIDs().NewID()
	cases := []struct {
		name  string
		log2N uint8
		r, p  uint32
		ok    bool
	}{
		{"N below 2^15", 14, 8, 1, false},
		{"N above 2^20", 21, 8, 1, false},
		{"r other than 8", 15, 7, 1, false},
		{"r above 8", 15, 9, 1, false},
		{"p zero", 15, 8, 0, false},
		{"p above 4", 15, 8, 5, false},
		{"huge p", 15, 8, 1 << 30, false},
		{"huge N", 255, 8, 1, false},
		{"lowest accepted", 15, 8, 1, true},
		{"highest p accepted", 15, 8, 4, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blob := rawHeader(id, c.log2N, c.r, c.p)
			if !c.ok {
				start := time.Now()
				_, _, err := DecodeKeyExport(blob, testPassphrase)
				if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
					t.Errorf("error = %v, want INVALID_ARGUMENT", err)
				}
				if took := time.Since(start); took > 250*time.Millisecond {
					t.Errorf("rejection took %v: parameters were not checked before the derivation", took)
				}
				return
			}
			if _, _, _, err := parseExportHeader(blob); err != nil {
				t.Errorf("parameters within bounds refused: %v", err)
			}
		})
	}
}

func TestImportRejectsANonUUIDv7KEKID(t *testing.T) {
	blob := rawHeader("00000000-0001-4000-8000-000000000000", 15, 8, 1)
	if _, _, err := DecodeKeyExport(blob, testPassphrase); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("error = %v, want INVALID_ARGUMENT", err)
	}
}
