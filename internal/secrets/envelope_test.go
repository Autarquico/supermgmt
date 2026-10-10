package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	vectorSecretID = domain.ID("00000000-0001-7000-8000-000000000001")
	otherSecretID  = domain.ID("00000000-0001-7000-8000-000000000003")
	vectorKEKID    = domain.ID("00000000-0001-7000-8000-000000000002")
)

// countingReader yields 0,1,2,... so every "random" value in a vector is known.
type countingReader struct{ next byte }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.next
		r.next++
	}
	return len(p), nil
}

func vectorKEK() []byte {
	kek := make([]byte, keySize)
	for i := range kek {
		kek[i] = 0xA0 + byte(i)
	}
	return kek
}

func sealWith(t *testing.T, secretID domain.ID, plaintext string) sealed {
	t.Helper()
	enc, err := seal(vectorKEK(), vectorKEKID, secretID, []byte(plaintext), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// TestEnvelopeMatchesSpecFormulas rebuilds the §10 envelope with nothing but
// the standard library and the spec's formulas, and compares byte for byte.
func TestEnvelopeMatchesSpecFormulas(t *testing.T) {
	plaintext := []byte("correct horse battery staple")
	got, err := seal(vectorKEK(), vectorKEKID, vectorSecretID, plaintext, &countingReader{})
	if err != nil {
		t.Fatal(err)
	}

	lpOf := func(s string) []byte { return append([]byte{0, 0, 0, byte(len(s))}, s...) }
	aadW := bytes.Join([][]byte{lpOf("supermgmt/dek/v1"), lpOf(string(vectorSecretID)), lpOf(string(vectorKEKID))}, nil)
	version := []byte{0, 0, 0, 1}
	aadP := bytes.Join([][]byte{lpOf("supermgmt/secret/v1"), lpOf(string(vectorSecretID)), append([]byte{0, 0, 0, 4}, version...)}, nil)

	random := &countingReader{}
	dek, nonceW, nonceP := make([]byte, 32), make([]byte, 12), make([]byte, 12)
	_, _ = random.Read(dek)
	_, _ = random.Read(nonceW)
	_, _ = random.Read(nonceP)
	gcmFor := func(key []byte) cipher.AEAD {
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	}
	wantWrapped := gcmFor(vectorKEK()).Seal(bytes.Clone(nonceW), nonceW, dek, aadW)
	wantCipher := gcmFor(dek).Seal(bytes.Clone(nonceP), nonceP, plaintext, aadP)

	if !bytes.Equal(got.WrappedDEK, wantWrapped) {
		t.Errorf("wrapped DEK = %x, want %x", got.WrappedDEK, wantWrapped)
	}
	if !bytes.Equal(got.Ciphertext, wantCipher) {
		t.Errorf("ciphertext = %x, want %x", got.Ciphertext, wantCipher)
	}
}

// TestEnvelopeGoldenVector pins the exact bytes: any change of label, prefix
// or layout must be a deliberate, reviewed one.
func TestEnvelopeGoldenVector(t *testing.T) {
	got, err := seal(vectorKEK(), vectorKEKID, vectorSecretID, []byte("hello"), &countingReader{})
	if err != nil {
		t.Fatal(err)
	}
	const (
		wantWrapped = "202122232425262728292a2b1cdbd682c5739cdda39f8a9c3ecfc5826de9cfced71b33e12120d6820d3913bb5d858845c438772672670afbd1d9fb8a"
		wantCipher  = "2c2d2e2f30313233343536373a98497a0d8268b0efe8b678bb617bda993ca1c0ed"
	)
	if hex.EncodeToString(got.WrappedDEK) != wantWrapped {
		t.Errorf("wrapped DEK = %x", got.WrappedDEK)
	}
	if hex.EncodeToString(got.Ciphertext) != wantCipher {
		t.Errorf("ciphertext = %x", got.Ciphertext)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	for _, plaintext := range []string{"x", string(bytes.Repeat([]byte("k"), 4096)), ""} {
		got, err := open(vectorKEK(), vectorKEKID, vectorSecretID, sealWith(t, vectorSecretID, plaintext))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if string(got) != plaintext {
			t.Errorf("round trip changed a %d-byte plaintext", len(plaintext))
		}
	}
}

func TestEverySealUsesAFreshDEKAndNonces(t *testing.T) {
	a, b := sealWith(t, vectorSecretID, "same"), sealWith(t, vectorSecretID, "same")
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Error("two seals of the same plaintext produced identical bytes")
	}
}

func TestOpenRejectsEveryTamperedByte(t *testing.T) {
	enc := sealWith(t, vectorSecretID, "payload")
	for name, field := range map[string]func(*sealed) []byte{
		"wrapped DEK": func(s *sealed) []byte { return s.WrappedDEK },
		"ciphertext":  func(s *sealed) []byte { return s.Ciphertext },
	} {
		t.Run(name, func(t *testing.T) {
			for i := range field(&enc) {
				tampered := sealed{WrappedDEK: bytes.Clone(enc.WrappedDEK), Ciphertext: bytes.Clone(enc.Ciphertext)}
				field(&tampered)[i] ^= 0x01
				if _, err := open(vectorKEK(), vectorKEKID, vectorSecretID, tampered); err == nil {
					t.Fatalf("flipping byte %d of the %s was accepted", i, name)
				}
			}
		})
	}
}

func TestOpenRejectsTruncatedBlobs(t *testing.T) {
	enc := sealWith(t, vectorSecretID, "payload")
	for _, cut := range []int{0, 5, nonceSize, nonceSize + 15} {
		if _, err := open(vectorKEK(), vectorKEKID, vectorSecretID, sealed{WrappedDEK: enc.WrappedDEK[:cut], Ciphertext: enc.Ciphertext}); err == nil {
			t.Errorf("wrapped DEK cut to %d bytes was accepted", cut)
		}
		if _, err := open(vectorKEK(), vectorKEKID, vectorSecretID, sealed{WrappedDEK: enc.WrappedDEK, Ciphertext: enc.Ciphertext[:cut]}); err == nil {
			t.Errorf("ciphertext cut to %d bytes was accepted", cut)
		}
	}
}

func TestOpenBindsTheEnvelopeToItsSecretAndKEK(t *testing.T) {
	enc := sealWith(t, vectorSecretID, "payload")
	if _, err := open(vectorKEK(), vectorKEKID, otherSecretID, enc); err == nil {
		t.Error("an envelope opened under another secret id")
	}
	if _, err := open(vectorKEK(), otherSecretID, vectorSecretID, enc); err == nil {
		t.Error("an envelope opened under another kek id")
	}
	wrongKEK := bytes.Repeat([]byte{7}, keySize)
	if _, err := open(wrongKEK, vectorKEKID, vectorSecretID, enc); err == nil {
		t.Error("an envelope opened under another kek")
	}
}

// TestWrappedDEKSwapBetweenSecretsFails: moving secret A's wrapped DEK onto
// secret B's row must not open B (aad_w carries the secret id).
func TestWrappedDEKSwapBetweenSecretsFails(t *testing.T) {
	a, b := sealWith(t, vectorSecretID, "a-secret"), sealWith(t, otherSecretID, "b-secret")
	swapped := sealed{WrappedDEK: a.WrappedDEK, Ciphertext: b.Ciphertext}
	if _, err := open(vectorKEK(), vectorKEKID, otherSecretID, swapped); err == nil {
		t.Error("a wrapped DEK from another secret opened this one")
	}
}

// TestLabelSwapFails: the domain-separation labels keep a wrapped DEK from
// standing in for a payload and a payload for a wrapped DEK.
func TestLabelSwapFails(t *testing.T) {
	enc := sealWith(t, vectorSecretID, "payload")
	if _, err := open(vectorKEK(), vectorKEKID, vectorSecretID, sealed{WrappedDEK: enc.Ciphertext, Ciphertext: enc.Ciphertext}); err == nil {
		t.Error("a payload was accepted as a wrapped DEK")
	}
	if _, err := open(vectorKEK(), vectorKEKID, vectorSecretID, sealed{WrappedDEK: enc.WrappedDEK, Ciphertext: enc.WrappedDEK}); err == nil {
		t.Error("a wrapped DEK was accepted as a payload")
	}
}

func TestKEKCheckRecordIsBoundToItsKEKID(t *testing.T) {
	check, err := gcmSeal(vectorKEK(), []byte(labelKEKCheck), aadKEKCheck(vectorKEKID), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gcmOpen(vectorKEK(), check, aadKEKCheck(otherSecretID)); err == nil {
		t.Error("a check record verified under another kek id")
	}
}
