// Package secrets is the M1 slice of spec §10 (ADR-0003, ADR-0016): AES-256-GCM
// envelope encryption with file-based master keys, a versioned secret store,
// and the instance SSH identity. It introduces no cryptography of its own.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	// EnvelopeVersion is the only envelope format this slice reads and writes.
	EnvelopeVersion = 1

	keySize   = 32
	nonceSize = 12

	labelDEK      = "supermgmt/dek/v1"
	labelSecret   = "supermgmt/secret/v1"
	labelKEKCheck = "supermgmt/kek-check/v1"
)

// lp is the spec's length prefix: uint32be(len(x)) || x.
func lp(x []byte) []byte {
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(x)), uint32(len(x))) //nolint:gosec // lengths here are short labels and ids
	return append(out, x...)
}

func lpString(s string) []byte { return lp([]byte(s)) }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func aadWrap(secretID, kekID domain.ID) []byte {
	return concat(lpString(labelDEK), lpString(secretID.String()), lpString(kekID.String()))
}

func aadPayload(secretID domain.ID) []byte {
	version := binary.BigEndian.AppendUint32(nil, EnvelopeVersion)
	return concat(lpString(labelSecret), lpString(secretID.String()), lp(version))
}

func aadKEKCheck(kekID domain.ID) []byte {
	return concat(lpString(labelKEKCheck), lpString(kekID.String()))
}

// sealed is the encrypted form of one secret version: both fields are
// nonce(12) || ciphertext || tag.
type sealed struct {
	WrappedDEK []byte
	Ciphertext []byte
}

// seal encrypts plaintext under a fresh DEK and wraps the DEK under kek.
func seal(kek []byte, kekID, secretID domain.ID, plaintext []byte, random io.Reader) (sealed, error) {
	dek := make([]byte, keySize)
	defer zero(dek)
	if _, err := io.ReadFull(random, dek); err != nil {
		return sealed{}, fmt.Errorf("generate data key: %w", err)
	}
	wrapped, err := gcmSeal(kek, dek, aadWrap(secretID, kekID), random)
	if err != nil {
		return sealed{}, fmt.Errorf("wrap data key: %w", err)
	}
	ciphertext, err := gcmSeal(dek, plaintext, aadPayload(secretID), random)
	if err != nil {
		return sealed{}, fmt.Errorf("encrypt payload: %w", err)
	}
	return sealed{WrappedDEK: wrapped, Ciphertext: ciphertext}, nil
}

// open reverses seal. Every failure is the same opaque error: callers learn
// that authentication failed, never which part or why.
func open(kek []byte, kekID, secretID domain.ID, s sealed) ([]byte, error) {
	dek, err := gcmOpen(kek, s.WrappedDEK, aadWrap(secretID, kekID))
	if err != nil {
		return nil, errUndecryptable
	}
	defer zero(dek)
	plaintext, err := gcmOpen(dek, s.Ciphertext, aadPayload(secretID))
	if err != nil {
		return nil, errUndecryptable
	}
	return plaintext, nil
}

var errUndecryptable = smerr.New(smerr.CodeInternal, "", "secret cannot be decrypted: authentication failed")

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func gcmSeal(key, plaintext, aad []byte, random io.Reader) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(key, blob, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < nonceSize+aead.Overhead() {
		return nil, errUndecryptable
	}
	return aead.Open(nil, blob[:nonceSize], blob[nonceSize:], aad)
}

func zero(b []byte) { clear(b) }
