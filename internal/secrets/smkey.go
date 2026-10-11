package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// SMKEY1 is the passphrase-wrapped master-key export of spec §10:
//
//	"SMKEY1" | u8 version=1 | lp(kek_id) | u8 log2N | u32 r | u32 p | salt(16) | nonce(12)
//	| AES-256-GCM(scrypt(passphrase, salt, N, r, p, 32), nonce, KEK, aad = all preceding bytes)
const (
	smkeyMagic   = "SMKEY1"
	smkeyVersion = 1
	saltSize     = 16

	// MinPassphraseLength is the shortest passphrase an export accepts, in characters.
	MinPassphraseLength = 12

	defaultLog2N = 17
	defaultR     = 8
	defaultP     = 1

	minLog2N = 15
	maxLog2N = 20
	fixedR   = 8
	maxP     = 4

	uuidTextSize = 36
	gcmTagSize   = 16

	maxSMKEYSize = 512 // far above a real export (about 160 bytes); bounds parsing of hostile input
)

var errBadExport = smerr.New(smerr.CodeInvalidArgument, "", "key export is malformed, uses unsupported parameters, or the passphrase is wrong")

type kdfParams struct {
	log2N uint8
	r, p  uint32
}

var defaultKDF = kdfParams{log2N: defaultLog2N, r: defaultR, p: defaultP}

func (k kdfParams) valid() bool {
	return k.log2N >= minLog2N && k.log2N <= maxLog2N && k.r == fixedR && k.p >= 1 && k.p <= maxP
}

// EncodeKeyExport wraps kek under passphrase with the default scrypt cost.
// The passphrase must have at least MinPassphraseLength characters.
func EncodeKeyExport(id domain.ID, kek []byte, passphrase string) ([]byte, error) {
	return encodeKeyExport(id, kek, passphrase, defaultKDF, rand.Reader)
}

func encodeKeyExport(id domain.ID, kek []byte, passphrase string, kdf kdfParams, random io.Reader) ([]byte, error) {
	if utf8.RuneCountInString(passphrase) < MinPassphraseLength {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("passphrase must have at least %d characters", MinPassphraseLength))
	}
	if !kdf.valid() || len(kek) != keySize {
		return nil, errors.New("export parameters out of range")
	}
	salt, nonce := make([]byte, saltSize), make([]byte, nonceSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	header := concat([]byte(smkeyMagic), []byte{smkeyVersion}, lpString(id.String()), []byte{kdf.log2N},
		binary.BigEndian.AppendUint32(nil, kdf.r), binary.BigEndian.AppendUint32(nil, kdf.p), salt, nonce)
	wrapKey, err := deriveWrapKey(passphrase, salt, kdf)
	if err != nil {
		return nil, err
	}
	defer zero(wrapKey)
	aead, err := newGCM(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("init export cipher: %w", err)
	}
	return aead.Seal(header, nonce, kek, header[:len(header):len(header)]), nil
}

func deriveWrapKey(passphrase string, salt []byte, kdf kdfParams) ([]byte, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, 1<<kdf.log2N, int(kdf.r), int(kdf.p), keySize)
	if err != nil {
		return nil, fmt.Errorf("derive export key: %w", err)
	}
	return key, nil
}

// DecodeKeyExport authenticates and unwraps an SMKEY1 export. Parameters
// outside the accepted bounds are rejected before any key derivation runs; a
// wrong passphrase and a tampered file are indistinguishable.
func DecodeKeyExport(export []byte, passphrase string) (domain.ID, []byte, error) {
	header, id, kdf, err := parseExportHeader(export)
	if err != nil {
		return "", nil, err
	}
	salt := header[len(header)-saltSize-nonceSize : len(header)-nonceSize]
	nonce := header[len(header)-nonceSize:]
	wrapKey, err := deriveWrapKey(passphrase, salt, kdf)
	if err != nil {
		return "", nil, err
	}
	defer zero(wrapKey)
	aead, err := newGCM(wrapKey)
	if err != nil {
		return "", nil, fmt.Errorf("init export cipher: %w", err)
	}
	kek, err := aead.Open(nil, nonce, export[len(header):], header)
	if err != nil || len(kek) != keySize {
		zero(kek)
		return "", nil, errBadExport
	}
	return id, kek, nil
}

// parseExportHeader returns the authenticated-data prefix of export with the
// id and cost parameters it declares, after checking every bound.
func parseExportHeader(export []byte) (header []byte, id domain.ID, kdf kdfParams, err error) {
	if len(export) > maxSMKEYSize {
		return nil, "", kdfParams{}, errBadExport
	}
	r := bytes.NewReader(export)
	magic := make([]byte, len(smkeyMagic)+1)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic[:len(smkeyMagic)]) != smkeyMagic || magic[len(smkeyMagic)] != smkeyVersion {
		return nil, "", kdfParams{}, errBadExport
	}
	var idLen uint32
	if err := binary.Read(r, binary.BigEndian, &idLen); err != nil || idLen != uuidTextSize {
		return nil, "", kdfParams{}, errBadExport
	}
	rawID := make([]byte, idLen)
	if _, err := io.ReadFull(r, rawID); err != nil {
		return nil, "", kdfParams{}, errBadExport
	}
	if id, err = domain.ParseID(string(rawID)); err != nil {
		return nil, "", kdfParams{}, errBadExport
	}
	if err := binary.Read(r, binary.BigEndian, &kdf.log2N); err != nil {
		return nil, "", kdfParams{}, errBadExport
	}
	if err := binary.Read(r, binary.BigEndian, &kdf.r); err != nil {
		return nil, "", kdfParams{}, errBadExport
	}
	if err := binary.Read(r, binary.BigEndian, &kdf.p); err != nil {
		return nil, "", kdfParams{}, errBadExport
	}
	if !kdf.valid() {
		return nil, "", kdfParams{}, errBadExport
	}
	headerLen := len(export) - r.Len() + saltSize + nonceSize
	if len(export) != headerLen+keySize+gcmTagSize {
		return nil, "", kdfParams{}, errBadExport
	}
	return export[:headerLen], id, kdf, nil
}
