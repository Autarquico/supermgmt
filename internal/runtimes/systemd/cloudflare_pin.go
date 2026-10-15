package systemd

import (
	"crypto/sha1" //nolint:gosec // OpenPGP v4 key fingerprints are defined as SHA-1; this identifies a key, it does not authenticate data
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// cloudflarePin is the signing key of pkg.cloudflare.com/cloudflared, pinned in
// the build (ADR-0037). Setup installs exactly these bytes as the apt keyring
// and checks on the node that the installed file is these bytes; nothing is
// downloaded, so the node's network cannot substitute the key.
//
// Provenance (2026-10-15): fetched from https://pkg.cloudflare.com/cloudflare-main.gpg
// (2279 bytes, sha256 1bd95f4082b320d541bee351560fc2765aa9f9cd8efa4c9e32135e63f252721d); the
// primary fingerprint matched keyserver.ubuntu.com, uid "CloudFlare Software Packaging 2025
// <help@cloudflare.com>", created 2025-10-23. Cloudflare publishes no fingerprint in its docs, so
// the maintainer confirms it on the real-account checklist. When Cloudflare rotates its key, setup
// fails closed until this pin is updated:
//
//	curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o cloudflare-main.gpg   # already binary, not armored
//	gpg --show-keys --with-colons cloudflare-main.gpg | awk -F: '$1=="fpr"{print $10; exit}'
//	base64 -w0 cloudflare-main.gpg
var cloudflarePin = pinnedKey{
	fingerprint:   "CC94B39C77AE7342A68B89628A682D308D4E5E73",
	keyringBase64: "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",
}

type pinnedKey struct{ fingerprint, keyringBase64 string }

// keyring returns the pinned keyring after proving it holds exactly one
// primary key, and that key has the pinned fingerprint.
func (k pinnedKey) keyring() ([]byte, error) {
	if k.fingerprint == "" || k.keyringBase64 == "" {
		return nil, smerr.New(smerr.CodeInternal, "", "the Cloudflare package signing key is not pinned in this build")
	}
	ring, err := base64.StdEncoding.DecodeString(k.keyringBase64)
	if err != nil {
		return nil, smerr.New(smerr.CodeInternal, "", "the pinned Cloudflare keyring is not valid base64")
	}
	got, err := keyringFingerprint(ring)
	if err != nil {
		return nil, smerr.New(smerr.CodeInternal, "", "the pinned Cloudflare keyring is unusable: "+err.Error())
	}
	if !strings.EqualFold(got, strings.ReplaceAll(k.fingerprint, " ", "")) {
		return nil, smerr.New(smerr.CodeInternal, "", "the pinned Cloudflare keyring does not match its pinned fingerprint")
	}
	return ring, nil
}

const (
	pgpPublicKeyTag = 6
	pgpKeyVersion4  = 4
)

// keyringFingerprint returns the upper-case V4 fingerprint of the one primary
// key in a binary OpenPGP keyring. A keyring with no primary key, a second
// one, or a malformed packet is refused: apt trusts every key in a signed-by
// file, so a pinned file must not carry anything else.
func keyringFingerprint(ring []byte) (string, error) {
	fingerprint := ""
	for len(ring) > 0 {
		tag, body, rest, err := nextPacket(ring)
		if err != nil {
			return "", err
		}
		ring = rest
		if tag != pgpPublicKeyTag {
			continue
		}
		if fingerprint != "" {
			return "", errors.New("more than one primary key")
		}
		if len(body) == 0 || len(body) > 0xffff || body[0] != pgpKeyVersion4 {
			return "", errors.New("primary key is not a version 4 key")
		}
		h := sha1.New()                                                            //nolint:gosec // see the import
		h.Write([]byte{0x99, byte(len(body) >> 8 & 0xff), byte(len(body) & 0xff)}) // a V4 key packet is framed with a two-octet length
		h.Write(body)
		fingerprint = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	}
	if fingerprint == "" {
		return "", errors.New("no primary key")
	}
	return fingerprint, nil
}

var errMalformedPacket = errors.New("truncated or malformed OpenPGP packet")

// nextPacket splits one OpenPGP packet (RFC 9580 section 4) off ring. Partial
// and indeterminate lengths are refused: a key block uses neither.
func nextPacket(ring []byte) (tag int, body, rest []byte, err error) {
	if ring[0]&0x80 == 0 {
		return 0, nil, nil, errMalformedPacket
	}
	var length, header int
	if ring[0]&0x40 != 0 {
		tag = int(ring[0] & 0x3f)
		length, header, err = newFormatLength(ring)
	} else {
		tag = int(ring[0]>>2) & 0xf
		length, header, err = oldFormatLength(ring)
	}
	if err != nil {
		return 0, nil, nil, err
	}
	if length < 0 || length > len(ring)-header {
		return 0, nil, nil, errMalformedPacket
	}
	return tag, ring[header : header+length], ring[header+length:], nil
}

func newFormatLength(ring []byte) (length, header int, err error) {
	if len(ring) < 2 {
		return 0, 0, errMalformedPacket
	}
	switch first := int(ring[1]); {
	case first < 192:
		return first, 2, nil
	case first < 224:
		if len(ring) < 3 {
			return 0, 0, errMalformedPacket
		}
		return (first-192)<<8 + int(ring[2]) + 192, 3, nil
	case first == 255:
		if len(ring) < 6 {
			return 0, 0, errMalformedPacket
		}
		return int(ring[2])<<24 | int(ring[3])<<16 | int(ring[4])<<8 | int(ring[5]), 6, nil
	}
	return 0, 0, errors.New("partial-length OpenPGP packet")
}

func oldFormatLength(ring []byte) (length, header int, err error) {
	width := 1 << (ring[0] & 3) // 1, 2, 4 octets; 8 stands for "indeterminate"
	if width > 4 {
		return 0, 0, errors.New("indeterminate-length OpenPGP packet")
	}
	if len(ring) < 1+width {
		return 0, 0, errMalformedPacket
	}
	for _, b := range ring[1 : 1+width] {
		length = length<<8 | int(b)
	}
	return length, 1 + width, nil
}
