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
// TO BE FILLED BY THE MAINTAINER from a key whose fingerprint was checked
// out of band (Cloudflare's documentation or dashboard), never from a fetch
// whose result is trusted on sight:
//
//	curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o cloudflare-main.gpg   # already binary, not armored
//	gpg --show-keys --with-colons cloudflare-main.gpg | awk -F: '$1=="fpr"{print $10; exit}'
//	base64 -w0 cloudflare-main.gpg
//
// While either field is empty, tunnel setup fails closed before it contacts
// the node.
var cloudflarePin = pinnedKey{
	fingerprint:   "", // 40 hex digits, the primary key's V4 fingerprint
	keyringBase64: "", // the binary keyring, base64
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
