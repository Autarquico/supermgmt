package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const hashPrefix = "sha256:"

// Canonical returns the RFC 8785 serialization of the normalized plan: the
// exact bytes that are hashed.
func Canonical(p *Plan) ([]byte, error) {
	normalized, err := normalize(p)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("encode plan: %w", err)
	}
	return canonicalizeJSON(raw)
}

// Hash returns "sha256:" + hex(SHA-256(Canonical(p))), the value approvals bind to.
func Hash(p *Plan) (string, error) {
	canonical, err := Canonical(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hashPrefix + hex.EncodeToString(sum[:]), nil
}
