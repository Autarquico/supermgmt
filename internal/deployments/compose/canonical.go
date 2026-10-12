package compose

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// canonicalYAML serializes the tree as the public model of spec §20.3 step 9:
// mapping keys sorted at every level, sequences in source order, no anchors.
func canonicalYAML(root *node) ([]byte, error) {
	return encode(canonicalCopy(root))
}

// canonicalHash is the plan content hash of a document: sha256:<hex>.
func canonicalHash(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalCopy(n *node) *node {
	out := *n
	out.items = nil
	for _, item := range n.items {
		out.items = append(out.items, canonicalCopy(item))
	}
	out.entries = nil
	for _, e := range canonicalEntries(n) {
		e.val = canonicalCopy(e.val)
		out.entries = append(out.entries, e)
	}
	return &out
}

func canonicalEntries(n *node) []entry {
	entries := slices.Clone(n.entries)
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.key, b.key) })
	return entries
}
