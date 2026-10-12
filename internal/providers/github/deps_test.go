package github

// The virtual Sigstore that signs test attestations (T6b; ADR-0028). Imported
// here so go.mod already lists everything it needs; it never reaches a
// production build.
import _ "github.com/sigstore/sigstore-go/pkg/testing/ca"
