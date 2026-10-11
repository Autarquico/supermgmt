package auth

import (
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
)

// Minter is the app.TokenMinter backed by Mint and Hash. The app services
// cannot import this package (it imports them), so they take it as a seam.
type Minter struct{}

var _ app.TokenMinter = Minter{}

func (Minter) Mint(kind byte) (audit.Secret, string, error) { return Mint(Kind(kind)) }

// Hash parses token and returns its kind byte and storage hash.
func (Minter) Hash(token string) (byte, string, error) {
	kind, hash, err := Hash(token)
	return byte(kind), hash, err
}
