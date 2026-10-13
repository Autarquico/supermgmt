package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
)

func pinnedFuzzSeed(f *testing.F) string {
	f.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	key, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		f.Fatal(err)
	}
	return string(cryptossh.MarshalAuthorizedKey(key))
}

// FuzzParsePinned: an accepted pin is exactly one non-certificate key.
func FuzzParsePinned(f *testing.F) {
	seed := pinnedFuzzSeed(f)
	f.Add(seed)
	f.Add(seed + seed)
	f.Add(seed[:len(seed)/2])
	f.Add("")
	f.Add("ssh-rsa AAAA comment")
	f.Fuzz(func(t *testing.T, authorized string) {
		p, err := parsePinned(authorized)
		if err != nil {
			return
		}
		if p.key == nil {
			t.Fatal("accepted pin without a key")
		}
		if _, isCert := p.key.(*cryptossh.Certificate); isCert {
			t.Fatal("accepted a certificate")
		}
		if len(p.algorithms()) == 0 {
			t.Fatal("accepted key negotiates no algorithm")
		}
	})
}
