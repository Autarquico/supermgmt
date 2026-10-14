package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
)

func hostKeyFuzzSeed(f *testing.F) string {
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

func FuzzParseHostKey(f *testing.F) {
	seed := hostKeyFuzzSeed(f)
	f.Add(seed)
	f.Add(seed + seed)
	f.Add(seed[:len(seed)/2])
	f.Add("")
	f.Fuzz(func(t *testing.T, authorized string) {
		key, err := ParseHostKey(authorized)
		if err != nil {
			return
		}
		if _, isCert := key.(*cryptossh.Certificate); isCert {
			t.Fatal("accepted a certificate")
		}
		if _, err := Fingerprint(string(cryptossh.MarshalAuthorizedKey(key))); err != nil {
			t.Fatalf("accepted key has no fingerprint: %v", err)
		}
	})
}
