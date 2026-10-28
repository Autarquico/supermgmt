package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
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

// FuzzParseAccessToken: an accepted token has both halves and no byte that
// could break the child's environment.
func FuzzParseAccessToken(f *testing.F) {
	for _, seed := range []string{"abc.access:s3cr3t", "  id:secret\n", ":secret", "id:", "id", "id:sec\x00ret", "a:b:c"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, stored string) {
		tok, err := ParseAccessToken(stored)
		if err != nil {
			return
		}
		secret := tok.ClientSecret.Reveal()
		if tok.ClientID == "" || secret == "" || strings.Contains(tok.ClientID, ":") {
			t.Fatalf("ParseAccessToken(%q) = %q / %q", stored, tok.ClientID, secret)
		}
		if strings.ContainsFunc(tok.ClientID+secret, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
			t.Fatalf("ParseAccessToken(%q) kept a control or space character", stored)
		}
	})
}

// FuzzSanitizeDiagnostic: the secret never survives, and the result is one
// printable, bounded line.
func FuzzSanitizeDiagnostic(f *testing.F) {
	f.Add("error: bad token s3cr3t-value\nretry", "s3cr3t-value")
	f.Add("Authorization: Bearer abc\x1b[31m", "abc")
	f.Add(strings.Repeat("x", 4096), "x")
	f.Fuzz(func(t *testing.T, text, secret string) {
		got := sanitizeDiagnostic(text, secret)
		// Secrets reaching here passed ParseAccessToken: no space or control
		// character, which the line folding could otherwise reassemble.
		printable := !strings.ContainsFunc(secret, func(r rune) bool { return r < 0x21 || r == 0x7f })
		if printable && len(secret) >= 8 && strings.Contains(got, secret) {
			t.Fatalf("secret %q survived in %q", secret, got)
		}
		if strings.ContainsFunc(got, func(r rune) bool { return r == '\n' || r == '\r' || r < 0x20 }) {
			t.Fatalf("control character in %q", got)
		}
		if n := len([]rune(got)); n > diagnosticRunes+3 {
			t.Fatalf("length %d over the bound", n)
		}
	})
}
