package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The token file is read by an unattended bridge: whatever it holds, the
// result is one whitespace-free word or a usage error, never a partial token.
func FuzzReadTokenFile(f *testing.F) {
	for _, seed := range []string{"smm_abc\n", "", " \n", "smm_a smm_b", "\xff\xfe", "tok\x00en", strings.Repeat("a", maxTokenFileBytes+10)} {
		f.Add([]byte(seed))
	}
	path := filepath.Join(f.TempDir(), "token")
	f.Fuzz(func(t *testing.T, content []byte) {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		token, err := readTokenFile(path, os.Geteuid())
		if err != nil {
			if token != "" {
				t.Fatalf("token %q returned with error %v", string(token), err)
			}
			return
		}
		if text := string(token); text == "" || strings.ContainsAny(text, " \t\r\n") || len(text) > maxTokenFileBytes {
			t.Fatalf("accepted token %q", text)
		}
	})
}
