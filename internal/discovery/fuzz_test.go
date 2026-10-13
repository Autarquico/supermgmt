package discovery

import (
	"strings"
	"testing"
)

// FuzzParseProbe: probe output comes from a node and is untrusted. Parse never
// panics, and an accepted output yields only data bounded by its input.
func FuzzParseProbe(f *testing.F) {
	f.Add([]byte(linuxProbe))
	f.Add([]byte("@@probe 1\n"))
	f.Add([]byte("@@probe 1\n@@uname\nLinux\r\n@@hostname\n"))
	f.Add([]byte("@@probe 2\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, output []byte) {
		s, err := Parse(output)
		if err != nil {
			return
		}
		if len(s.Kernel) > len(output) || len(s.Hostname) > len(output) {
			t.Fatalf("parsed text longer than the %d-byte input", len(output))
		}
		if lines := strings.Count(string(output), "\n") + 1; len(s.Addresses) > lines {
			t.Fatalf("%d addresses from %d lines", len(s.Addresses), lines)
		}
	})
}
