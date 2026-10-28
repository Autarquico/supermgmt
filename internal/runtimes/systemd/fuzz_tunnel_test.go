package systemd

import (
	"regexp"
	"slices"
	"testing"
)

func FuzzParseOSRelease(f *testing.F) {
	f.Add("debian trixie\n")
	f.Add("ubuntu noble")
	f.Add("debian noble\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		codename, err := parseOSRelease(out)
		if err == nil && !slices.Contains([]string{"trixie", "noble"}, codename) {
			t.Fatalf("accepted %q as %q", out, codename)
		}
	})
}

func FuzzParsePackageStatus(f *testing.F) {
	f.Add("ii  2026.10.1\n")
	f.Add("rc  2026.10.1\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		if parsePackageStatus(out) && len(out) < 2 {
			t.Fatalf("installed from %q", out)
		}
	})
}

var sha256Hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func FuzzParseSHA256(f *testing.F) {
	f.Add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -\n")
	f.Add("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855  -\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		if hash, ok := parseSHA256(out); ok && !sha256Hex64.MatchString(hash) {
			t.Fatalf("accepted %q from %q", hash, out)
		}
	})
}

var fingerprint40 = regexp.MustCompile(`^[0-9A-F]{40}$`)

func FuzzKeyringFingerprint(f *testing.F) {
	f.Add(testKeyring())
	f.Add([]byte{0xC6, 0x0A, 4, 0, 0, 0, 1, 22, 9, 0xAA, 1, 0xBB})
	f.Add([]byte{0x99, 0xFF, 0xFF})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, ring []byte) {
		if fp, err := keyringFingerprint(ring); err == nil && !fingerprint40.MatchString(fp) {
			t.Fatalf("fingerprint %q", fp)
		}
	})
}
