package app

import (
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// FuzzAppLogCursor feeds the cursor a client hands back and the lines a node wrote through the follow
// machinery: a cursor decodes within its bounds or is invalid, and no line of output ever carries the marker
// the redaction uses to tell lines apart.
func FuzzAppLogCursor(f *testing.F) {
	f.Add(logCursor{Since: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC), Skip: 3}.encode(), "a\nb password=x\nc")
	f.Add("e30", "")
	f.Add("!!!", "-----BEGIN RSA PRIVATE KEY-----\nbody")
	f.Add("eyJzIjoiMjAyNi0xMS0wOVQxMDowMDowMFoiLCJrIjotMX0", "\x00")
	f.Fuzz(func(t *testing.T, cursor, text string) {
		if c, err := decodeLogCursor(cursor); err != nil {
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Fatalf("error %v is not invalid_argument", err)
			}
		} else if c.Skip < 0 || c.Skip > 10000 || c.Since.IsZero() {
			t.Fatalf("cursor %q decoded out of bounds: %+v", cursor, c)
		}
		lines := strings.Split(strings.ReplaceAll(text, "\x00", ""), "\n")
		for _, l := range scrubLines(lines) {
			if strings.Contains(l.text, "\x00") || l.raw < 0 || l.raw >= len(lines) {
				t.Fatalf("scrubLines(%q) produced %+v", lines, l)
			}
		}
	})
}
