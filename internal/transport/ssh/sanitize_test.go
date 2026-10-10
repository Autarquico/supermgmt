package ssh

import (
	"testing"
	"unicode/utf8"
)

func TestSanitize(t *testing.T) {
	tests := map[string]struct{ in, want string }{
		"plain text kept":            {"hello world\n", "hello world\n"},
		"tab and newline kept":       {"a\tb\nc", "a\tb\nc"},
		"carriage return dropped":    {"a\r\nb\rc", "a\nbc"},
		"SGR colors":                 {"\x1b[1;31mred\x1b[0m", "red"},
		"CSI cursor and erase":       {"a\x1b[2J\x1b[Hb\x1b[10;20Hc", "abc"},
		"private CSI":                {"a\x1b[?25lb\x1b[?1049hc", "abc"},
		"OSC title with BEL":         {"a\x1b]0;evil title\x07b", "ab"},
		"OSC hyperlink with ST":      {"\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\", "link"},
		"DCS string":                 {"a\x1bPq#0;2;0;0;0\x1b\\b", "ab"},
		"APC string":                 {"a\x1b_payload\x1b\\b", "ab"},
		"two-byte escapes":           {"a\x1bc\x1b7\x1b=b", "ab"},
		"charset designation":        {"a\x1b(0b", "ab"},
		"unterminated OSC":           {"keep\x1b]0;never ends", "keep"},
		"unterminated CSI":           {"keep\x1b[12", "keep"},
		"lone ESC at end":            {"keep\x1b", "keep"},
		"8-bit CSI":                  {"a\u009b31mb", "ab"},
		"8-bit OSC":                  {"a\u009d0;title\u009cb", "ab"},
		"other C1 controls":          {"a\u0085b\u0080c", "abc"},
		"C0 controls":                {"a\x00b\x01c\x07d\x08e\x0bf\x0cg\x7fh", "abcdefgh"},
		"invalid UTF-8 repaired":     {"ok\xffend", "ok�end"},
		"truncated multibyte repair": {"caf\xc3", "caf�"},
		"valid unicode kept":         {"ünïcødé 日本語 🚀", "ünïcødé 日本語 🚀"},
		"escape cannot hide text":    {"\x1b[31m\x1b[0mprompt$ ", "prompt$ "},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Sanitize([]byte(tt.in)); got != tt.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func FuzzSanitize(f *testing.F) {
	for _, seed := range []string{
		"", "plain", "\x1b[31mred\x1b[0m", "\x1b]0;t\x07", "\x1b]8;;u\x1b\\x", "\u009b31m", "\xff\xfe", "\x1b", "\x1bP\x1b\\",
		"a\x1b[", "\x1b[\x1b[\x1b[", "\x00\x01\x02", "\u009d\u009c",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out := Sanitize(in)
		if !utf8.ValidString(out) {
			t.Fatalf("output is not valid UTF-8: %q", out)
		}
		for _, r := range out {
			if r == 0x1b || r == 0x7f || (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("control character %U survived in %q", r, out)
			}
		}
		if again := Sanitize([]byte(out)); again != out {
			t.Fatalf("not idempotent: %q then %q", out, again)
		}
	})
}
