package textsafe

import (
	"strings"
)

const (
	esc = 0x1b
	bel = 0x07
)

// Sanitize makes untrusted remote output safe to parse and display (spec §30):
// invalid UTF-8 becomes U+FFFD, ANSI/VT escape sequences (7-bit and 8-bit C1
// forms) are removed whole, and every remaining control character is dropped
// except newline and tab. Carriage returns are dropped, so "\r\n" becomes "\n".
func Sanitize(b []byte) string {
	text := []rune(strings.ToValidUTF8(string(b), "�"))
	var out strings.Builder
	out.Grow(len(b))
	for i := 0; i < len(text); {
		r := text[i]
		switch {
		case r == esc:
			i = skipEscape(text, i)
		case isC1Introducer(r):
			i = skipC1Sequence(text, i)
		case r == '\n' || r == '\t':
			out.WriteRune(r)
			i++
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			i++
		default:
			out.WriteRune(r)
			i++
		}
	}
	return out.String()
}

// isC1Introducer: CSI, OSC, DCS, SOS, PM and APC in their one-rune C1 form.
func isC1Introducer(r rune) bool {
	switch r {
	case 0x9b, 0x9d, 0x90, 0x98, 0x9e, 0x9f:
		return true
	}
	return false
}

// skipEscape returns the index after the sequence that starts with ESC at i.
func skipEscape(text []rune, i int) int {
	if i+1 >= len(text) {
		return i + 1
	}
	switch text[i+1] {
	case '[':
		return skipCSI(text, i+2)
	case ']', 'P', 'X', '^', '_':
		return skipString(text, i+2)
	}
	// ESC, optional intermediates (0x20-0x2f), one final byte (0x30-0x7e).
	j := i + 1
	for j < len(text) && text[j] >= 0x20 && text[j] <= 0x2f {
		j++
	}
	if j < len(text) && text[j] >= 0x30 && text[j] <= 0x7e {
		j++
	}
	return j
}

func skipC1Sequence(text []rune, i int) int {
	if text[i] == 0x9b {
		return skipCSI(text, i+1)
	}
	return skipString(text, i+1)
}

// skipCSI consumes parameters (0x30-0x3f), intermediates (0x20-0x2f) and the
// final byte (0x40-0x7e). A malformed sequence ends at the first other rune.
func skipCSI(text []rune, j int) int {
	for j < len(text) && text[j] >= 0x20 && text[j] <= 0x3f {
		j++
	}
	if j < len(text) && text[j] >= 0x40 && text[j] <= 0x7e {
		j++
	}
	return j
}

// skipString consumes a control string (OSC, DCS, ...) up to and including its
// terminator: BEL, ST (ESC \ or U+009C). An unterminated string runs to the end.
func skipString(text []rune, j int) int {
	for j < len(text) {
		switch {
		case text[j] == bel || text[j] == 0x9c:
			return j + 1
		case text[j] == esc && j+1 < len(text) && text[j+1] == '\\':
			return j + 2
		}
		j++
	}
	return j
}

// Line sanitizes a single-line field: like Sanitize, and newlines are dropped too.
func Line(s string) string {
	return strings.ReplaceAll(Sanitize([]byte(s)), "\n", "")
}
