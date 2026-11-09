package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// The palette follows the global design system: cold neutrals, one accent, and
// the semantic colors emerald, amber, rose and sky. Meaning never depends on
// color alone: every state also has a glyph or a word.
type theme struct {
	title, dim, accent, selected lipgloss.Style
	ok, warn, bad, info          lipgloss.Style
}

func newTheme() theme {
	fg := func(hex string) lipgloss.Style { return lipgloss.NewStyle().Foreground(lipgloss.Color(hex)) }
	return theme{
		title:    lipgloss.NewStyle().Bold(true),
		dim:      fg("#64748b"),
		accent:   fg("#0ea5e9"),
		selected: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0ea5e9")),
		ok:       fg("#10b981"),
		warn:     fg("#f59e0b"),
		bad:      fg("#f43f5e"),
		info:     fg("#0ea5e9"),
	}
}

// clip shortens plain text to w cells, marking the cut with an ellipsis.
// It must run before styling: it does not understand escape sequences.
func clip(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	runes := []rune(s)
	for len(runes) > 0 && lipgloss.Width(string(runes))+1 > w {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}

// wrap breaks plain text into lines of at most w cells at spaces, indenting
// continuations by indent. A word wider than a line is split by cells: no text
// is dropped. Like clip, it must run before styling.
func wrap(s string, w int, indent string) []string {
	if w <= len(indent)+1 || lipgloss.Width(s) <= w {
		return []string{s}
	}
	var lines []string
	line, prefix := "", ""
	flush := func() {
		lines = append(lines, line)
		line, prefix = "", indent
	}
	for _, word := range strings.Fields(s) {
		if line != "" && lipgloss.Width(line+" "+word) > w {
			flush()
		}
		if lipgloss.Width(prefix+word) > w && lipgloss.Width(word) <= w {
			// Whole beats indented: a key that fits only unindented stays in one piece.
			line, prefix = word, ""
			flush()
			continue
		}
		if lipgloss.Width(prefix+word) > w {
			var rows []string
			rows, word = splitWord(word, prefix, indent, w)
			for _, row := range rows {
				line = row
				flush()
			}
		}
		switch {
		case word == "":
		case line == "":
			line = prefix + word
		default:
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// splitWord cuts a word wider than a line into rows of at most w cells, the
// first behind prefix and the rest behind indent, and returns what is left
// once it fits. It walks the word once, so its cost is linear in the word.
func splitWord(word, prefix, indent string, w int) (rows []string, rest string) {
	runes := []rune(word)
	for {
		room := w - lipgloss.Width(prefix)
		n, used := 0, 0
		for n < len(runes) {
			cells := lipgloss.Width(string(runes[n]))
			if n > 0 && used+cells > room {
				break
			}
			used += cells
			n++
		}
		if n == len(runes) && used <= room {
			return rows, string(runes)
		}
		rows = append(rows, prefix+string(runes[:n]))
		runes, prefix = runes[n:], indent
		if len(runes) == 0 {
			return rows, ""
		}
	}
}

// padTo right-pads s with spaces to w cells; longer text is left as is.
func padTo(s string, w int) string {
	if gap := w - lipgloss.Width(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s
}

// cell clips and pads plain text to exactly w cells.
func cell(s string, w int) string { return padTo(clip(s, w), w) }

// fitLines makes lines exactly h rows of exactly w cells. Callers clip plain
// text before styling; the escape-aware cut here is only a safety net.
func fitLines(lines []string, w, h int) []string {
	out := make([]string, h)
	for i := range out {
		if i < len(lines) {
			out[i] = padTo(cutStyled(lines[i], w), w)
		} else {
			out[i] = strings.Repeat(" ", w)
		}
	}
	return out
}

// sideBySide joins two panes with a vertical hairline.
func sideBySide(left, right []string, leftW, rightW, h int) []string {
	l, r := fitLines(left, leftW, h), fitLines(right, rightW, h)
	out := make([]string, h)
	for i := range out {
		out[i] = l[i] + "│" + r[i]
	}
	return out
}

// cutStyled truncates a possibly styled line to w cells.
func cutStyled(line string, w int) string {
	if lipgloss.Width(line) <= w {
		return line
	}
	return lipgloss.NewStyle().MaxWidth(w).Render(line)
}
