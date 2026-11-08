package tui

import (
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
)

func TestWrapOfAVeryLongWordIsFastAndLosesNothing(t *testing.T) {
	word := strings.Repeat("abcdefgh", 25_000) // 200k runes
	for _, text := range []string{word, "x " + word + " y", strings.Repeat("世", 50_000)} {
		done := make(chan []string, 1)
		go func() { done <- wrap(text, 80, "   ") }()
		var lines []string
		select {
		case lines = <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("wrap of a very long word did not finish")
		}
		for _, line := range lines {
			if width := lipgloss.Width(line); width > 80 {
				t.Fatalf("line of %d cells", width)
			}
		}
		if got, want := strings.ReplaceAll(strings.Join(lines, ""), " ", ""), strings.ReplaceAll(text, " ", ""); got != want {
			t.Fatal("wrap dropped text")
		}
	}
}
