package ssh

import (
	"bytes"
	"testing"
)

func TestLimitedBuffer(t *testing.T) {
	tests := map[string]struct {
		maxBytes, maxLines int
		writes             []string
		want               string
		truncated          bool
	}{
		"under both limits":         {100, 10, []string{"a\nb\n"}, "a\nb\n", false},
		"exactly the byte limit":    {4, 0, []string{"abcd"}, "abcd", false},
		"one byte over":             {4, 0, []string{"abcde"}, "abcd", true},
		"exactly the line limit":    {100, 2, []string{"a\nb\n"}, "a\nb\n", false},
		"a byte past the lines":     {100, 2, []string{"a\nb\nc"}, "a\nb\n", true},
		"lines across writes":       {100, 2, []string{"a\n", "b", "\nc\n"}, "a\nb\n", true},
		"bytes across writes":       {5, 0, []string{"abc", "def", "ghi"}, "abcde", true},
		"unlimited lines":           {100, 0, []string{"a\n\n\n\n\n"}, "a\n\n\n\n\n", false},
		"later writes stay dropped": {2, 0, []string{"abc", "d"}, "ab", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			b := newLimitedBuffer(tt.maxBytes, tt.maxLines)
			for _, w := range tt.writes {
				if n, err := b.Write([]byte(w)); n != len(w) || err != nil {
					t.Fatalf("Write(%q) = %d, %v; a writer that short-writes blocks the remote command", w, n, err)
				}
			}
			if !bytes.Equal(b.Bytes(), []byte(tt.want)) || b.truncated != tt.truncated {
				t.Errorf("got %q truncated=%v, want %q %v", b.Bytes(), b.truncated, tt.want, tt.truncated)
			}
		})
	}
}
