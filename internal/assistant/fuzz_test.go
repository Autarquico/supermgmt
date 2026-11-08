package assistant

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

func FuzzStreamParser(f *testing.F) {
	for _, name := range []string{"tool-call.jsonl", "approval-required.jsonl", "not-signed-in-no-mcp.jsonl"} {
		raw, err := os.ReadFile(filepath.Join(fixtureDir, name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte("{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"\\u001b[2J\"}]}}\n"))
	f.Add([]byte("not json\n"))
	f.Fuzz(func(t *testing.T, stream []byte) {
		r := bufio.NewReader(bytes.NewReader(stream))
		p := newParser(AuthSubscription)
		for {
			line, err := readLine(r)
			if errors.Is(err, io.EOF) || err != nil {
				return
			}
			events, err := p.parse(line)
			if err != nil {
				return
			}
			for _, e := range events {
				if strings.IndexFunc(e.Text, unsafeRune) >= 0 {
					t.Fatalf("event text %q holds a control character", e.Text)
				}
				if e.Kind == KindApproval && (e.Approval == nil || e.Approval.JobID == "") {
					t.Fatalf("approval event without a job: %+v", e)
				}
			}
		}
	})
}

func unsafeRune(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }
