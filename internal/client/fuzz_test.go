package client

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

// FuzzReadFrames feeds arbitrary event-stream bytes to the SSE reader: it
// never panics, always ends in an error (a body only ends by error), and
// never delivers a frame with an empty event name.
func FuzzReadFrames(f *testing.F) {
	f.Add("event: job\ndata: {\"a\":1}\n\n")
	f.Add("data: one\ndata: two\n\n")
	f.Add(": comment\nretry: 100\nid: 7\n\nevent: closed\n\n")
	f.Add("event: job\ndata: no terminating blank line")
	f.Add("data\n\ndata:\n\n:\n\n")
	f.Add("event: x\r\ndata: y\r\n\r\n")

	f.Fuzz(func(t *testing.T, stream string) {
		err := readFrames(strings.NewReader(stream), func(fr frame) error {
			if fr.event == "" {
				t.Fatal("a frame was delivered without an event name")
			}
			return nil
		})
		if err == nil {
			t.Fatal("readFrames returned nil on a finished body")
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("unexpected error %v", err)
		}
		if errors.Is(err, bufio.ErrTooLong) && !hasFuzzOversizeLine(stream) {
			t.Fatal("a stream with no oversize line was refused as too long")
		}
	})
}

func hasFuzzOversizeLine(stream string) bool {
	for _, line := range strings.Split(stream, "\n") {
		if len(line) >= maxFrameBytes {
			return true
		}
	}
	return false
}

func TestReadFramesRefusesAnOversizeLine(t *testing.T) {
	stream := "data: " + strings.Repeat("x", maxFrameBytes+16) + "\n\n"
	err := readFrames(strings.NewReader(stream), func(frame) error {
		t.Fatal("a frame was delivered from an oversize line")
		return nil
	})
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("error = %v, want bufio.ErrTooLong", err)
	}
}
