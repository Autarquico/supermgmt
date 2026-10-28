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

// FuzzCloudflareProxyCommand: an accepted ProxyCommand is the quoted absolute
// path, the fixed subcommand and a DNS hostname, with every % doubled; nothing
// else can reach the shell OpenSSH runs it through.
func FuzzCloudflareProxyCommand(f *testing.F) {
	f.Add("/usr/local/bin/cloudflared", "ssh-web1.example.com")
	f.Add("/opt/my dir/cloudflared", "ssh-web1.example.com")
	f.Add("/usr/bin/cloud'flared", "x.example.com")
	f.Add("/usr/bin/cloudflared", "%h.example.com")
	f.Add("relative/cloudflared", "a;b.example.com")
	f.Fuzz(func(t *testing.T, path, hostname string) {
		cmd, err := cloudflareProxyCommand(path, hostname)
		if err != nil {
			return
		}
		want := strings.ReplaceAll("'"+path+"' access ssh --hostname "+hostname, "%", "%%")
		if cmd != want || strings.Count(path, "'") != 0 {
			t.Fatalf("cloudflareProxyCommand(%q, %q) = %q", path, hostname, cmd)
		}
		if strings.ContainsAny(hostname, " ;|&$`'\"\\()<>%\n") {
			t.Fatalf("hostname %q with shell or token syntax was accepted", hostname)
		}
	})
}
