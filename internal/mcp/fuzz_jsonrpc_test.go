package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// jsonrpcFuzzSink collects what the server writes back.
type jsonrpcFuzzSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *jsonrpcFuzzSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *jsonrpcFuzzSink) Close() error { return nil }

func (s *jsonrpcFuzzSink) frames() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Split(bytes.TrimSpace(s.buf.Bytes()), []byte("\n"))
}

const (
	jsonrpcFuzzInitialize  = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"f","version":"0"}}}`
	jsonrpcFuzzInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
)

// Raw frames from an MCP peer go straight into the SDK server, the upstream
// parsing path. Whatever arrives, the connection ends and every frame the
// server wrote is itself valid JSON.
func FuzzJSONRPCFrames(f *testing.F) {
	handshake := jsonrpcFuzzInitialize + "\n" + jsonrpcFuzzInitialized + "\n"
	for _, seed := range []string{
		handshake + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n",
		handshake + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"infra_list_nodes","arguments":{}}}` + "\n",
		handshake + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"infra_submit_plan","arguments":{"plan_id":1}}}` + "\n",
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]` + "\n",
		`{"jsonrpc":"1.0","id":null,"method":""}` + "\n",
		`{"jsonrpc":"2.0","id":{"a":1},"method":"initialize"}` + "\n",
		"{", "\x00\xff\n\n", "",
	} {
		f.Add([]byte(seed))
	}
	api := newServerFakeAPI()
	f.Fuzz(func(t *testing.T, frames []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		sink := &jsonrpcFuzzSink{}
		transport := &sdk.IOTransport{Reader: io.NopCloser(bytes.NewReader(frames)), Writer: sink}
		session, err := NewServer(api, Options{WriteTools: true, Version: "0"}).Connect(ctx, transport, nil)
		if err != nil {
			return
		}
		_ = session.Wait()
		for _, frame := range sink.frames() {
			if len(frame) > 0 && !json.Valid(frame) {
				t.Fatalf("server wrote a malformed frame: %q", frame)
			}
		}
	})
}
