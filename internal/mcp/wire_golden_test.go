package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The wire goldens in testdata/wire are JSON-RPC bytes written by hand from
// the MCP specification text, not recorded from the SDK. A response matches
// when every key of the golden is present and equal, arrays have equal
// length and the string "$string" stands for any non-empty string.

const (
	wireTimeout   = 5 * time.Second
	wireOrigin    = "https://supermgmt.example"
	wireHandshake = "2025-11-25"
)

var wireAllowedVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18"}

type wireCase struct {
	Name       string            `json:"name"`
	Transports []string          `json:"transports"`
	Headers    map[string]string `json:"headers"`
	Request    json.RawMessage   `json:"request"`
	Response   any               `json:"response"`
}

func (c wireCase) runsOn(transport string) bool {
	return len(c.Transports) == 0 || slices.Contains(c.Transports, transport)
}

func (c wireCase) isInitialize() bool {
	var request struct {
		Method string `json:"method"`
	}
	return json.Unmarshal(c.Request, &request) == nil && request.Method == "initialize"
}

func loadWireCases(t *testing.T, file string) []wireCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "wire", file))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Cases []wireCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if len(golden.Cases) == 0 {
		t.Fatalf("%s has no cases", file)
	}
	return golden.Cases
}

// wireMismatches lists where got departs from the golden want.
func wireMismatches(path string, want, got any) []string {
	switch want := want.(type) {
	case map[string]any:
		gotMap, ok := got.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: want an object, got %v", path, got)}
		}
		var out []string
		for key, wantValue := range want {
			if strings.HasPrefix(key, "_comment") {
				continue
			}
			gotValue, present := gotMap[key]
			if !present {
				out = append(out, fmt.Sprintf("%s.%s: missing", path, key))
				continue
			}
			out = append(out, wireMismatches(path+"."+key, wantValue, gotValue)...)
		}
		return out
	case []any:
		gotList, ok := got.([]any)
		if !ok || len(gotList) != len(want) {
			return []string{fmt.Sprintf("%s: want %d elements, got %v", path, len(want), got)}
		}
		var out []string
		for i := range want {
			out = append(out, wireMismatches(fmt.Sprintf("%s[%d]", path, i), want[i], gotList[i])...)
		}
		return out
	case string:
		if gotString, ok := got.(string); want == "$string" && ok && gotString != "" || got == want {
			return nil
		}
	default:
		if got == want {
			return nil
		}
	}
	return []string{fmt.Sprintf("%s: want %v, got %v", path, want, got)}
}

func wireServer() *sdk.Server {
	return NewServer(readTestAPI(), Options{Version: "0.0.0-wire"})
}

func wireHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := wireServer()
	handler := NewHTTPHandler(
		func(*http.Request) *sdk.Server { return server },
		HTTPOptions{AllowedOrigin: wireOrigin, ProtocolVersions: wireAllowedVersions},
	)
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)
	return httpServer
}

// wirePost sends raw bytes the way a streamable HTTP client does.
func wirePost(t *testing.T, url string, headers map[string]string, body string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, payload
}

func wireDecode(t *testing.T, payload []byte) any {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, payload)
	}
	return decoded
}

func wireExpect(t *testing.T, c wireCase, got any) {
	t.Helper()
	for _, mismatch := range wireMismatches("$", c.Response, got) {
		t.Errorf("%s: %s", c.Name, mismatch)
	}
}

// wireStdio is a raw newline-delimited JSON-RPC peer of a server running on
// pipes, as `sm mcp` runs on stdin/stdout.
type wireStdio struct {
	t     *testing.T
	in    io.Writer
	lines chan string
}

func startWireStdio(t *testing.T) *wireStdio {
	t.Helper()
	serverIn, clientOut := io.Pipe()
	clientIn, serverOut := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = wireServer().Run(ctx, &sdk.IOTransport{Reader: serverIn, Writer: serverOut})
	}()
	peer := &wireStdio{t: t, in: clientOut, lines: make(chan string, 16)}
	go func() {
		scanner := bufio.NewScanner(clientIn)
		scanner.Buffer(nil, 1<<20)
		for scanner.Scan() {
			peer.lines <- scanner.Text()
		}
		close(peer.lines)
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientOut.Close()
		_ = clientIn.Close()
		<-done
	})
	return peer
}

func (p *wireStdio) send(message string) {
	p.t.Helper()
	if _, err := io.WriteString(p.in, message+"\n"); err != nil {
		p.t.Fatal(err)
	}
}

func (p *wireStdio) receive() []byte {
	p.t.Helper()
	select {
	case line, open := <-p.lines:
		if !open {
			p.t.Fatal("server closed the pipe")
		}
		return []byte(line)
	case <-time.After(wireTimeout):
		p.t.Fatal("no response from the server")
	}
	return nil
}

func (p *wireStdio) handshake(version string) {
	p.t.Helper()
	p.send(`{"jsonrpc":"2.0","id":"handshake","method":"initialize","params":{"protocolVersion":"` + version +
		`","capabilities":{},"clientInfo":{"name":"raw-wire-client","version":"1"}}}`)
	p.receive()
	p.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

var wireFiles = []string{"initialize.golden.json", "tools_list.golden.json", "tools_call.golden.json"}

func TestWire_GoldensOverStdio(t *testing.T) {
	for _, file := range wireFiles {
		for _, c := range loadWireCases(t, file) {
			if !c.runsOn("stdio") {
				continue
			}
			t.Run(c.Name, func(t *testing.T) {
				peer := startWireStdio(t)
				if !c.isInitialize() {
					version := c.Headers[protocolVersionHeader]
					if version == "" {
						version = wireHandshake
					}
					peer.handshake(version)
				}
				peer.send(string(c.Request))
				wireExpect(t, c, wireDecode(t, peer.receive()))
			})
		}
	}
}

func TestWire_GoldensOverHTTP(t *testing.T) {
	httpServer := wireHTTPServer(t)
	for _, file := range wireFiles {
		for _, c := range loadWireCases(t, file) {
			if !c.runsOn("http") {
				continue
			}
			t.Run(c.Name, func(t *testing.T) {
				response, payload := wirePost(t, httpServer.URL, c.Headers, string(c.Request))
				if response.StatusCode != http.StatusOK {
					t.Fatalf("status = %d: %s", response.StatusCode, payload)
				}
				if got := response.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
					t.Errorf("Content-Type = %q, want application/json", got)
				}
				wireExpect(t, c, wireDecode(t, payload))
			})
		}
	}
}

func TestWire_MatcherPinsTheGoldenRules(t *testing.T) {
	tests := []struct {
		name      string
		want, got string
		mismatch  bool
	}{
		{"extra keys in the response are fine", `{"a":1}`, `{"a":1,"b":2}`, false},
		{"missing key", `{"a":1}`, `{"b":2}`, true},
		{"different value", `{"a":1}`, `{"a":2}`, true},
		{"array length matters", `{"a":[1]}`, `{"a":[1,2]}`, true},
		{"$string matches a non-empty string", `{"a":"$string"}`, `{"a":"x"}`, false},
		{"$string refuses an empty string", `{"a":"$string"}`, `{"a":""}`, true},
		{"$string refuses a number", `{"a":"$string"}`, `{"a":1}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want, got any
			if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.got), &got); err != nil {
				t.Fatal(err)
			}
			if mismatch := len(wireMismatches("$", want, got)) > 0; mismatch != tt.mismatch {
				t.Errorf("mismatch = %v, want %v", mismatch, tt.mismatch)
			}
		})
	}
}
