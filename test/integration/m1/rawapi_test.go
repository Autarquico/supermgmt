package m1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// rawResponse is one HTTP answer as it came off the socket.
type rawResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// errorBody decodes an error envelope.
func (r rawResponse) errorBody(t *testing.T) wire.Error {
	t.Helper()
	var env wire.ErrorEnvelope
	if err := json.Unmarshal(r.Body, &env); err != nil {
		t.Fatalf("status %d body %q is not an error envelope: %v", r.Status, r.Body, err)
	}
	return env.Error
}

func (in *instance) httpClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", in.socket)
			},
		},
	}
}

func (in *instance) newRequest(t *testing.T, method, path string, headers map[string]string, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, "http://supermgmt"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", wire.ContentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// raw sends one request exactly as written, with no client-side help.
func (in *instance) raw(t *testing.T, method, path string, headers map[string]string, body string) rawResponse {
	t.Helper()
	resp, err := in.httpClient().Do(in.newRequest(t, method, path, headers, body))
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", method, path, err)
	}
	return rawResponse{Status: resp.StatusCode, Header: resp.Header, Body: data}
}

// sendWithoutReading writes a request and keeps the connection open without
// ever reading the answer, as a client that loses its response. The connection
// is closed with the test.
func (in *instance) sendWithoutReading(t *testing.T, method, path string, headers map[string]string, body string) {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", in.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var buf bytes.Buffer
	if err := in.newRequest(t, method, path, headers, body).Write(&buf); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func requireCode(t *testing.T, r rawResponse, status int, code smerr.Code) wire.Error {
	t.Helper()
	got := r.errorBody(t)
	if r.Status != status || got.Code != code {
		t.Fatalf("status %d code %s (%s), want %d %s", r.Status, got.Code, got.Message, status, code)
	}
	return got
}
