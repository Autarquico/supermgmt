//go:build e2e

package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
)

// Typed returns the repository's own HTTPS client for this server, signed with token.
func (s *Server) Typed(token string) *client.Client {
	s.t.Helper()
	c, err := client.NewRemote(client.Remote{URL: s.URL, CAFile: s.CAFile, Token: token}, client.Options{})
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}

// Raw sends one JSON request over HTTPS as a person would with curl: no repository client in
// between. out may be nil; the envelope's data is decoded into it. The status code is returned
// with the error body (if any) as the error.
func (s *Server) Raw(ctx context.Context, token, method, path string, in, out any) (int, error) {
	s.t.Helper()
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.URL+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", wire.ContentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: s.CA.Pool(), MinVersion: tls.VersionTLS12},
	}}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	if out != nil {
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return resp.StatusCode, fmt.Errorf("decode envelope: %w: %s", err, raw)
		}
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode data: %w: %s", err, raw)
		}
	}
	return resp.StatusCode, nil
}

// Bootstrap exchanges a one-time code for the first administrator of a server without OIDC and
// returns the API token. It posts the display name that `sm login --bootstrap` does not send
// (BUG-2).
func (s *Server) Bootstrap(ctx context.Context, code, displayName string) string {
	s.t.Helper()
	var out wire.Bootstrapped
	if _, err := s.Raw(ctx, "", http.MethodPost, wire.PathBootstrap, wire.BootstrapRequest{Code: code, DisplayName: displayName}, &out); err != nil {
		s.t.Fatalf("bootstrap exchange: %v", err)
	}
	switch {
	case out.APIToken != nil:
		return out.APIToken.Value
	case out.Session != nil:
		return out.Session.Token
	}
	s.t.Fatal("bootstrap issued no credential")
	return ""
}
