package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	httpListBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

	httpMetaVersion = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":` +
		`{"io.modelcontextprotocol/protocolVersion":"2025-03-26"}}}`

	httpInitializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
)

func TestHTTP_UnsupportedProtocolVersionIsRefused(t *testing.T) {
	server := wireHTTPServer(t)
	tests := []struct {
		name    string
		headers map[string]string
		body    string
	}{
		{"header", map[string]string{protocolVersionHeader: "2025-03-26"}, httpListBody},
		{"unknown header", map[string]string{protocolVersionHeader: "1999-01-01"}, httpListBody},
		{"initialize proposal", nil, httpInitializeBody},
		{"per-request version", nil, httpMetaVersion},
		{"batched initialize", nil, "[" + httpInitializeBody + "]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, payload := wirePost(t, server.URL, tt.headers, tt.body)
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.StatusCode, payload)
			}
			if !strings.Contains(string(payload), "2025-11-25") {
				t.Errorf("body does not list the supported versions: %s", payload)
			}
		})
	}
}

func TestHTTP_OriginMustMatchTheConfiguredOne(t *testing.T) {
	server := wireHTTPServer(t)
	headers := func(origin string) map[string]string {
		return map[string]string{protocolVersionHeader: wireHandshake, "Origin": origin}
	}
	tests := []struct {
		name   string
		origin string
		want   int
	}{
		{"same origin", wireOrigin, http.StatusOK},
		{"other host", "https://evil.example", http.StatusForbidden},
		{"other scheme", "http://supermgmt.example", http.StatusForbidden},
		{"other port", "https://supermgmt.example:8443", http.StatusForbidden},
		{"trailing slash", wireOrigin + "/", http.StatusForbidden},
		{"opaque origin", "null", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, payload := wirePost(t, server.URL, headers(tt.origin), httpListBody)
			if response.StatusCode != tt.want {
				t.Errorf("status = %d, want %d: %s", response.StatusCode, tt.want, payload)
			}
		})
	}
}

func TestHTTP_RequestWithoutOriginIsServed(t *testing.T) {
	server := wireHTTPServer(t)

	response, payload := wirePost(t, server.URL, map[string]string{protocolVersionHeader: wireHandshake}, httpListBody)

	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200: %s", response.StatusCode, payload)
	}
}

func TestHTTP_EmptyAllowedOriginRefusesAnyOrigin(t *testing.T) {
	handler := NewHTTPHandler(
		func(*http.Request) *sdk.Server { return wireServer() },
		HTTPOptions{ProtocolVersions: wireAllowedVersions},
	)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	response, _ := wirePost(t, server.URL, map[string]string{"Origin": wireOrigin}, httpListBody)

	if response.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403: any Origin mismatches an empty AllowedOrigin", response.StatusCode)
	}
}

func TestHTTP_StatelessServerRefusesGetAndDelete(t *testing.T) {
	server := wireHTTPServer(t)
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			request, err := http.NewRequestWithContext(t.Context(), method, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Accept", "application/json, text/event-stream")
			request.Header.Set(protocolVersionHeader, wireHandshake)

			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()

			if response.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405", response.StatusCode)
			}
			if allow := response.Header.Get("Allow"); allow != http.MethodPost {
				t.Errorf("Allow = %q, want POST", allow)
			}
		})
	}
}

func TestHTTP_NoSessionIsIssued(t *testing.T) {
	server := wireHTTPServer(t)

	response, _ := wirePost(t, server.URL, nil, strings.Replace(httpInitializeBody, "2025-03-26", wireHandshake, 1))

	if id := response.Header.Get("Mcp-Session-Id"); id != "" {
		t.Errorf("Mcp-Session-Id = %q, a stateless server issues none", id)
	}
}

func TestHTTP_OversizedBodyIsRefused(t *testing.T) {
	server := wireHTTPServer(t)
	huge := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("a", 5<<20) + `"}}`

	response, _ := wirePost(t, server.URL, map[string]string{protocolVersionHeader: wireHandshake}, huge)

	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", response.StatusCode)
	}
}

func TestHTTP_ProtectedResourceMetadataDocument(t *testing.T) {
	handler := ProtectedResourceMetadata("https://sm.example/mcp", "https://idp.example", []string{"mcp:use"})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var document struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		ScopesSupported        []string `json:"scopes_supported"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Resource != "https://sm.example/mcp" {
		t.Errorf("resource = %q", document.Resource)
	}
	if len(document.AuthorizationServers) != 1 || document.AuthorizationServers[0] != "https://idp.example" {
		t.Errorf("authorization_servers = %v", document.AuthorizationServers)
	}
	if len(document.ScopesSupported) != 1 || document.ScopesSupported[0] != "mcp:use" {
		t.Errorf("scopes_supported = %v", document.ScopesSupported)
	}
	if len(document.BearerMethodsSupported) != 1 || document.BearerMethodsSupported[0] != "header" {
		t.Errorf("bearer_methods_supported = %v, tokens travel in the Authorization header only", document.BearerMethodsSupported)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestHTTP_ProtectedResourceMetadataIsReadOnly(t *testing.T) {
	handler := ProtectedResourceMetadata("https://sm.example/mcp", "https://idp.example", nil)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/.well-known/oauth-protected-resource", nil))

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", recorder.Code)
	}
}
