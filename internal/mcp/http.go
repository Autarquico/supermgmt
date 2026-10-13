package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const protocolVersionHeader = "MCP-Protocol-Version"

var errBodyTooLarge = errors.New("request body too large")

// NewHTTPHandler serves MCP over streamable HTTP, stateless and with JSON
// responses (ADR-0031): no session survives a request, GET and DELETE are 405.
// On top of the SDK handler it refuses a request whose Origin is not
// o.AllowedOrigin (DNS rebinding, 403) and one that names a protocol version
// outside o.ProtocolVersions (400), in the MCP-Protocol-Version header, in an
// initialize request or in a per-request protocol version.
func NewHTTPHandler(server func(*http.Request) *sdk.Server, o HTTPOptions) http.Handler {
	inner := sdk.NewStreamableHTTPHandler(server, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && origin != o.AllowedOrigin {
			http.Error(w, "Forbidden: origin not allowed", http.StatusForbidden)
			return
		}
		if err := requireAllowedVersions(w, r, o.ProtocolVersions); err != nil {
			http.Error(w, err.Error(), versionErrorStatus(err))
			return
		}
		inner.ServeHTTP(w, r)
	})
}

func versionErrorStatus(err error) int {
	if errors.Is(err, errBodyTooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// requireAllowedVersions checks every protocol version a request names. It
// leaves r.Body readable for the SDK handler.
func requireAllowedVersions(w http.ResponseWriter, r *http.Request, allowed []string) error {
	var named []string
	if header := r.Header.Get(protocolVersionHeader); header != "" {
		named = append(named, header)
	}
	if r.Method == http.MethodPost && r.Body != nil {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sdk.DefaultMaxRequestBodyBytes))
		if err != nil {
			return fmt.Errorf("read request: %w", errBodyTooLarge)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		named = append(named, versionsInBody(body)...)
	}
	for _, version := range named {
		if !slices.Contains(allowed, version) {
			return fmt.Errorf("bad request: unsupported protocol version %q (supported versions: %s)",
				version, strings.Join(allowed, ","))
		}
	}
	return nil
}

type versionedMessage struct {
	Method string `json:"method"`
	Params struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Meta            map[string]any `json:"_meta"`
	} `json:"params"`
}

// versionsInBody lists the protocol versions named by the JSON-RPC messages
// of a body: the one an initialize request proposes and the per-request one
// of the 2026-07-28 protocol. A body that is not JSON-RPC names none; the SDK
// handler rejects it.
func versionsInBody(body []byte) []string {
	var messages []versionedMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		var single versionedMessage
		if json.Unmarshal(body, &single) != nil {
			return nil
		}
		messages = []versionedMessage{single}
	}
	var versions []string
	for _, m := range messages {
		if m.Method == "initialize" && m.Params.ProtocolVersion != "" {
			versions = append(versions, m.Params.ProtocolVersion)
		}
		if v, ok := m.Params.Meta[sdk.MetaKeyProtocolVersion].(string); ok {
			versions = append(versions, v)
		}
	}
	return versions
}

// ProtectedResourceMetadata serves the RFC 9728 document of the MCP resource:
// the resource identifier, its authorization server and the scopes it needs.
// Tokens are accepted in the Authorization header only.
func ProtectedResourceMetadata(resource, issuer string, scopes []string) http.Handler {
	return auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   []string{issuer},
		ScopesSupported:        scopes,
		BearerMethodsSupported: []string{"header"},
	})
}
