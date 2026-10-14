package oauthfake

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// IntrospectionPath is where RFC 7662 introspection is served once enabled.
const IntrospectionPath = "/introspect"

// Introspection is the fake's token-introspection endpoint. It authenticates
// the caller with HTTP Basic (client_secret_basic) and answers
// `{"active": false}` for any token it was not told about.
type Introspection struct {
	clientID string
	secret   string

	mu        sync.Mutex
	responses map[string]map[string]any
}

// EnableIntrospection serves introspection for the given client credentials.
func (s *Server) EnableIntrospection(clientID, secret string) *Introspection {
	in := &Introspection{clientID: clientID, secret: secret, responses: map[string]map[string]any{}}
	s.Handle(IntrospectionPath, in.serve)
	return in
}

// IntrospectionURL is the URL of the endpoint.
func (s *Server) IntrospectionURL() string { return s.http.URL + IntrospectionPath }

// IntrospectionCalls is how many times the endpoint was called.
func (s *Server) IntrospectionCalls() int { return s.Calls(IntrospectionPath) }

// ActiveResponse is the introspection answer for a valid access token with the
// server's defaults, issued at now and valid for an hour. Mutate it freely.
func (s *Server) ActiveResponse(now time.Time) map[string]any {
	claims := s.AccessToken(now).Claims
	claims["active"] = true
	claims["token_type"] = "Bearer"
	return claims
}

// Answer makes the endpoint return response for bearer.
func (in *Introspection) Answer(bearer string, response map[string]any) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.responses[bearer] = response
}

func (in *Introspection) serve(w http.ResponseWriter, r *http.Request) {
	if !in.authenticated(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	in.mu.Lock()
	response, known := in.responses[r.PostForm.Get("token")]
	in.mu.Unlock()
	if !known {
		response = map[string]any{"active": false}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (in *Introspection) authenticated(r *http.Request) bool {
	id, secret, ok := r.BasicAuth()
	if !ok {
		return false
	}
	// Credentials arrive form-encoded (RFC 6749 §2.3.1).
	id, idErr := url.QueryUnescape(id)
	secret, secretErr := url.QueryUnescape(secret)
	return idErr == nil && secretErr == nil &&
		subtle.ConstantTimeCompare([]byte(id), []byte(in.clientID)) == 1 &&
		subtle.ConstantTimeCompare([]byte(secret), []byte(in.secret)) == 1
}
