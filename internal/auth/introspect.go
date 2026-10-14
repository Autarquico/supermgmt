package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
)

// introspectionMaxResponseBytes bounds what an authorization server can make
// us read back.
const introspectionMaxResponseBytes = 1 << 20

// introspectionTokenTypes are the `token_type` values (RFC 7662 §2.2) of an
// access token a bearer may present.
var introspectionTokenTypes = []string{"access_token", "Bearer"}

// introspector validates opaque access tokens with the authorization
// server's RFC 7662 endpoint. Every call is a fresh request: an answer is
// never cached beyond the request that asked.
type introspector struct {
	endpoint string
	clientID string
	secret   audit.Secret
	http     *http.Client
}

func newIntrospector(cfg OAuthConfig) introspector {
	return introspector{endpoint: cfg.IntrospectionURL, clientID: cfg.ClientID, secret: cfg.ClientSecret, http: cfg.HTTP}
}

func (i introspector) verify(ctx context.Context, bearer string) (accessClaims, error) {
	body, err := i.ask(ctx, bearer)
	if err != nil {
		return accessClaims{}, err
	}
	if err := requireActiveAccessToken(body); err != nil {
		return accessClaims{}, err
	}
	return decodeAccessClaims(body)
}

func (i introspector) ask(ctx context.Context, bearer string) ([]byte, error) {
	form := url.Values{"token": {bearer}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// client_secret_basic: both parts are form-encoded first (RFC 6749 §2.3.1).
	req.SetBasicAuth(url.QueryEscape(i.clientID), url.QueryEscape(i.secret.Reveal()))
	resp, err := i.http.Do(req)
	if err != nil {
		return nil, invalidOAuthToken("introspection unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, invalidOAuthToken("introspection refused the request")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, introspectionMaxResponseBytes))
	if err != nil {
		return nil, invalidOAuthToken("introspection response unreadable")
	}
	return body, nil
}

// requireActiveAccessToken reads the two introspection-only members: `active`
// must be true and `token_type`, when present, must name an access token.
func requireActiveAccessToken(body []byte) error {
	var answer struct {
		Active    bool   `json:"active"`
		TokenType string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return invalidOAuthToken("introspection response is malformed")
	}
	switch {
	case !answer.Active:
		return invalidOAuthToken("token is not active")
	case answer.TokenType != "" && !slices.Contains(introspectionTokenTypes, answer.TokenType):
		return invalidOAuthToken("token type is not an access token")
	}
	return nil
}
