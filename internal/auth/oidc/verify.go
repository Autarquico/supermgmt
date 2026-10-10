package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func invalid(msg string, cause error) error {
	return smerr.Wrap(cause, smerr.CodeUnauthenticated, smerr.ReasonOIDCInvalid, msg)
}

// idTokenClaims are the claims go-oidc does not expose itself. email_verified
// is a strict bool: a string "true" is rejected rather than coerced.
type idTokenClaims struct {
	Email           string   `json:"email"`
	EmailVerified   bool     `json:"email_verified"`
	Name            string   `json:"name"`
	AuthorizedParty string   `json:"azp"`
	JTI             string   `json:"jti"`
	NotBefore       *float64 `json:"nbf"`
}

// verifyIDToken checks a raw ID token (ADR-0018 "ID token verification").
// wantNonce is empty for the device flow, which has no nonce (RFC 8628).
func (c *Client) verifyIDToken(ctx context.Context, raw, wantNonce string) (Claims, error) {
	token, err := c.verifier.Verify(c.withHTTPClient(ctx), raw)
	if err != nil {
		return Claims{}, invalid("id token rejected", err)
	}
	var extra idTokenClaims
	if err := token.Claims(&extra); err != nil {
		return Claims{}, invalid("id token claims malformed", err)
	}
	if err := c.checkClaims(token, extra, wantNonce); err != nil {
		return Claims{}, err
	}
	if err := c.rememberJTI(ctx, token, extra.JTI); err != nil {
		return Claims{}, err
	}
	return Claims{
		Issuer:        token.Issuer,
		Subject:       token.Subject,
		Email:         extra.Email,
		EmailVerified: extra.EmailVerified,
		Name:          extra.Name,
	}, nil
}

func (c *Client) checkClaims(token *gooidc.IDToken, extra idTokenClaims, wantNonce string) error {
	now := c.clock.Now()
	switch {
	case token.Subject == "":
		return invalid("id token has no subject", nil)
	case token.Expiry.Add(clockSkew).Before(now):
		return invalid("id token expired", nil)
	case token.IssuedAt.IsZero() || token.IssuedAt.After(now.Add(clockSkew)):
		return invalid("id token issued in the future or without iat", nil)
	case extra.NotBefore != nil && time.Unix(int64(*extra.NotBefore), 0).After(now.Add(clockSkew)):
		return invalid("id token not yet valid", nil)
	case !authorizedPartyOK(token.Audience, extra.AuthorizedParty, c.clientID):
		return invalid("id token authorized party mismatch", nil)
	case wantNonce != "" && subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(wantNonce)) != 1:
		return invalid("id token nonce mismatch", nil)
	case !extra.EmailVerified || extra.Email == "":
		return invalid("id token has no verified email", nil)
	case !c.domainAllowed(extra.Email):
		return invalid("email domain is not allowed", nil)
	}
	return nil
}

// authorizedPartyOK: azp, when present, is this client; with several
// audiences it must be present (OIDC Core 3.1.3.7).
func authorizedPartyOK(audience []string, azp, clientID string) bool {
	if azp != "" {
		return azp == clientID
	}
	return len(audience) <= 1
}

// domainAllowed accepts exactly one "@" and, when allowed_domains is set, a
// domain in it (case-insensitive).
func (c *Client) domainAllowed(email string) bool {
	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	if len(c.allowedMails) == 0 {
		return true
	}
	for _, allowed := range c.allowedMails {
		if strings.EqualFold(domain, allowed) {
			return true
		}
	}
	return false
}

func (c *Client) rememberJTI(ctx context.Context, token *gooidc.IDToken, jti string) error {
	if jti == "" {
		return nil
	}
	fresh, err := c.replay.Remember(ctx, token.Issuer, jti, token.Expiry.Add(clockSkew))
	if err != nil {
		return smerr.Wrap(err, smerr.CodeInternal, "", "record id token jti")
	}
	if !fresh {
		return smerr.FromReason(smerr.ReasonOIDCReplay, "id token already used")
	}
	return nil
}

var errNoIDToken = errors.New("token response has no id_token")
