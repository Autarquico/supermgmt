package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Remote MCP access tokens (spec §24, ADR-0033): an external authorization
// server issues them, SuperMgmt only validates them. A token is checked
// against the RFC 9068 profile, mapped to the pre-registered `mcp` identity of
// its (issuer, subject, client_id) and recorded by hash so revocation and
// expiry at claim work as for every other credential.

const (
	oauthClockSkew      = time.Minute
	oauthMaxTokenBytes  = 8 << 10
	oauthTokenIDPrefix  = "oat-"
	oauthTokenIDHexSize = 32
)

// OAuthConfig is the validated mcp.oauth section plus its collaborators.
type OAuthConfig struct {
	Issuer           string
	Resource         string
	JWKSURL          string
	IntrospectionURL string
	ClientID         string
	ClientSecret     audit.Secret
	RequiredScopes   []string
	// HTTP reaches the authorization server: netguard provider rules, no redirects.
	HTTP *http.Client
	// Clock defaults to the system clock.
	Clock domain.Clock
}

// accessVerifier turns a bearer into the claims of an access token whose
// signature (or activity, for introspection) is already established. It
// applies none of the claim rules: those are the resolver's, so every
// validation path is held to the same ones.
type accessVerifier interface {
	verify(ctx context.Context, bearer string) (accessClaims, error)
}

// OAuthResolver authenticates a remote MCP client's OAuth access token.
type OAuthResolver struct {
	db     *database.DB
	cfg    OAuthConfig
	jwt    accessVerifier // nil without jwks_url
	opaque accessVerifier // nil without introspection_url
}

var _ Resolver = (*OAuthResolver)(nil)

// NewOAuthResolver builds the resolver. Nothing is fetched until the first
// token arrives.
func NewOAuthResolver(ctx context.Context, cfg OAuthConfig, db *database.DB) (*OAuthResolver, error) {
	if db == nil || cfg.HTTP == nil || cfg.Issuer == "" || cfg.Resource == "" {
		return nil, errors.New("oauth resolver needs a database, an http client, an issuer and a resource")
	}
	if cfg.JWKSURL == "" && cfg.IntrospectionURL == "" {
		return nil, errors.New("oauth resolver needs jwks_url or introspection_url")
	}
	r := &OAuthResolver{db: db, cfg: cfg}
	if cfg.JWKSURL != "" {
		r.jwt = jwtVerifier{keys: gooidc.NewRemoteKeySet(gooidc.ClientContext(ctx, cfg.HTTP), cfg.JWKSURL)}
	}
	if cfg.IntrospectionURL != "" {
		if cfg.ClientID == "" || cfg.ClientSecret.Reveal() == "" {
			return nil, errors.New("oauth introspection needs a client id and secret")
		}
		r.opaque = newIntrospector(cfg)
	}
	return r, nil
}

func (r *OAuthResolver) now() time.Time { return clockOrSystem(r.cfg.Clock).Now() }

func (r *OAuthResolver) Resolve(ctx context.Context, bearer string) (app.Caller, error) {
	if len(bearer) > oauthMaxTokenBytes {
		return app.Caller{}, invalidOAuthToken("token too large")
	}
	hash := hashOf(bearer)
	if err := r.refuseRevoked(ctx, hash); err != nil {
		return app.Caller{}, err
	}
	verifier, err := r.verifierFor(bearer)
	if err != nil {
		return app.Caller{}, err
	}
	claims, err := verifier.verify(ctx, bearer)
	if err != nil {
		return app.Caller{}, err
	}
	if err := r.checkClaims(claims); err != nil {
		return app.Caller{}, err
	}
	return r.admit(ctx, hash, claims)
}

func (r *OAuthResolver) verifierFor(bearer string) (accessVerifier, error) {
	jwtShaped := strings.Count(bearer, ".") == 2
	switch {
	case jwtShaped && r.jwt != nil:
		return r.jwt, nil
	case r.opaque != nil:
		return r.opaque, nil
	}
	return nil, invalidOAuthToken("no validation method for this token")
}

// refuseRevoked rejects a token whose row was revoked before any signature or
// network work, so a revoked token costs no JWKS or introspection call.
func (r *OAuthResolver) refuseRevoked(ctx context.Context, hash string) error {
	row, err := database.GetOAuthAccessTokenByHash(ctx, r.db.Reader(), hash)
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return nil
	case err != nil:
		return fmt.Errorf("look up oauth access token: %w", err)
	case row.RevokedAt != nil:
		return smerr.FromReason(smerr.ReasonCredentialRevoked, "credential was revoked")
	}
	return nil
}

// checkClaims applies the RFC 9068 access-token rules of ADR-0033. The scope
// check comes last so that only an otherwise valid token earns a 403.
func (r *OAuthResolver) checkClaims(c accessClaims) error {
	now := r.now()
	switch {
	case c.HasNonce:
		return invalidOAuthToken("token carries a nonce")
	case c.Issuer != r.cfg.Issuer:
		return invalidOAuthToken("wrong issuer")
	case !slices.Contains(c.Audience, r.cfg.Resource):
		return invalidOAuthToken("token is not for this resource")
	case c.ExpiresAt.IsZero() || now.After(c.ExpiresAt.Add(oauthClockSkew)):
		return invalidOAuthToken("token expired")
	case c.IssuedAt.IsZero():
		return invalidOAuthToken("token has no iat")
	case c.IssuedAt.After(now.Add(oauthClockSkew)):
		return invalidOAuthToken("token issued in the future")
	case c.NotBefore != nil && c.NotBefore.After(now.Add(oauthClockSkew)):
		return invalidOAuthToken("token not yet valid")
	case c.Subject == "":
		return invalidOAuthToken("token has no subject")
	case c.ClientID == "":
		return invalidOAuthToken("token has no client_id")
	case c.AuthorizedParty != "" && c.AuthorizedParty != c.ClientID:
		return invalidOAuthToken("azp does not match client_id")
	}
	if missing := missingScopes(r.cfg.RequiredScopes, c.Scopes); len(missing) > 0 {
		return smerr.FromReason(smerr.ReasonScopeDenied, "insufficient_scope: "+strings.Join(missing, " "))
	}
	return nil
}

func missingScopes(required, granted []string) []string {
	var missing []string
	for _, s := range required {
		if !slices.Contains(granted, s) {
			missing = append(missing, s)
		}
	}
	return missing
}

// admit maps the claims to the live remote client registered for them and
// records the token.
func (r *OAuthResolver) admit(ctx context.Context, hash string, c accessClaims) (app.Caller, error) {
	client, err := r.registeredClient(ctx, c)
	if err != nil {
		return app.Caller{}, err
	}
	if c.IssuedAt.Before(client.CreatedAt.Add(-oauthClockSkew)) {
		return app.Caller{}, invalidOAuthToken("token predates the client registration")
	}
	floor, err := database.CredentialsNotBefore(ctx, r.db.Reader())
	if err != nil {
		return app.Caller{}, fmt.Errorf("read credentials floor: %w", err)
	}
	if c.IssuedAt.Before(floor) {
		return app.Caller{}, invalidOAuthToken("token predates a restore")
	}
	stored, err := r.record(ctx, hash, client, c)
	if err != nil {
		return app.Caller{}, err
	}
	expires := c.ExpiresAt
	return app.Caller{
		ID:         client.IdentityID,
		Credential: domain.CredentialContext{Kind: domain.CredentialOAuthAccessToken, ID: stored.ID.String(), ExpiresAt: &expires},
		Source:     requestSource,
	}, nil
}

func unregisteredMCPClient() error {
	return smerr.FromReason(smerr.ReasonMCPClientUnregistered, "no registered MCP client for this token")
}

// registeredClient is the live, active remote client of the token's
// (issuer, subject, client_id). Every miss is the same error, so a token
// cannot probe which clients exist.
func (r *OAuthResolver) registeredClient(ctx context.Context, c accessClaims) (database.MCPClient, error) {
	var id domain.ID
	err := r.db.Reader().QueryRowContext(ctx, `
		SELECT COALESCE(MAX(id), '') FROM identities
		WHERE actor_type = ? AND issuer = ? AND subject = ? AND client_id = ? AND disabled_at IS NULL`,
		domain.ActorMCP, c.Issuer, c.Subject, c.ClientID).Scan(&id)
	if err != nil {
		return database.MCPClient{}, fmt.Errorf("find mcp identity: %w", err)
	}
	if id == "" {
		return database.MCPClient{}, unregisteredMCPClient()
	}
	client, err := database.GetLiveMCPClientByIdentity(ctx, r.db.Reader(), id)
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return database.MCPClient{}, unregisteredMCPClient()
	case err != nil:
		return database.MCPClient{}, fmt.Errorf("find mcp client: %w", err)
	case client.Origin != database.MCPOriginRemote || client.State != database.MCPClientActive:
		return database.MCPClient{}, unregisteredMCPClient()
	}
	return client, nil
}

func (r *OAuthResolver) record(ctx context.Context, hash string, client database.MCPClient, c accessClaims) (database.OAuthAccessToken, error) {
	var stored database.OAuthAccessToken
	err := r.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		var err error
		stored, err = database.RecordOAuthAccessToken(ctx, tx, database.OAuthAccessToken{
			ID: domain.ID(oauthTokenIDPrefix + hash[:oauthTokenIDHexSize]), MCPClientID: client.ID, TokenHash: hash,
			Issuer: c.Issuer, JTI: c.JTI, IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, FirstSeenAt: r.now(),
		})
		return err
	})
	if smerr.CodeOf(err) == smerr.CodeConflict {
		return database.OAuthAccessToken{}, invalidOAuthToken("token is revoked or belongs to another client")
	}
	if err != nil {
		return database.OAuthAccessToken{}, fmt.Errorf("record oauth access token: %w", err)
	}
	return stored, nil
}

func invalidOAuthToken(msg string) error {
	return smerr.FromReason(smerr.ReasonOAuthTokenInvalid, msg)
}

// ---- claims ----------------------------------------------------------------

// accessClaims are the claims of an access token that the rules read, whether
// they came from a JWT payload or an introspection response.
type accessClaims struct {
	Issuer          string
	Subject         string
	Audience        []string
	ClientID        string
	AuthorizedParty string
	Scopes          []string
	JTI             string
	ExpiresAt       time.Time
	IssuedAt        time.Time
	NotBefore       *time.Time
	HasNonce        bool
}

// rawAccessClaims is the wire shape shared by JWT payloads (RFC 9068) and
// introspection responses (RFC 7662).
type rawAccessClaims struct {
	Issuer          string          `json:"iss"`
	Subject         string          `json:"sub"`
	Audience        audience        `json:"aud"`
	ClientID        string          `json:"client_id"`
	AuthorizedParty string          `json:"azp"`
	Scope           scopeList       `json:"scope"`
	Scp             scopeList       `json:"scp"`
	JTI             string          `json:"jti"`
	Exp             *float64        `json:"exp"`
	Iat             *float64        `json:"iat"`
	Nbf             *float64        `json:"nbf"`
	Nonce           json.RawMessage `json:"nonce"`
}

func decodeAccessClaims(payload []byte) (accessClaims, error) {
	var raw rawAccessClaims
	if err := json.Unmarshal(payload, &raw); err != nil {
		return accessClaims{}, invalidOAuthToken("claims are malformed")
	}
	return accessClaims{
		Issuer: raw.Issuer, Subject: raw.Subject, Audience: raw.Audience, ClientID: raw.ClientID,
		AuthorizedParty: raw.AuthorizedParty, Scopes: append(raw.Scope, raw.Scp...), JTI: raw.JTI,
		ExpiresAt: unixTime(raw.Exp), IssuedAt: unixTime(raw.Iat), NotBefore: optionalUnixTime(raw.Nbf),
		HasNonce: len(raw.Nonce) > 0,
	}, nil
}

func unixTime(seconds *float64) time.Time {
	if seconds == nil {
		return time.Time{}
	}
	return time.Unix(int64(*seconds), 0)
}

func optionalUnixTime(seconds *float64) *time.Time {
	if seconds == nil {
		return nil
	}
	t := unixTime(seconds)
	return &t
}

// audience is `aud`: a string or an array of strings (RFC 7519 §4.1.3).
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// scopeList is `scope` (space-delimited string, RFC 8693) or `scp` (array).
type scopeList []string

func (s *scopeList) UnmarshalJSON(b []byte) error {
	var delimited string
	if json.Unmarshal(b, &delimited) == nil {
		*s = strings.Fields(delimited)
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// ---- JWT path --------------------------------------------------------------

// jwtAlgorithms are the signature algorithms ADR-0033 admits; "none" and the
// HMAC family are absent, so a key set cannot be tricked into a symmetric check.
var jwtAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA"}

var jwtAccessTokenTypes = []string{"at+jwt", "application/at+jwt"}

type jwtVerifier struct {
	keys *gooidc.RemoteKeySet
}

func (v jwtVerifier) verify(ctx context.Context, bearer string) (accessClaims, error) {
	if err := checkJWTHeader(bearer); err != nil {
		return accessClaims{}, err
	}
	payload, err := v.keys.VerifySignature(ctx, bearer)
	if err != nil {
		return accessClaims{}, smerr.Wrap(err, smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid, "signature rejected")
	}
	return decodeAccessClaims(payload)
}

// checkJWTHeader enforces the algorithm allowlist and the RFC 9068 `typ`,
// the only in-band mark that tells an access token from an ID token.
func checkJWTHeader(token string) error {
	encoded, _, found := strings.Cut(token, ".")
	if !found {
		return invalidOAuthToken("token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return invalidOAuthToken("token header is malformed")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return invalidOAuthToken("token header is malformed")
	}
	switch {
	case !slices.Contains(jwtAlgorithms, header.Alg):
		return invalidOAuthToken("signature algorithm not accepted")
	case !slices.Contains(jwtAccessTokenTypes, strings.ToLower(header.Typ)):
		return invalidOAuthToken("token type is not at+jwt")
	}
	return nil
}
