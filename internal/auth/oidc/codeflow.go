package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// loginState is what the server remembers between Start and Exchange.
type loginState struct {
	nonce     string
	redirect  string
	challenge string
	expiresAt time.Time
}

var (
	s256Challenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	pkceVerifier  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

func (c *Client) Start(ctx context.Context, redirect, challenge string) (string, string, error) {
	if err := checkLoopbackRedirect(redirect); err != nil {
		return "", "", smerr.Wrap(err, smerr.CodeInvalidArgument, "", "redirect_uri must be http://127.0.0.1:<port>/callback")
	}
	if !s256Challenge.MatchString(challenge) {
		return "", "", smerr.New(smerr.CodeInvalidArgument, "", "code_challenge must be an S256 challenge")
	}
	state, nonce := rand.Text(), rand.Text()
	now := c.clock.Now()
	expiresAt := now.Add(loginStateTTL)
	c.states.put(state, clientOf(ctx), loginState{
		nonce:     nonce,
		redirect:  redirect,
		challenge: challenge,
		expiresAt: expiresAt,
	}, expiresAt, now)
	conf := c.oauth
	conf.RedirectURL = redirect
	authURL := conf.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		gooidc.Nonce(nonce),
	)
	return authURL, state, nil
}

func (c *Client) Exchange(ctx context.Context, code, state, verifier string) (Claims, error) {
	login, ok := c.states.take(state)
	switch {
	case !ok || !c.clock.Now().Before(login.expiresAt):
		return Claims{}, invalid("login state is unknown or expired", nil)
	case code == "":
		return Claims{}, invalid("authorization code is missing", nil)
	case !verifierMatches(verifier, login.challenge):
		return Claims{}, invalid("code_verifier does not match the challenge", nil)
	}
	conf := c.oauth
	conf.RedirectURL = login.redirect
	token, err := conf.Exchange(c.withHTTPClient(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, idpError("redeem authorization code", err)
	}
	raw, _ := token.Extra("id_token").(string)
	if raw == "" {
		return Claims{}, invalid("token response has no id_token", errNoIDToken)
	}
	return c.verifyIDToken(ctx, raw, login.nonce)
}

// idpError separates an IdP that answered "no" (the person's problem) from an
// IdP that could not be reached (the operator's).
func idpError(action string, err error) error {
	var refusal *oauth2.RetrieveError
	if errors.As(err, &refusal) {
		return invalid("identity provider refused to "+action, err)
	}
	return smerr.Wrap(err, smerr.CodeProviderError, "", "identity provider unreachable: "+action)
}

func verifierMatches(verifier, challenge string) bool {
	if !pkceVerifier.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

// checkLoopbackRedirect accepts only http://127.0.0.1:<port>/callback
// (RFC 8252 section 7.3).
func checkLoopbackRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	port, portErr := strconv.Atoi(u.Port())
	switch {
	case u.Scheme != "http", u.Hostname() != "127.0.0.1":
		return fmt.Errorf("%q is not on the IPv4 loopback over http", raw)
	case portErr != nil || port < 1 || port > 65535:
		return fmt.Errorf("%q has no valid port", raw)
	case u.Path != "/callback", u.RawQuery != "", u.Fragment != "", u.User != nil, u.Opaque != "":
		return fmt.Errorf("%q is not exactly /callback", raw)
	}
	return nil
}
