package oidc

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
	slowDownStep    = 5 * time.Second
)

// deviceTxn is a device login held by the server. Its mutex serializes polls,
// so one approval yields one session however many clients poll at once.
type deviceTxn struct {
	mu         sync.Mutex
	deviceCode string
	interval   time.Duration
	expiresAt  time.Time
	lastPoll   time.Time
	completed  bool // kept, not deleted, so a replay is CONFLICT rather than unknown
}

func (c *Client) DeviceStart(ctx context.Context) (DeviceTxn, error) {
	if c.oauth.Endpoint.DeviceAuthURL == "" {
		return DeviceTxn{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "the identity provider does not offer the device grant")
	}
	// Dex ignores HTTP Basic at the device endpoint: credentials go in the form (ADR-0018).
	auth, err := c.oauth.DeviceAuth(c.withHTTPClient(ctx),
		oauth2.SetAuthURLParam("client_secret", c.clientSecret.Reveal()))
	if err != nil {
		return DeviceTxn{}, idpError("start the device authorization", err)
	}
	if err := checkDeviceAuth(auth); err != nil {
		return DeviceTxn{}, invalid("identity provider returned a malformed device authorization", err)
	}
	now := c.clock.Now()
	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = defaultPollGap
	}
	// oauth2 turns expires_in into a wall-clock Expiry; rounding recovers the
	// seconds the IdP sent so the injected clock stays the only time source.
	lifetime := time.Until(auth.Expiry).Round(time.Second)
	txn := &deviceTxn{
		deviceCode: auth.DeviceCode,
		interval:   interval,
		expiresAt:  now.Add(lifetime),
		lastPoll:   now,
	}
	id := rand.Text()
	c.txns.put(id, txn)
	return DeviceTxn{
		ID:                      id,
		UserCode:                auth.UserCode,
		VerificationURI:         auth.VerificationURI,
		VerificationURIComplete: auth.VerificationURIComplete,
		Interval:                interval,
		ExpiresAt:               txn.expiresAt,
	}, nil
}

func checkDeviceAuth(auth *oauth2.DeviceAuthResponse) error {
	switch {
	case auth.DeviceCode == "" || auth.UserCode == "":
		return errors.New("device_code or user_code is missing")
	case auth.Expiry.IsZero():
		return errors.New("expires_in is missing")
	}
	if _, err := parseHTTPS(auth.VerificationURI); err != nil {
		return fmt.Errorf("verification_uri: %w", err)
	}
	if auth.VerificationURIComplete != "" {
		if _, err := parseHTTPS(auth.VerificationURIComplete); err != nil {
			return fmt.Errorf("verification_uri_complete: %w", err)
		}
	}
	return nil
}

func (c *Client) DevicePoll(ctx context.Context, txnID string) (Claims, error) {
	txn, ok := c.txns.get(txnID)
	if !ok {
		return Claims{}, invalid("device transaction is unknown", nil)
	}
	txn.mu.Lock()
	defer txn.mu.Unlock()
	now := c.clock.Now()
	switch {
	case txn.completed:
		return Claims{}, smerr.New(smerr.CodeConflict, "", "device login already completed")
	case !now.Before(txn.expiresAt):
		c.txns.drop(txnID)
		return Claims{}, invalid("device transaction expired", nil)
	case now.Sub(txn.lastPoll) < txn.interval:
		txn.lastPoll = now
		txn.interval += slowDownStep
		return Claims{}, Pending{SlowDown: true}
	}
	txn.lastPoll = now
	raw, err := c.pollIdP(ctx, txnID, txn)
	if err != nil {
		return Claims{}, err
	}
	claims, err := c.verifyIDToken(ctx, raw, "")
	if err != nil {
		c.txns.drop(txnID)
		return Claims{}, err
	}
	txn.completed = true
	return claims, nil
}

// pollIdP asks the token endpoint once and returns the raw ID token, Pending,
// or the reason the transaction is over (which also removes it).
func (c *Client) pollIdP(ctx context.Context, txnID string, txn *deviceTxn) (string, error) {
	status, reply, err := c.postDeviceGrant(ctx, txn.deviceCode)
	if err != nil {
		return "", smerr.Wrap(err, smerr.CodeProviderError, "", "identity provider unreachable: poll the device grant")
	}
	switch reply.Error {
	case "":
	case "authorization_pending":
		return "", Pending{}
	case "slow_down":
		txn.interval += slowDownStep
		return "", Pending{SlowDown: true}
	default: // expired_token, access_denied and anything unexpected end the login
		c.txns.drop(txnID)
		return "", invalid("device login was not approved: "+reply.Error, nil)
	}
	if status != http.StatusOK || reply.IDToken == "" {
		c.txns.drop(txnID)
		return "", invalid("token response has no id_token", errNoIDToken)
	}
	return reply.IDToken, nil
}

type deviceGrantReply struct {
	IDToken string `json:"id_token"`
	Error   string `json:"error"`
}

func (c *Client) postDeviceGrant(ctx context.Context, deviceCode string) (int, deviceGrantReply, error) {
	form := url.Values{
		"grant_type":  {deviceGrantType},
		"device_code": {deviceCode},
		"client_id":   {c.clientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauth.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, deviceGrantReply{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret.Reveal()))
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, deviceGrantReply{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, deviceGrantReply{}, err
	}
	var reply deviceGrantReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return resp.StatusCode, deviceGrantReply{}, nil // not JSON: no id_token, no error code
	}
	return resp.StatusCode, reply, nil
}
