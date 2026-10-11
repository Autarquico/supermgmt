package join

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	requestTimeout   = 30 * time.Second
	maxResponseBytes = 1 << 20
)

// Client presents the join token to the server over HTTPS.
type Client struct {
	endpoint string
	http     *http.Client
}

var _ Enroller = (*Client)(nil)

// NewClient checks that server is an https URL and trusts the system roots, or
// the PEM certificates in caPEM when given. The token travels in the request
// body, so a plain-http server and any redirect are refused.
func NewClient(server string, caPEM []byte) (*Client, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "--server must be an https URL such as https://mgmt.example.com")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, smerr.New(smerr.CodeInvalidArgument, "", "--ca-file holds no PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	return &Client{
		endpoint: u.JoinPath(wire.PathEnroll).String(),
		http: &http.Client{
			Timeout:       requestTimeout,
			Transport:     &http.Transport{TLSClientConfig: tlsConfig},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Enroll posts the request and decodes the server's answer.
func (c *Client) Enroll(ctx context.Context, r wire.EnrollRequest) (wire.Enrolled, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return wire.Enrolled{}, fmt.Errorf("encode the enrollment request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return wire.Enrolled{}, fmt.Errorf("build the enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", wire.ContentType)
	req.Header.Set("Accept", wire.ContentType)
	resp, err := c.http.Do(req)
	if err != nil {
		return wire.Enrolled{}, fmt.Errorf("reach the server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return wire.Enrolled{}, fmt.Errorf("read the server's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return wire.Enrolled{}, serverError(resp.StatusCode, payload)
	}
	var envelope wire.Envelope[wire.Enrolled]
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Data.NodeID == "" {
		return wire.Enrolled{}, errors.New("the server sent an unreadable enrollment answer")
	}
	return envelope.Data, nil
}

func serverError(status int, payload []byte) error {
	var envelope wire.ErrorEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Error.Code == "" {
		return fmt.Errorf("the server answered HTTP %d without an error body", status)
	}
	return envelope.Error.Err()
}
