package oidc

import (
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

// trustedOrigins is the issuer's origin plus the configured extra origins
// (§23.1 discovery trust). The issuer itself must be https.
func trustedOrigins(cfg Config) (map[string]bool, error) {
	issuer, err := originOf(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: issuer: %w", err)
	}
	trusted := map[string]bool{issuer: true}
	for _, raw := range cfg.AllowedEndpointOrigins {
		origin, err := originOf(raw)
		if err != nil {
			return nil, fmt.Errorf("oidc: allowed_endpoint_origins: %w", err)
		}
		trusted[origin] = true
	}
	return trusted, nil
}

// originOf returns scheme://host[:port] of an https URL, lowercased and
// without the default port, so equal origins compare equal.
func originOf(raw string) (string, error) {
	u, err := parseHTTPS(raw)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && port != "443" {
		host += ":" + port
	}
	return "https://" + host, nil
}

// checkEndpoints refuses a discovery document that points the server at an
// origin nobody vouched for. The device endpoint is optional; the others are
// required.
func checkEndpoints(trusted map[string]bool, endpoint oauth2.Endpoint, jwksURI string) error {
	required := []struct{ name, url string }{
		{"authorization_endpoint", endpoint.AuthURL},
		{"token_endpoint", endpoint.TokenURL},
		{"jwks_uri", jwksURI},
	}
	for _, e := range required {
		if e.url == "" {
			return fmt.Errorf("oidc: discovery lacks %s", e.name)
		}
	}
	optional := []struct{ name, url string }{{"device_authorization_endpoint", endpoint.DeviceAuthURL}}
	for _, e := range append(required, optional...) {
		if e.url == "" {
			continue
		}
		origin, err := originOf(e.url)
		if err != nil {
			return fmt.Errorf("oidc: discovery %s: %w", e.name, err)
		}
		if !trusted[origin] {
			return fmt.Errorf("oidc: discovery %s is on origin %s, which is neither the issuer's nor in allowed_endpoint_origins", e.name, origin)
		}
	}
	return nil
}
