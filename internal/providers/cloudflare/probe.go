package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Names of the checks a Probe runs.
const (
	CheckToken         = "token"
	CheckTunnels       = "tunnels"
	CheckAccessApps    = "access.apps"
	CheckAccessPolicy  = "access.policies"
	CheckServiceTokens = "access.service_tokens"
	CheckZone          = "zone"
	CheckDNS           = "dns"
)

// VerifyToken asks Cloudflare whether the token is valid and active. It proves
// validity and status only, never scopes. Account-owned tokens verify at the
// account endpoint, user-owned ones at the user endpoint; the account endpoint
// is tried first.
func (c *Client) VerifyToken(ctx context.Context) (TokenInfo, error) {
	info, err := c.verify(ctx, c.account("/tokens/verify"))
	var api *APIError
	if err == nil || !errors.As(err, &api) || api.Retryable() {
		return info, err
	}
	return c.verify(ctx, "/user/tokens/verify")
}

func (c *Client) verify(ctx context.Context, path string) (TokenInfo, error) {
	env, err := c.do(ctx, http.MethodGet, path, nil, nil, maxObjectBody)
	if err != nil {
		return TokenInfo{}, err
	}
	info, err := decodeTokenInfo(env.Result)
	if err != nil {
		return TokenInfo{}, &outcomeUnknown{msg: "cloudflare: token verification answer", err: err}
	}
	return info, nil
}

// Check is the outcome of one read-only probe.
type Check struct {
	Name string
	// Err is nil when the read succeeded; otherwise it is sanitized.
	Err error
}

// OK reports a successful read.
func (c Check) OK() bool { return c.Err == nil }

// ProbeReport is what the provisioning token was proven to do.
//
// Edit rights are deliberately absent: Cloudflare offers no way to prove them
// without mutating, so a caller reports them as "not verifiable".
type ProbeReport struct {
	Token  TokenInfo
	Checks []Check
}

// Check returns the named check; the zero Check (with an error) when it did not run.
func (r ProbeReport) Check(name string) Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{Name: name, Err: errors.New("not run")}
}

// Probe runs the read-only checks doctor reports: the token, the reads of the
// three product areas, the zone and the zone's DNS records. It never mutates.
func (c *Client) Probe(ctx context.Context, zoneName string) ProbeReport {
	var r ProbeReport
	info, err := c.VerifyToken(ctx)
	if err == nil && !info.Active() {
		err = fmt.Errorf("cloudflare: the API token is %s", c.sanitize(info.Status))
	}
	r.Token = info
	r.Checks = append(r.Checks, Check{CheckToken, err})
	for _, read := range []struct{ name, path string }{
		{CheckTunnels, c.account("/cfd_tunnel")},
		{CheckAccessApps, c.account("/access/apps")},
		{CheckAccessPolicy, c.account("/access/policies")},
		{CheckServiceTokens, c.account("/access/service_tokens")},
	} {
		r.Checks = append(r.Checks, Check{read.name, c.probePage(ctx, read.path)})
	}
	zone, err := c.ZoneByName(ctx, zoneName)
	r.Checks = append(r.Checks, Check{CheckZone, err})
	if err == nil {
		r.Checks = append(r.Checks, Check{CheckDNS, c.probePage(ctx, "/zones/"+zone.ID+"/dns_records")})
	}
	return r
}

func (c *Client) probePage(ctx context.Context, path string) error {
	_, err := c.do(ctx, http.MethodGet, path, url.Values{"page": {"1"}, "per_page": {"1"}}, nil, maxListBody)
	return err
}
