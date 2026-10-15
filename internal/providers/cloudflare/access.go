package cloudflare

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

const (
	// ServiceTokenDuration is how long a service token lives (one year).
	ServiceTokenDuration = "8760h"
	sessionDuration      = "24h"
	maxEmailLen          = 254
	maxPolicyEntries     = 1000
)

func (c *Client) accessPath(kind, id string) (string, error) {
	if id == "" {
		return c.account("/access/" + kind), nil
	}
	if !validID(id) {
		return "", invalid("invalid %s id %q", kind, id)
	}
	return c.account("/access/" + kind + "/" + id), nil
}

// --- reusable policies ---

// CreateAccessPolicy creates a reusable Access policy.
func (c *Client) CreateAccessPolicy(ctx context.Context, spec PolicySpec) (AccessPolicy, error) {
	body, err := policyBody(spec)
	if err != nil {
		return AccessPolicy{}, err
	}
	path, _ := c.accessPath("policies", "")
	env, err := c.do(ctx, http.MethodPost, path, nil, body, maxObjectBody)
	if err != nil {
		return AccessPolicy{}, err
	}
	return policyOf(env)
}

// UpdateAccessPolicy replaces the name, decision and include list of a policy:
// rotating the service token rewrites the include list of every owned policy.
func (c *Client) UpdateAccessPolicy(ctx context.Context, id string, spec PolicySpec) (AccessPolicy, error) {
	path, err := c.accessPath("policies", id)
	if err != nil || id == "" {
		return AccessPolicy{}, orInvalid(err, "a policy id is required")
	}
	body, err := policyBody(spec)
	if err != nil {
		return AccessPolicy{}, err
	}
	env, err := c.do(ctx, http.MethodPut, path, nil, body, maxObjectBody)
	if err != nil {
		return AccessPolicy{}, err
	}
	return policyOf(env)
}

// FindAccessPolicies lists the reusable policies named exactly name. The API
// has no name filter for them, so every page is read and filtered here.
func (c *Client) FindAccessPolicies(ctx context.Context, name string) ([]AccessPolicy, error) {
	if !cleanName(name) {
		return nil, invalid("invalid policy name")
	}
	path, _ := c.accessPath("policies", "")
	all, err := listAll(ctx, c, path, nil, decodeAccessPolicies)
	return exactly(all, name, func(p AccessPolicy) string { return p.Name }, func(AccessPolicy) bool { return true }), err
}

// DeleteAccessPolicy deletes a reusable policy; one still attached to an
// application is refused.
func (c *Client) DeleteAccessPolicy(ctx context.Context, id string) error {
	path, err := c.accessPath("policies", id)
	if err != nil || id == "" {
		return orInvalid(err, "a policy id is required")
	}
	_, err = c.do(ctx, http.MethodDelete, path, nil, nil, maxObjectBody)
	return err
}

func policyOf(env envelope) (AccessPolicy, error) {
	p, err := decodeAccessPolicy(env.Result)
	if err != nil {
		return AccessPolicy{}, &outcomeUnknown{msg: "cloudflare: policy answer", err: err}
	}
	return p, nil
}

type includeRule map[string]map[string]string

func policyBody(spec PolicySpec) (map[string]any, error) {
	if !cleanName(spec.Name) {
		return nil, invalid("invalid policy name")
	}
	var decision string
	var include []includeRule
	switch spec.Kind {
	case PolicyServiceAuth:
		decision = "non_identity"
		if len(spec.ServiceTokenIDs) == 0 || len(spec.Emails) != 0 || len(spec.ServiceTokenIDs) > maxPolicyEntries {
			return nil, invalid("a service auth policy lists service tokens and nothing else")
		}
		for _, id := range spec.ServiceTokenIDs {
			if !validID(id) {
				return nil, invalid("invalid service token id %q", id)
			}
			include = append(include, includeRule{"service_token": {"token_id": id}})
		}
	case PolicyAllow:
		decision = "allow"
		if len(spec.Emails) == 0 || len(spec.ServiceTokenIDs) != 0 || len(spec.Emails) > maxPolicyEntries {
			return nil, invalid("an allow policy lists email addresses and nothing else")
		}
		for _, e := range spec.Emails {
			if !validEmail(e) {
				return nil, invalid("invalid owner email address")
			}
			include = append(include, includeRule{"email": {"email": e}})
		}
	default:
		return nil, invalid("unknown policy kind %q", spec.Kind)
	}
	return map[string]any{"name": spec.Name, "decision": decision, "include": include}, nil
}

// validEmail accepts a single plain address: one @, no wildcard, no spaces.
func validEmail(e string) bool {
	local, domain, ok := strings.Cut(e, "@")
	return ok && len(e) <= maxEmailLen && local != "" && strings.Contains(domain, ".") &&
		!strings.Contains(domain, "@") && !strings.ContainsAny(e, "* \t\r\n,;<>\"") && cleanName(e)
}

func orInvalid(err error, msg string) error {
	if err != nil {
		return err
	}
	return invalid("%s", msg)
}

// --- applications ---

// CreateAccessApp creates a self-hosted Access application on spec.Domain.
// The domain must be unique among the account's applications.
func (c *Client) CreateAccessApp(ctx context.Context, spec AppSpec) (AccessApp, error) {
	body, err := appBody(spec)
	if err != nil {
		return AccessApp{}, err
	}
	path, _ := c.accessPath("apps", "")
	env, err := c.do(ctx, http.MethodPost, path, nil, body, maxObjectBody)
	if err != nil {
		return AccessApp{}, err
	}
	return appOf(env)
}

// UpdateAccessApp replaces the policies and allowed identity providers of an
// application (the body of CreateAccessApp), so a re-run of setup can apply a
// changed access_identity_providers.
func (c *Client) UpdateAccessApp(ctx context.Context, id string, spec AppSpec) (AccessApp, error) {
	path, err := c.accessPath("apps", id)
	if err != nil || id == "" {
		return AccessApp{}, orInvalid(err, "an application id is required")
	}
	body, err := appBody(spec)
	if err != nil {
		return AccessApp{}, err
	}
	env, err := c.do(ctx, http.MethodPut, path, nil, body, maxObjectBody)
	if err != nil {
		return AccessApp{}, err
	}
	return appOf(env)
}

func appBody(spec AppSpec) (map[string]any, error) {
	if !cleanName(spec.Name) || !validHostname(strings.ToLower(spec.Domain)) || len(spec.PolicyIDs) == 0 {
		return nil, invalid("an application needs a name, a domain and at least one policy")
	}
	policies := make([]map[string]any, 0, len(spec.PolicyIDs))
	for i, id := range spec.PolicyIDs {
		if !validID(id) {
			return nil, invalid("invalid policy id %q", id)
		}
		policies = append(policies, map[string]any{"id": id, "precedence": i + 1})
	}
	body := map[string]any{
		"name": spec.Name, "domain": strings.ToLower(spec.Domain), "type": "self_hosted",
		"session_duration": sessionDuration, "policies": policies, "app_launcher_visible": false,
	}
	if len(spec.AllowedIdPs) > 0 {
		for _, id := range spec.AllowedIdPs {
			if !validID(id) {
				return nil, invalid("invalid identity provider id %q", id)
			}
		}
		body["allowed_idps"] = spec.AllowedIdPs
	}
	return body, nil
}

func appOf(env envelope) (AccessApp, error) {
	app, err := decodeAccessApp(env.Result)
	if err != nil {
		return AccessApp{}, &outcomeUnknown{msg: "cloudflare: application answer", err: err}
	}
	return app, nil
}

// FindAccessApps lists the applications named exactly name.
func (c *Client) FindAccessApps(ctx context.Context, name string) ([]AccessApp, error) {
	if !cleanName(name) {
		return nil, invalid("invalid application name")
	}
	path, _ := c.accessPath("apps", "")
	all, err := listAll(ctx, c, path, url.Values{"name": {name}, "exact": {"true"}}, decodeAccessApps)
	return exactly(all, name, func(a AccessApp) string { return a.Name }, func(AccessApp) bool { return true }), err
}

// DeleteAccessApp deletes an application.
func (c *Client) DeleteAccessApp(ctx context.Context, id string) error {
	path, err := c.accessPath("apps", id)
	if err != nil || id == "" {
		return orInvalid(err, "an application id is required")
	}
	_, err = c.do(ctx, http.MethodDelete, path, nil, nil, maxObjectBody)
	return err
}

// --- service tokens ---

// CreateServiceToken creates an Access service token. Its secret is in the
// answer to this call only: a caller that loses the answer deletes the token
// (found by name) and creates another.
func (c *Client) CreateServiceToken(ctx context.Context, name string) (NewServiceToken, error) {
	if !cleanName(name) {
		return NewServiceToken{}, invalid("invalid service token name")
	}
	path, _ := c.accessPath("service_tokens", "")
	env, err := c.do(ctx, http.MethodPost, path, nil,
		map[string]string{"name": name, "duration": ServiceTokenDuration}, maxObjectBody)
	if err != nil {
		return NewServiceToken{}, err
	}
	token, err := decodeServiceToken(env.Result)
	if err == nil && token.ClientSecret.Reveal() == "" {
		err = errUnreadable
	}
	if err != nil {
		return NewServiceToken{}, &outcomeUnknown{msg: "cloudflare: service token answer", err: err}
	}
	return token, nil
}

// FindServiceTokens lists the service tokens named exactly name.
func (c *Client) FindServiceTokens(ctx context.Context, name string) ([]ServiceToken, error) {
	if !cleanName(name) {
		return nil, invalid("invalid service token name")
	}
	path, _ := c.accessPath("service_tokens", "")
	all, err := listAll(ctx, c, path, url.Values{"name": {name}}, decodeServiceTokens)
	return exactly(all, name, func(t ServiceToken) string { return t.Name }, func(ServiceToken) bool { return true }), err
}

// DeleteServiceToken deletes a service token.
func (c *Client) DeleteServiceToken(ctx context.Context, id string) error {
	path, err := c.accessPath("service_tokens", id)
	if err != nil || id == "" {
		return orInvalid(err, "a service token id is required")
	}
	_, err = c.do(ctx, http.MethodDelete, path, nil, nil, maxObjectBody)
	return err
}
