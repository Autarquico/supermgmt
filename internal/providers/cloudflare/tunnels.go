package cloudflare

import (
	"context"
	"net/http"
	"net/url"

	"github.com/autarquico/supermgmt/internal/audit"
)

func (c *Client) tunnelPath(id, rest string) (string, error) {
	if !validID(id) {
		return "", invalid("invalid tunnel id %q", id)
	}
	return c.account("/cfd_tunnel/" + id + rest), nil
}

// CreateTunnel creates a remotely managed tunnel (config_src cloudflare). The
// name is the ownership marker; a name already taken is a conflict.
func (c *Client) CreateTunnel(ctx context.Context, name string) (Tunnel, error) {
	if !cleanName(name) {
		return Tunnel{}, invalid("invalid tunnel name")
	}
	env, err := c.do(ctx, http.MethodPost, c.account("/cfd_tunnel"), nil,
		map[string]string{"name": name, "config_src": "cloudflare"}, maxObjectBody)
	if err != nil {
		return Tunnel{}, err
	}
	return c.tunnelOf(env)
}

func (c *Client) tunnelOf(env envelope) (Tunnel, error) {
	t, err := decodeTunnel(env.Result)
	if err != nil {
		return Tunnel{}, &outcomeUnknown{msg: "cloudflare: tunnel answer", err: err}
	}
	return t, nil
}

// FindTunnels lists the live tunnels with exactly this name, reading every page.
func (c *Client) FindTunnels(ctx context.Context, name string) ([]Tunnel, error) {
	if !cleanName(name) {
		return nil, invalid("invalid tunnel name")
	}
	all, err := listAll(ctx, c, c.account("/cfd_tunnel"), url.Values{"name": {name}, "is_deleted": {"false"}}, decodeTunnels)
	return exactly(all, name, func(t Tunnel) string { return t.Name }, func(t Tunnel) bool { return !t.Deleted() }), err
}

// GetTunnel reads a tunnel by ID; a deleted tunnel is returned with DeletedAt set.
func (c *Client) GetTunnel(ctx context.Context, id string) (Tunnel, error) {
	path, err := c.tunnelPath(id, "")
	if err != nil {
		return Tunnel{}, err
	}
	env, err := c.do(ctx, http.MethodGet, path, nil, nil, maxObjectBody)
	if err != nil {
		return Tunnel{}, err
	}
	return c.tunnelOf(env)
}

// DeleteTunnel deletes a tunnel. Cloudflare refuses while connectors are
// attached; see CleanupTunnelConnections.
func (c *Client) DeleteTunnel(ctx context.Context, id string) error {
	path, err := c.tunnelPath(id, "")
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, path, nil, nil, maxObjectBody)
	return err
}

// CleanupTunnelConnections drops the connections of a tunnel whose connector
// has stopped, so that it can be deleted.
func (c *Client) CleanupTunnelConnections(ctx context.Context, id string) error {
	path, err := c.tunnelPath(id, "/connections")
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, path, nil, nil, maxObjectBody)
	return err
}

// PutTunnelIngress replaces the ingress of a tunnel's remote configuration.
// The last rule must be the hostname-less catch-all.
func (c *Client) PutTunnelIngress(ctx context.Context, id string, ingress []IngressRule) (TunnelConfig, error) {
	path, err := c.tunnelPath(id, "/configurations")
	if err != nil {
		return TunnelConfig{}, err
	}
	if err := validateIngress(ingress); err != nil {
		return TunnelConfig{}, err
	}
	body := map[string]any{"config": map[string]any{"ingress": ingress}}
	env, err := c.do(ctx, http.MethodPut, path, nil, body, maxObjectBody)
	if err != nil {
		return TunnelConfig{}, err
	}
	return c.configOf(env)
}

// GetTunnelConfig reads the remote configuration of a tunnel.
func (c *Client) GetTunnelConfig(ctx context.Context, id string) (TunnelConfig, error) {
	path, err := c.tunnelPath(id, "/configurations")
	if err != nil {
		return TunnelConfig{}, err
	}
	env, err := c.do(ctx, http.MethodGet, path, nil, nil, maxObjectBody)
	if err != nil {
		return TunnelConfig{}, err
	}
	return c.configOf(env)
}

func (c *Client) configOf(env envelope) (TunnelConfig, error) {
	cfg, err := decodeTunnelConfig(env.Result)
	if err != nil {
		return TunnelConfig{}, &outcomeUnknown{msg: "cloudflare: tunnel configuration answer", err: err}
	}
	return cfg, nil
}

func validateIngress(rules []IngressRule) error {
	if len(rules) == 0 || len(rules) > 100 {
		return invalid("ingress needs between 1 and 100 rules")
	}
	for i, r := range rules {
		last := i == len(rules)-1
		switch {
		case !cleanName(r.Service):
			return invalid("ingress rule %d has no valid service", i)
		case last && r.Hostname != "":
			return invalid("the last ingress rule must be the catch-all")
		case !last && !validHostname(r.Hostname):
			return invalid("ingress rule %d has an invalid hostname", i)
		}
	}
	return nil
}

// TunnelToken reads the credential cloudflared runs with. It is a secret: the
// caller streams it to the node and keeps it nowhere else.
func (c *Client) TunnelToken(ctx context.Context, id string) (audit.Secret, error) {
	path, err := c.tunnelPath(id, "/token")
	if err != nil {
		return "", err
	}
	env, err := c.do(ctx, http.MethodGet, path, nil, nil, maxObjectBody)
	if err != nil {
		return "", err
	}
	token, err := decodeTunnelToken(env.Result)
	if err != nil {
		return "", &outcomeUnknown{msg: "cloudflare: tunnel token answer", err: err}
	}
	return token, nil
}

// exactly keeps the items whose name equals want and that pass keep: the
// server filter is a convenience, never the proof.
func exactly[T any](items []T, want string, name func(T) string, keep func(T) bool) []T {
	var out []T
	for _, it := range items {
		if name(it) == want && keep(it) {
			out = append(out, it)
		}
	}
	return out
}
