package pvesim

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---- the shim's side: the Sim served to the tools in the PVE host container ----

// Handler serves POST /run to the shims. Every request carries the bearer token.
func (s *Sim) Handler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req Request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, s.Run(r.Context(), req))
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---- the fake API's side: the administration endpoint of its container ----

// TokenRequest, GrantRequest and RoleRequest are the bodies of the admin endpoint of the fake.
type TokenRequest struct {
	User    string `json:"user"`
	ID      string `json:"id"`
	Privsep bool   `json:"privsep"`
}

type GrantRequest struct {
	Subject   string `json:"subject"`
	Path      string `json:"path"`
	Role      string `json:"role"`
	Propagate bool   `json:"propagate"`
}

type RoleRequest struct {
	Name       string   `json:"name"`
	Privileges []string `json:"privileges"`
}

// AdminClient is the API implementation that talks to the admin endpoint of the fake PVE API.
type AdminClient struct {
	BaseURL string
	HTTP    *http.Client
}

// NewAdminClient returns a client for the admin endpoint at baseURL.
func NewAdminClient(baseURL string) *AdminClient {
	return &AdminClient{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *AdminClient) call(ctx context.Context, method, path string, body, into any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd) //nolint:gosec // the admin endpoint of the fake, chosen by the harness
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req) //nolint:gosec // see above
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	if into != nil {
		return json.Unmarshal(raw, into)
	}
	return nil
}

func (c *AdminClient) PutGuest(ctx context.Context, g FakeGuest) error {
	return c.call(ctx, http.MethodPost, "/guest", g, nil)
}

func (c *AdminClient) RemoveGuest(ctx context.Context, vmid int) error {
	return c.call(ctx, http.MethodDelete, fmt.Sprintf("/guest/%d", vmid), nil, nil)
}

func (c *AdminClient) SetRole(ctx context.Context, name string, privileges []string) error {
	return c.call(ctx, http.MethodPost, "/role", RoleRequest{Name: name, Privileges: privileges}, nil)
}

func (c *AdminClient) AddToken(ctx context.Context, user, id string, privsep bool) (string, error) {
	var reply struct {
		Secret string `json:"secret"`
	}
	err := c.call(ctx, http.MethodPost, "/token", TokenRequest{User: user, ID: id, Privsep: privsep}, &reply)
	return reply.Secret, err
}

func (c *AdminClient) Grant(ctx context.Context, subject, path, role string, propagate bool) error {
	return c.call(ctx, http.MethodPost, "/grant", GrantRequest{Subject: subject, Path: path, Role: role, Propagate: propagate}, nil)
}

func (c *AdminClient) Revoke(ctx context.Context, subject, path, role string) error {
	return c.call(ctx, http.MethodPost, "/revoke", GrantRequest{Subject: subject, Path: path, Role: role}, nil)
}

// CA is the PEM of the CA that signed the fake API's certificate.
func (c *AdminClient) CA(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/ca", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

// Ready reports whether the admin endpoint answers.
func (c *AdminClient) Ready(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
