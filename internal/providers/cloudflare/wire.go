package cloudflare

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/autarquico/supermgmt/internal/audit"
)

const (
	maxNameLen  = 255
	maxTokenLen = 4096
	maxItems    = 10_000
)

// idPattern is every Cloudflare identifier: 32 hex characters, a UUID, or the
// "<hex>.access" client ID of a service token.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)

var errUnreadable = errors.New("cloudflare: unreadable answer")

type wireError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type wireInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

// envelope is the v4 answer wrapper: success, errors and, on lists, result_info.
type envelope struct {
	Success bool
	Errors  []wireError
	Result  json.RawMessage
	Info    wireInfo
}

// decodeEnvelope reads the wrapper every v4 answer carries. A document without
// a boolean success is not a Cloudflare answer.
func decodeEnvelope(body []byte) (envelope, error) {
	var w struct {
		Success *bool           `json:"success"`
		Errors  []wireError     `json:"errors"`
		Result  json.RawMessage `json:"result"`
		Info    *wireInfo       `json:"result_info"`
	}
	if err := json.Unmarshal(body, &w); err != nil || w.Success == nil {
		return envelope{}, errUnreadable
	}
	env := envelope{Success: *w.Success, Errors: w.Errors, Result: w.Result}
	if w.Info != nil {
		env.Info = *w.Info
	}
	return env, nil
}

// decodeObject reads one JSON object and converts it with the type's own
// validation. A null or empty result is an error, not a zero object.
func decodeObject[W, T any](raw []byte, convert func(W) (T, error)) (T, error) {
	var zero T
	var w W
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &w) != nil {
		return zero, errUnreadable
	}
	return convert(w)
}

// decodeObjects reads a JSON array of objects; null is an empty list.
func decodeObjects[W, T any](raw []byte, convert func(W) (T, error)) ([]T, error) {
	var ws []W
	if len(raw) == 0 {
		return nil, errUnreadable
	}
	if json.Unmarshal(raw, &ws) != nil || len(ws) > maxItems {
		return nil, errUnreadable
	}
	out := make([]T, 0, len(ws))
	for _, w := range ws {
		v, err := convert(w)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func validID(s string) bool { return idPattern.MatchString(s) && s != "." && s != ".." }

// cleanName accepts a non-empty, bounded, control-free label.
func cleanName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

// cleanText accepts text that may be empty (a comment).
func cleanText(s string) bool {
	return len(s) <= 2*maxNameLen && !strings.ContainsFunc(s, unicode.IsControl)
}

func timeOf(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.UTC()
}

// --- tunnels ---

type wireTunnel struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	CreatedAt   *time.Time        `json:"created_at"`
	DeletedAt   *time.Time        `json:"deleted_at"`
	Status      string            `json:"status"`
	ConfigSrc   string            `json:"config_src"`
	Connections []json.RawMessage `json:"connections"`
}

func (w wireTunnel) tunnel() (Tunnel, error) {
	if !validID(w.ID) || !cleanName(w.Name) || !cleanText(w.Status) || !cleanText(w.ConfigSrc) {
		return Tunnel{}, errUnreadable
	}
	return Tunnel{
		ID: w.ID, Name: w.Name, CreatedAt: timeOf(w.CreatedAt), DeletedAt: timeOf(w.DeletedAt),
		Status: w.Status, ConfigSrc: w.ConfigSrc, ActiveConnections: len(w.Connections),
	}, nil
}

func decodeTunnel(raw []byte) (Tunnel, error) {
	return decodeObject(raw, wireTunnel.tunnel)
}

func decodeTunnels(raw []byte) ([]Tunnel, error) {
	return decodeObjects(raw, wireTunnel.tunnel)
}

type wireTunnelConfig struct {
	TunnelID string `json:"tunnel_id"`
	Version  int    `json:"version"`
	Config   *struct {
		Ingress []IngressRule `json:"ingress"`
	} `json:"config"`
}

func (w wireTunnelConfig) config() (TunnelConfig, error) {
	if !validID(w.TunnelID) || w.Version < 0 {
		return TunnelConfig{}, errUnreadable
	}
	cfg := TunnelConfig{TunnelID: w.TunnelID, Version: w.Version}
	if w.Config != nil {
		if len(w.Config.Ingress) > maxItems {
			return TunnelConfig{}, errUnreadable
		}
		for _, rule := range w.Config.Ingress {
			if !cleanText(rule.Hostname) || !cleanName(rule.Service) {
				return TunnelConfig{}, errUnreadable
			}
		}
		cfg.Ingress = w.Config.Ingress
	}
	return cfg, nil
}

func decodeTunnelConfig(raw []byte) (TunnelConfig, error) {
	return decodeObject(raw, wireTunnelConfig.config)
}

// decodeTunnelToken reads the tunnel token, a JSON string, into a Secret.
func decodeTunnelToken(raw []byte) (audit.Secret, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "" || len(s) > maxTokenLen ||
		strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return "", errUnreadable
	}
	return audit.Secret(s), nil
}

// --- DNS ---

type wireDNSRecord struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Content   string     `json:"content"`
	Proxied   bool       `json:"proxied"`
	Comment   *string    `json:"comment"`
	CreatedOn *time.Time `json:"created_on"`
}

func (w wireDNSRecord) record() (DNSRecord, error) {
	comment := ""
	if w.Comment != nil {
		comment = *w.Comment
	}
	if !validID(w.ID) || !cleanName(w.Name) || !cleanName(w.Type) || !cleanText(w.Content) || !cleanText(comment) {
		return DNSRecord{}, errUnreadable
	}
	return DNSRecord{
		ID: w.ID, Name: strings.ToLower(w.Name), Type: w.Type, Content: strings.ToLower(w.Content),
		Proxied: w.Proxied, Comment: comment, CreatedOn: timeOf(w.CreatedOn),
	}, nil
}

func decodeDNSRecord(raw []byte) (DNSRecord, error) {
	return decodeObject(raw, wireDNSRecord.record)
}

func decodeDNSRecords(raw []byte) ([]DNSRecord, error) {
	return decodeObjects(raw, wireDNSRecord.record)
}

type wireZone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}

func (w wireZone) zone() (Zone, error) {
	if !validID(w.ID) || !cleanName(w.Name) || !cleanText(w.Status) || (w.Account.ID != "" && !validID(w.Account.ID)) {
		return Zone{}, errUnreadable
	}
	return Zone{ID: w.ID, Name: strings.ToLower(w.Name), Status: w.Status, AccountID: w.Account.ID}, nil
}

func decodeZones(raw []byte) ([]Zone, error) {
	return decodeObjects(raw, wireZone.zone)
}

// --- Access ---

type wireApp struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Domain      string            `json:"domain"`
	Type        string            `json:"type"`
	Policies    []json.RawMessage `json:"policies"`
	AllowedIdPs []string          `json:"allowed_idps"`
	CreatedAt   *time.Time        `json:"created_at"`
}

func (w wireApp) app() (AccessApp, error) {
	if !validID(w.ID) || !cleanName(w.Name) || !cleanText(w.Domain) || !cleanText(w.Type) || len(w.Policies) > maxItems {
		return AccessApp{}, errUnreadable
	}
	app := AccessApp{
		ID: w.ID, Name: w.Name, Domain: strings.ToLower(w.Domain), Type: w.Type,
		AllowedIdPs: w.AllowedIdPs, CreatedAt: timeOf(w.CreatedAt),
	}
	for _, id := range w.AllowedIdPs {
		if !validID(id) {
			return AccessApp{}, errUnreadable
		}
	}
	for _, p := range w.Policies {
		id, err := policyRefID(p)
		if err != nil {
			return AccessApp{}, err
		}
		app.PolicyIDs = append(app.PolicyIDs, id)
	}
	return app, nil
}

// policyRefID reads an application's policy entry: an object with an id, or
// the bare id.
func policyRefID(raw json.RawMessage) (string, error) {
	var ref struct {
		ID string `json:"id"`
	}
	var bare string
	switch {
	case json.Unmarshal(raw, &ref) == nil && validID(ref.ID):
		return ref.ID, nil
	case json.Unmarshal(raw, &bare) == nil && validID(bare):
		return bare, nil
	}
	return "", errUnreadable
}

func decodeAccessApp(raw []byte) (AccessApp, error) {
	return decodeObject(raw, wireApp.app)
}

func decodeAccessApps(raw []byte) ([]AccessApp, error) {
	return decodeObjects(raw, wireApp.app)
}

type wirePolicy struct {
	ID        string                       `json:"id"`
	Name      string                       `json:"name"`
	Decision  string                       `json:"decision"`
	Include   []map[string]json.RawMessage `json:"include"`
	CreatedAt *time.Time                   `json:"created_at"`
}

func (w wirePolicy) policy() (AccessPolicy, error) {
	if !validID(w.ID) || !cleanName(w.Name) || !cleanText(w.Decision) || len(w.Include) > maxItems {
		return AccessPolicy{}, errUnreadable
	}
	p := AccessPolicy{ID: w.ID, Name: w.Name, Decision: w.Decision, CreatedAt: timeOf(w.CreatedAt)}
	for _, rule := range w.Include {
		if email, ok := includeEmail(rule); ok {
			p.Emails = append(p.Emails, email)
		} else if id, ok := includeServiceToken(rule); ok {
			p.ServiceTokenIDs = append(p.ServiceTokenIDs, id)
		} else {
			p.UnknownRules++
		}
	}
	return p, nil
}

func includeEmail(rule map[string]json.RawMessage) (string, bool) {
	var v struct {
		Email string `json:"email"`
	}
	raw, ok := rule["email"]
	if !ok || len(rule) != 1 || json.Unmarshal(raw, &v) != nil || !cleanName(v.Email) {
		return "", false
	}
	return strings.ToLower(v.Email), true
}

func includeServiceToken(rule map[string]json.RawMessage) (string, bool) {
	var v struct {
		TokenID string `json:"token_id"`
	}
	raw, ok := rule["service_token"]
	if !ok || len(rule) != 1 || json.Unmarshal(raw, &v) != nil || !validID(v.TokenID) {
		return "", false
	}
	return v.TokenID, true
}

func decodeAccessPolicy(raw []byte) (AccessPolicy, error) {
	return decodeObject(raw, wirePolicy.policy)
}

func decodeAccessPolicies(raw []byte) ([]AccessPolicy, error) {
	return decodeObjects(raw, wirePolicy.policy)
}

type wireServiceToken struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	ClientID     string     `json:"client_id"`
	ClientSecret string     `json:"client_secret"`
	CreatedAt    *time.Time `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

func (w wireServiceToken) token() (NewServiceToken, error) {
	if !validID(w.ID) || !cleanName(w.Name) || !validID(w.ClientID) || len(w.ClientSecret) > maxTokenLen ||
		strings.ContainsFunc(w.ClientSecret, unicode.IsSpace) {
		return NewServiceToken{}, errUnreadable
	}
	return NewServiceToken{
		ServiceToken: ServiceToken{
			ID: w.ID, Name: w.Name, ClientID: w.ClientID,
			CreatedAt: timeOf(w.CreatedAt), ExpiresAt: timeOf(w.ExpiresAt),
		},
		ClientSecret: audit.Secret(w.ClientSecret),
	}, nil
}

func decodeServiceToken(raw []byte) (NewServiceToken, error) {
	return decodeObject(raw, wireServiceToken.token)
}

func decodeServiceTokens(raw []byte) ([]ServiceToken, error) {
	return decodeObjects(raw, func(w wireServiceToken) (ServiceToken, error) {
		t, err := w.token()
		return t.ServiceToken, err
	})
}

// --- token verification ---

type wireTokenInfo struct {
	ID        string     `json:"id"`
	Status    string     `json:"status"`
	ExpiresOn *time.Time `json:"expires_on"`
}

func (w wireTokenInfo) info() (TokenInfo, error) {
	if !validID(w.ID) || !cleanName(w.Status) {
		return TokenInfo{}, errUnreadable
	}
	return TokenInfo{ID: w.ID, Status: w.Status, ExpiresOn: timeOf(w.ExpiresOn)}, nil
}

func decodeTokenInfo(raw []byte) (TokenInfo, error) {
	return decodeObject(raw, wireTokenInfo.info)
}
