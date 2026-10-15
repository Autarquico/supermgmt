package cloudflare

import (
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
)

// Tunnel is a Cloudflare Tunnel as the API reports it.
type Tunnel struct {
	ID        string
	Name      string
	CreatedAt time.Time
	// DeletedAt is zero while the tunnel is live.
	DeletedAt time.Time
	// Status is Cloudflare's word: inactive, degraded, healthy, down.
	Status string
	// ConfigSrc is "cloudflare" for a remotely managed tunnel.
	ConfigSrc         string
	ActiveConnections int
}

// Deleted reports whether the tunnel was deleted.
func (t Tunnel) Deleted() bool { return !t.DeletedAt.IsZero() }

// IngressRule routes a hostname to a service. The catch-all rule has no hostname.
type IngressRule struct {
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service"`
}

// Services of the rules SuperMgmt writes.
const (
	ServiceSSH      = "ssh://localhost:22"
	ServiceNotFound = "http_status:404"
)

// SSHIngress routes hostname to the node's SSH daemon and answers 404 to
// everything else.
func SSHIngress(hostname string) []IngressRule {
	return []IngressRule{{Hostname: hostname, Service: ServiceSSH}, {Service: ServiceNotFound}}
}

// ClosedIngress routes nothing: every request is answered 404.
func ClosedIngress() []IngressRule { return []IngressRule{{Service: ServiceNotFound}} }

// TunnelConfig is the remotely managed configuration of a tunnel.
type TunnelConfig struct {
	TunnelID string
	Version  int
	Ingress  []IngressRule
}

// DNSRecord is a record of the zone.
type DNSRecord struct {
	ID        string
	Name      string
	Type      string
	Content   string
	Proxied   bool
	Comment   string
	CreatedOn time.Time
}

// Zone is a DNS zone of the account.
type Zone struct {
	ID        string
	Name      string
	Status    string
	AccountID string
}

// AccessApp is an Access application.
type AccessApp struct {
	ID          string
	Name        string
	Domain      string
	Type        string
	PolicyIDs   []string
	AllowedIdPs []string
	CreatedAt   time.Time
}

// AppSpec describes a self-hosted Access application on one domain.
type AppSpec struct {
	Name   string
	Domain string
	// PolicyIDs are reusable policies, in precedence order.
	PolicyIDs []string
	// AllowedIdPs restricts the identity providers a login may use. Empty is
	// never sent as such: Cloudflare would admit every provider of the
	// account. The client resolves it to the one-time PIN provider.
	AllowedIdPs []string
}

// PolicyKind says what a reusable policy does.
type PolicyKind string

const (
	// PolicyServiceAuth admits service tokens (decision non_identity).
	PolicyServiceAuth PolicyKind = "service_auth"
	// PolicyAllow admits listed email addresses after a login (decision allow).
	PolicyAllow PolicyKind = "allow"
)

// PolicySpec describes a reusable Access policy. ServiceAuth policies list
// ServiceTokenIDs, Allow policies list Emails; the other list stays empty.
type PolicySpec struct {
	Name            string
	Kind            PolicyKind
	ServiceTokenIDs []string
	Emails          []string
}

// AccessPolicy is a reusable Access policy as the API reports it.
type AccessPolicy struct {
	ID              string
	Name            string
	Decision        string
	ServiceTokenIDs []string
	Emails          []string
	// UnknownRules counts include rules of a kind SuperMgmt does not write
	// (everyone, a domain, a group...). Include rules widen who is admitted, so
	// a caller treats a non-zero count as a policy it does not own.
	UnknownRules int
	CreatedAt    time.Time
}

// ServiceToken is an Access service token. Its secret is never listed.
type ServiceToken struct {
	ID        string
	Name      string
	ClientID  string
	CreatedAt time.Time
	// ExpiresAt is zero for a token that does not expire.
	ExpiresAt time.Time
}

// NewServiceToken is a freshly created service token: the only moment its
// secret is available.
type NewServiceToken struct {
	ServiceToken
	ClientSecret audit.Secret
}

// TokenInfo is the answer of the token verification endpoints: validity and
// status, never scopes.
type TokenInfo struct {
	ID        string
	Status    string
	ExpiresOn time.Time
}

// Active reports whether Cloudflare considers the token usable.
func (t TokenInfo) Active() bool { return t.Status == "active" }

// IdentityProvider is a login method of the account's Zero Trust organisation.
type IdentityProvider struct {
	ID   string
	Name string
	Type string
}
