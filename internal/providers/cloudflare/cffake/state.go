package cffake

import (
	"slices"
	"strings"
	"time"
)

// Ingress is one rule of a tunnel's remote configuration.
type Ingress struct{ Hostname, Service string }

// Tunnel is a stored tunnel.
type Tunnel struct {
	ID, Name, ConfigSrc string
	CreatedAt           time.Time
	DeletedAt           time.Time // zero while live
	Connections         int
	Configured          bool // an ingress was ever PUT
	ConfigVersion       int
	Ingress             []Ingress
	seq                 int
}

// DNSRecord is a stored DNS record.
type DNSRecord struct {
	ID, Name, Type, Content, Comment string
	Proxied                          bool
	CreatedOn                        time.Time
	seq                              int
}

// Policy is a stored reusable Access policy.
type Policy struct {
	ID, Name, Decision string
	ServiceTokenIDs    []string
	Emails             []string
	CreatedAt          time.Time
	seq                int
}

// App is a stored Access application.
type App struct {
	ID, Name, Domain, Type string
	PolicyIDs              []string
	AllowedIdPs            []string
	CreatedAt              time.Time
	seq                    int
}

// IdentityProvider is a login method of the account's Zero Trust organisation.
type IdentityProvider struct{ ID, Name, Type string }

// ServiceToken is a stored Access service token.
type ServiceToken struct {
	ID, Name, ClientID, ClientSecret string
	CreatedAt, ExpiresAt             time.Time
	seq                              int
}

// Snapshot is every live object, by type, in creation order.
type Snapshot struct {
	Tunnels       []Tunnel
	DNSRecords    []DNSRecord
	Apps          []App
	Policies      []Policy
	ServiceTokens []ServiceToken
}

// Count is the number of objects in the snapshot.
func (s Snapshot) Count() int {
	return len(s.Tunnels) + len(s.DNSRecords) + len(s.Apps) + len(s.Policies) + len(s.ServiceTokens)
}

// Snapshot copies the live state. Deleted tunnels are not in it.
func (f *Fake) Snapshot() Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	var s Snapshot
	for _, t := range f.tunnels {
		if t.DeletedAt.IsZero() {
			s.Tunnels = append(s.Tunnels, t)
		}
	}
	s.DNSRecords = slices.Clone(f.dns)
	s.Apps = slices.Clone(f.apps)
	s.Policies = slices.Clone(f.policies)
	s.ServiceTokens = slices.Clone(f.tokens)
	return s
}

// Tunnels, DNSRecords, Apps, Policies and ServiceTokens are the Snapshot
// lists, for tests that look at one type.
func (f *Fake) Tunnels() []Tunnel             { return f.Snapshot().Tunnels }
func (f *Fake) DNSRecords() []DNSRecord       { return f.Snapshot().DNSRecords }
func (f *Fake) Apps() []App                   { return f.Snapshot().Apps }
func (f *Fake) Policies() []Policy            { return f.Snapshot().Policies }
func (f *Fake) ServiceTokens() []ServiceToken { return f.Snapshot().ServiceTokens }

// ConnectTunnel sets the number of connectors attached to a tunnel; Cloudflare
// refuses to delete a tunnel that has any.
func (f *Fake) ConnectTunnel(id string, connections int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.tunnels {
		if f.tunnels[i].ID == id {
			f.tunnels[i].Connections = connections
		}
	}
}

// SeedTunnel adds a live tunnel without a request, for objects another owner
// created.
func (f *Fake) SeedTunnel(name string) Tunnel {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := Tunnel{ID: f.newID(1), Name: name, ConfigSrc: "cloudflare", CreatedAt: f.clock(), seq: f.reqSeq}
	f.tunnels = append(f.tunnels, t)
	return t
}

// SeedDNSRecord adds a proxied CNAME without a request.
func (f *Fake) SeedDNSRecord(name, content, comment string) DNSRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := DNSRecord{
		ID: f.newHexID(4), Name: strings.ToLower(name), Type: "CNAME", Content: strings.ToLower(content),
		Proxied: true, Comment: comment, CreatedOn: f.clock(), seq: f.reqSeq,
	}
	f.dns = append(f.dns, r)
	return r
}

// SeedPolicy adds a reusable policy that admits one email, without a request.
func (f *Fake) SeedPolicy(name, email string) Policy {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := Policy{ID: f.newID(2), Name: name, Decision: "allow", Emails: []string{email}, CreatedAt: f.clock(), seq: f.reqSeq}
	f.policies = append(f.policies, p)
	return p
}

// RemovePolicy deletes a reusable policy without a request, as someone in the
// dashboard would; it reports whether one was there. An application still
// pointing at it keeps the dangling ID.
func (f *Fake) RemovePolicy(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, p := range f.policies {
		if p.ID == id {
			f.policies = append(f.policies[:i], f.policies[i+1:]...)
			return true
		}
	}
	return false
}

// RemoveApp deletes an Access application without a request, as someone in the
// dashboard would; it reports whether one was there.
func (f *Fake) RemoveApp(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, a := range f.apps {
		if a.ID == id {
			f.apps = append(f.apps[:i], f.apps[i+1:]...)
			return true
		}
	}
	return false
}

// SeedApp adds an Access application without a request.
func (f *Fake) SeedApp(name, domain string, policyIDs ...string) App {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := App{
		ID: f.newID(3), Name: name, Domain: strings.ToLower(domain), Type: "self_hosted",
		PolicyIDs: policyIDs, CreatedAt: f.clock(), seq: f.reqSeq,
	}
	f.apps = append(f.apps, a)
	return a
}

// SeedServiceToken adds a service token without a request.
func (f *Fake) SeedServiceToken(name string) ServiceToken {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.clock()
	t := ServiceToken{
		ID: f.newID(5), Name: name, ClientID: f.newHexID(6) + ".access", ClientSecret: f.newHexID(7),
		CreatedAt: now, ExpiresAt: now.Add(8760 * time.Hour), seq: f.reqSeq,
	}
	f.tokens = append(f.tokens, t)
	return t
}

// RoutableWithoutAccess lists the hostnames that reach a tunnel through a
// proxied CNAME while no Access application with a policy covers them. A
// correct provisioning never makes this non-empty, at any moment.
func (f *Fake) RoutableWithoutAccess() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unprotected()
}

// EverRoutableWithoutAccess is every hostname RoutableWithoutAccess reported
// after any committed mutation so far: the invariant over time, not only now.
func (f *Fake) EverRoutableWithoutAccess() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.violations)
}

func (f *Fake) checkInvariant() {
	for _, name := range f.unprotected() {
		if !slices.Contains(f.violations, name) {
			f.violations = append(f.violations, name)
		}
	}
}

func (f *Fake) unprotected() []string {
	var out []string
	for _, r := range f.dns {
		if r.Type != "CNAME" || !r.Proxied || !strings.HasSuffix(r.Content, ".cfargotunnel.com") {
			continue
		}
		if !f.protected(r.Name) {
			out = append(out, r.Name)
		}
	}
	return out
}

func (f *Fake) protected(hostname string) bool {
	for _, a := range f.apps {
		if a.Domain == hostname && slices.ContainsFunc(a.PolicyIDs, f.policyExists) {
			return true
		}
	}
	return false
}

func (f *Fake) policyExists(id string) bool {
	return slices.ContainsFunc(f.policies, func(p Policy) bool { return p.ID == id })
}

// SeedIdentityProvider adds a login method of the given type ("onetimepin",
// "github", "oidc", ...) without a request.
func (f *Fake) SeedIdentityProvider(name, kind string) IdentityProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	idp := IdentityProvider{ID: f.newID(8), Name: name, Type: kind}
	f.idps = append(f.idps, idp)
	return idp
}

// ClearIdentityProviders removes every login method, one-time PIN included: an
// organisation where nothing was ever enabled.
func (f *Fake) ClearIdentityProviders() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idps = nil
}
