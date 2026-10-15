package cffake

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
)

var paging = []string{"page", "per_page"}

func (f *Fake) routes() {
	acct := BasePath + "/accounts/{account}"
	f.handle(OpVerifyUser, "GET "+BasePath+"/user/tokens/verify", nil, f.verifyToken)
	f.handle(OpVerifyAccount, "GET "+acct+"/tokens/verify", nil, func(c *call) reply {
		if f.userToken {
			return fail(http.StatusForbidden, 1000, "Invalid API Token")
		}
		return f.verifyToken(c)
	})
	f.handle(OpZoneList, "GET "+BasePath+"/zones", append([]string{"name", "account.id"}, paging...), f.zoneList)

	f.handle(OpTunnelCreate, "POST "+acct+"/cfd_tunnel", nil, f.tunnelCreate)
	f.handle(OpTunnelList, "GET "+acct+"/cfd_tunnel", append([]string{"name", "is_deleted"}, paging...), f.tunnelList)
	f.handle(OpTunnelGet, "GET "+acct+"/cfd_tunnel/{id}", nil, f.tunnelGet)
	f.handle(OpTunnelDelete, "DELETE "+acct+"/cfd_tunnel/{id}", nil, f.tunnelDelete)
	f.handle(OpTunnelCleanup, "DELETE "+acct+"/cfd_tunnel/{id}/connections", nil, f.tunnelCleanup)
	f.handle(OpTunnelConfigPut, "PUT "+acct+"/cfd_tunnel/{id}/configurations", nil, f.configPut)
	f.handle(OpTunnelConfigGet, "GET "+acct+"/cfd_tunnel/{id}/configurations", nil, f.configGet)
	f.handle(OpTunnelToken, "GET "+acct+"/cfd_tunnel/{id}/token", nil, f.tunnelToken)

	zone := BasePath + "/zones/{zone}/dns_records"
	f.handle(OpDNSCreate, "POST "+zone, nil, f.dnsCreate)
	f.handle(OpDNSList, "GET "+zone, append([]string{"name", "type"}, paging...), f.dnsList)
	f.handle(OpDNSDelete, "DELETE "+zone+"/{id}", nil, f.dnsDelete)

	access := acct + "/access"
	f.handle(OpPolicyCreate, "POST "+access+"/policies", nil, func(c *call) reply { return f.policyWrite(c, "") })
	f.handle(OpPolicyList, "GET "+access+"/policies", paging, f.policyList)
	f.handle(OpPolicyUpdate, "PUT "+access+"/policies/{id}", nil, func(c *call) reply { return f.policyWrite(c, c.path("id")) })
	f.handle(OpPolicyDelete, "DELETE "+access+"/policies/{id}", nil, f.policyDelete)
	f.handle(OpAppCreate, "POST "+access+"/apps", nil, f.appCreate)
	f.handle(OpAppList, "GET "+access+"/apps", append([]string{"name", "exact"}, paging...), f.appList)
	f.handle(OpAppUpdate, "PUT "+access+"/apps/{id}", nil, func(c *call) reply { return f.appWrite(c, c.path("id")) })
	f.handle(OpAppDelete, "DELETE "+access+"/apps/{id}", nil, f.appDelete)
	f.handle(OpServiceTokenNew, "POST "+access+"/service_tokens", nil, f.serviceTokenCreate)
	f.handle(OpServiceTokenList, "GET "+access+"/service_tokens", append([]string{"name"}, paging...), f.serviceTokenList)
	f.handle(OpServiceTokenDel, "DELETE "+access+"/service_tokens/{id}", nil, f.serviceTokenDelete)
}

func notFound(code int, what string) reply { return fail(http.StatusNotFound, code, what+" not found") }

func stamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// listed pages a list of items already filtered and made visible.
func listed[T any](c *call, items []T, render func(T) any) reply {
	lo, hi, info, bad := c.paginate(len(items))
	if bad != nil {
		return *bad
	}
	out := make([]any, 0, hi-lo)
	for _, it := range items[lo:hi] {
		out = append(out, render(it))
	}
	return reply{status: http.StatusOK, result: out, info: info}
}

// --- token and zone ---

func (f *Fake) verifyToken(*call) reply {
	return ok(map[string]any{"id": "ffffffffffffffffffffffffffffffff", "status": "active", "not_before": nil, "expires_on": nil})
}

func (f *Fake) zoneList(c *call) reply {
	q := c.r.URL.Query()
	var zones []string
	if (q.Get("name") == "" || q.Get("name") == f.zone) && (q.Get("account.id") == "" || q.Get("account.id") == f.account) {
		zones = append(zones, f.zone)
	}
	return listed(c, zones, func(name string) any {
		return map[string]any{
			"id": f.zoneID, "name": name, "status": "active",
			"account": map[string]any{"id": f.account, "name": "cffake account"},
		}
	})
}

// --- tunnels ---

func tunnelJSON(t Tunnel) map[string]any {
	conns := make([]any, t.Connections)
	for i := range conns {
		conns[i] = map[string]any{"id": "c" + string(rune('0'+i%10)), "is_pending_reconnect": false}
	}
	status := "inactive"
	if t.Connections > 0 {
		status = "healthy"
	}
	return map[string]any{
		"id": t.ID, "name": t.Name, "created_at": stamp(t.CreatedAt), "deleted_at": stamp(t.DeletedAt),
		"status": status, "config_src": t.ConfigSrc, "remote_config": t.ConfigSrc == "cloudflare", "connections": conns,
	}
}

func (f *Fake) tunnelByID(id string) *Tunnel {
	for i := range f.tunnels {
		if f.tunnels[i].ID == id {
			return &f.tunnels[i]
		}
	}
	return nil
}

func (f *Fake) tunnelCreate(c *call) reply {
	var in struct {
		Name         string `json:"name"`
		ConfigSrc    string `json:"config_src"`
		TunnelSecret string `json:"tunnel_secret"`
	}
	if bad := c.decode(&in); bad != nil {
		return *bad
	}
	if in.Name == "" || !slices.Contains([]string{"", "cloudflare", "local"}, in.ConfigSrc) {
		return fail(http.StatusBadRequest, 1001, "invalid tunnel")
	}
	for _, t := range f.tunnels {
		if t.DeletedAt.IsZero() && t.Name == in.Name {
			return fail(http.StatusConflict, 1013, "You already have a tunnel with this name")
		}
	}
	src := in.ConfigSrc
	if src == "" {
		src = "local"
	}
	t := Tunnel{ID: f.newID(1), Name: in.Name, ConfigSrc: src, CreatedAt: f.clock(), seq: f.reqSeq}
	f.tunnels = append(f.tunnels, t)
	return ok(tunnelJSON(t))
}

func (f *Fake) tunnelList(c *call) reply {
	q := c.r.URL.Query()
	var items []Tunnel
	for _, t := range f.tunnels {
		switch {
		case !f.visible(t.seq):
		case q.Get("name") != "" && t.Name != q.Get("name"):
		case q.Get("is_deleted") == "false" && !t.DeletedAt.IsZero():
		case q.Get("is_deleted") == "true" && t.DeletedAt.IsZero():
		default:
			items = append(items, t)
		}
	}
	return listed(c, items, func(t Tunnel) any { return tunnelJSON(t) })
}

func (f *Fake) tunnelGet(c *call) reply {
	t := f.tunnelByID(c.path("id"))
	if t == nil {
		return notFound(1003, "tunnel")
	}
	return ok(tunnelJSON(*t))
}

func (f *Fake) liveTunnel(c *call) *Tunnel {
	if t := f.tunnelByID(c.path("id")); t != nil && t.DeletedAt.IsZero() {
		return t
	}
	return nil
}

func (f *Fake) tunnelDelete(c *call) reply {
	t := f.liveTunnel(c)
	switch {
	case t == nil:
		return notFound(1003, "tunnel")
	case t.Connections > 0:
		return fail(http.StatusBadRequest, 1022, "Cannot delete tunnel with active connections")
	}
	t.DeletedAt = f.clock()
	return ok(tunnelJSON(*t))
}

func (f *Fake) tunnelCleanup(c *call) reply {
	t := f.liveTunnel(c)
	if t == nil {
		return notFound(1003, "tunnel")
	}
	t.Connections = 0
	return ok(nil)
}

type wireIngress struct {
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service"`
}

func (f *Fake) configPut(c *call) reply {
	t := f.liveTunnel(c)
	if t == nil {
		return notFound(1003, "tunnel")
	}
	var in struct {
		Config struct {
			Ingress []wireIngress `json:"ingress"`
		} `json:"config"`
	}
	if bad := c.decode(&in); bad != nil {
		return *bad
	}
	rules := in.Config.Ingress
	if t.ConfigSrc != "cloudflare" || len(rules) == 0 || rules[len(rules)-1].Hostname != "" || rules[len(rules)-1].Service == "" {
		return fail(http.StatusBadRequest, 1015, "The last ingress rule must be a catch-all rule")
	}
	var stored []Ingress
	for i, r := range rules {
		if i < len(rules)-1 && (r.Hostname == "" || r.Service == "") {
			return fail(http.StatusBadRequest, 1015, "Only the last ingress rule may omit the hostname")
		}
		stored = append(stored, Ingress{Hostname: strings.ToLower(r.Hostname), Service: r.Service})
	}
	t.Ingress, t.Configured = stored, true
	t.ConfigVersion++
	return ok(configJSON(*t))
}

func configJSON(t Tunnel) map[string]any {
	var config any
	if t.Configured {
		rules := make([]wireIngress, 0, len(t.Ingress))
		for _, r := range t.Ingress {
			rules = append(rules, wireIngress(r))
		}
		config = map[string]any{"ingress": rules}
	}
	return map[string]any{"tunnel_id": t.ID, "version": t.ConfigVersion, "config": config, "source": "cloudflare", "created_at": stamp(t.CreatedAt)}
}

func (f *Fake) configGet(c *call) reply {
	t := f.liveTunnel(c)
	if t == nil {
		return notFound(1003, "tunnel")
	}
	return ok(configJSON(*t))
}

func (f *Fake) tunnelToken(c *call) reply {
	t := f.liveTunnel(c)
	if t == nil {
		return notFound(1003, "tunnel")
	}
	doc, _ := json.Marshal(map[string]string{"a": f.account, "t": t.ID, "s": "c2VjcmV0LW9mLQ" + t.ID})
	return ok(base64.StdEncoding.EncodeToString(doc))
}

// --- DNS ---

func dnsJSON(zoneID, zoneName string, r DNSRecord) map[string]any {
	return map[string]any{
		"id": r.ID, "zone_id": zoneID, "zone_name": zoneName, "name": r.Name, "type": r.Type, "content": r.Content,
		"proxied": r.Proxied, "ttl": 1, "comment": r.Comment, "created_on": stamp(r.CreatedOn),
	}
}

func (f *Fake) zoneMissing(c *call) *reply {
	if c.path("zone") == f.zoneID {
		return nil
	}
	r := notFound(7003, "zone")
	return &r
}

func (f *Fake) dnsCreate(c *call) reply {
	if bad := f.zoneMissing(c); bad != nil {
		return *bad
	}
	var in struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		Proxied bool   `json:"proxied"`
		TTL     int    `json:"ttl"`
		Comment string `json:"comment"`
	}
	if bad := c.decode(&in); bad != nil {
		return *bad
	}
	name := strings.ToLower(in.Name)
	if in.Type != "CNAME" || in.Content == "" || (name != f.zone && !strings.HasSuffix(name, "."+f.zone)) {
		return fail(http.StatusBadRequest, 9005, "invalid DNS record")
	}
	for _, r := range f.dns {
		if r.Name == name {
			return fail(http.StatusBadRequest, 81057, "The record already exists.")
		}
	}
	r := DNSRecord{
		ID: f.newHexID(4), Name: name, Type: in.Type, Content: strings.ToLower(in.Content), Proxied: in.Proxied,
		Comment: in.Comment, CreatedOn: f.clock(), seq: f.reqSeq,
	}
	f.dns = append(f.dns, r)
	return ok(dnsJSON(f.zoneID, f.zone, r))
}

func (f *Fake) dnsList(c *call) reply {
	if bad := f.zoneMissing(c); bad != nil {
		return *bad
	}
	q := c.r.URL.Query()
	var items []DNSRecord
	for _, r := range f.dns {
		if f.visible(r.seq) && (q.Get("name") == "" || r.Name == strings.ToLower(q.Get("name"))) && (q.Get("type") == "" || r.Type == q.Get("type")) {
			items = append(items, r)
		}
	}
	return listed(c, items, func(r DNSRecord) any { return dnsJSON(f.zoneID, f.zone, r) })
}

func (f *Fake) dnsDelete(c *call) reply {
	if bad := f.zoneMissing(c); bad != nil {
		return *bad
	}
	for i, r := range f.dns {
		if r.ID == c.path("id") {
			f.dns = slices.Delete(f.dns, i, i+1)
			return ok(map[string]any{"id": r.ID})
		}
	}
	return notFound(81044, "record")
}

// --- Access policies ---

func policyJSON(p Policy) map[string]any {
	include := []any{}
	for _, id := range p.ServiceTokenIDs {
		include = append(include, map[string]any{"service_token": map[string]any{"token_id": id}})
	}
	for _, e := range p.Emails {
		include = append(include, map[string]any{"email": map[string]any{"email": e}})
	}
	return map[string]any{
		"id": p.ID, "name": p.Name, "decision": p.Decision, "include": include, "exclude": []any{}, "require": []any{},
		"reusable": true, "created_at": stamp(p.CreatedAt),
	}
}

// policyWrite creates a policy (id "") or replaces one.
func (f *Fake) policyWrite(c *call, id string) reply {
	var in struct {
		Name     string                         `json:"name"`
		Decision string                         `json:"decision"`
		Include  []map[string]map[string]string `json:"include"`
	}
	if bad := c.decode(&in); bad != nil {
		return *bad
	}
	p := Policy{Name: in.Name, Decision: in.Decision}
	for _, rule := range in.Include {
		if email, found := rule["email"]; found && len(rule) == 1 && in.Decision == "allow" && email["email"] != "" {
			p.Emails = append(p.Emails, strings.ToLower(email["email"]))
		} else if tok, found := rule["service_token"]; found && len(rule) == 1 && in.Decision == "non_identity" && tok["token_id"] != "" {
			if !slices.ContainsFunc(f.tokens, func(t ServiceToken) bool { return t.ID == tok["token_id"] }) {
				return fail(http.StatusBadRequest, 12130, "service token does not exist")
			}
			p.ServiceTokenIDs = append(p.ServiceTokenIDs, tok["token_id"])
		} else {
			return fail(http.StatusBadRequest, 12130, "include rule does not fit the decision")
		}
	}
	if in.Name == "" || len(in.Include) == 0 || !slices.Contains([]string{"allow", "non_identity"}, in.Decision) {
		return fail(http.StatusBadRequest, 12130, "invalid policy")
	}
	if id == "" {
		p.ID, p.CreatedAt, p.seq = f.newID(2), f.clock(), f.reqSeq
		f.policies = append(f.policies, p)
		return ok(policyJSON(p))
	}
	for i := range f.policies {
		if f.policies[i].ID == id {
			p.ID, p.CreatedAt, p.seq = id, f.policies[i].CreatedAt, f.policies[i].seq
			f.policies[i] = p
			return ok(policyJSON(p))
		}
	}
	return notFound(12130, "policy")
}

func (f *Fake) policyList(c *call) reply {
	var items []Policy
	for _, p := range f.policies {
		if f.visible(p.seq) {
			items = append(items, p)
		}
	}
	return listed(c, items, func(p Policy) any { return policyJSON(p) })
}

func (f *Fake) policyDelete(c *call) reply {
	id := c.path("id")
	for _, a := range f.apps {
		if slices.Contains(a.PolicyIDs, id) {
			return fail(http.StatusConflict, 12130, "policy is attached to an application")
		}
	}
	for i, p := range f.policies {
		if p.ID == id {
			f.policies = slices.Delete(f.policies, i, i+1)
			return ok(map[string]any{"id": id})
		}
	}
	return notFound(12130, "policy")
}

// --- Access applications ---

func appJSON(a App) map[string]any {
	policies := []any{}
	for i, id := range a.PolicyIDs {
		policies = append(policies, map[string]any{"id": id, "precedence": i + 1})
	}
	return map[string]any{
		"id": a.ID, "aud": "aud-" + a.ID, "name": a.Name, "domain": a.Domain, "type": a.Type,
		"policies": policies, "allowed_idps": a.AllowedIdPs, "session_duration": "24h", "created_at": stamp(a.CreatedAt),
	}
}

func (f *Fake) appCreate(c *call) reply { return f.appWrite(c, "") }

// appWrite creates an application (id "") or replaces one.
func (f *Fake) appWrite(c *call, id string) reply {
	var in struct {
		Name               string `json:"name"`
		Domain             string `json:"domain"`
		Type               string `json:"type"`
		SessionDuration    string `json:"session_duration"`
		AppLauncherVisible bool   `json:"app_launcher_visible"`
		Policies           []struct {
			ID         string `json:"id"`
			Precedence int    `json:"precedence"`
		} `json:"policies"`
		AllowedIdPs []string `json:"allowed_idps"`
	}
	if bad := c.decode(&in); bad != nil {
		return *bad
	}
	domain := strings.ToLower(in.Domain)
	if in.Name == "" || domain == "" || in.Type != "self_hosted" {
		return fail(http.StatusBadRequest, 12130, "invalid application")
	}
	a := App{Name: in.Name, Domain: domain, Type: in.Type, AllowedIdPs: in.AllowedIdPs, CreatedAt: f.clock(), seq: f.reqSeq}
	for _, p := range in.Policies {
		if !f.policyExists(p.ID) {
			return fail(http.StatusBadRequest, 12130, "policy does not exist")
		}
		a.PolicyIDs = append(a.PolicyIDs, p.ID)
	}
	existing := slices.IndexFunc(f.apps, func(other App) bool { return other.ID == id })
	if id != "" && existing < 0 {
		return notFound(12130, "application")
	}
	for _, other := range f.apps {
		if other.Domain == domain && other.ID != id {
			return fail(http.StatusConflict, 12130, "An application with this domain already exists")
		}
	}
	if id != "" {
		a.ID, a.CreatedAt, a.seq = id, f.apps[existing].CreatedAt, f.apps[existing].seq
		f.apps[existing] = a
		return ok(appJSON(a))
	}
	a.ID = f.newID(3)
	f.apps = append(f.apps, a)
	return ok(appJSON(a))
}

func (f *Fake) appList(c *call) reply {
	q := c.r.URL.Query()
	var items []App
	for _, a := range f.apps {
		name := q.Get("name")
		matches := name == "" || a.Name == name || (q.Get("exact") != "true" && strings.Contains(strings.ToLower(a.Name), strings.ToLower(name)))
		if f.visible(a.seq) && matches {
			items = append(items, a)
		}
	}
	return listed(c, items, func(a App) any { return appJSON(a) })
}

func (f *Fake) appDelete(c *call) reply {
	for i, a := range f.apps {
		if a.ID == c.path("id") {
			f.apps = slices.Delete(f.apps, i, i+1)
			return ok(map[string]any{"id": a.ID})
		}
	}
	return notFound(12130, "application")
}

// --- service tokens ---

func tokenJSON(t ServiceToken, withSecret bool) map[string]any {
	doc := map[string]any{
		"id": t.ID, "name": t.Name, "client_id": t.ClientID, "created_at": stamp(t.CreatedAt),
		"updated_at": stamp(t.CreatedAt), "expires_at": stamp(t.ExpiresAt), "duration": "8760h",
	}
	if withSecret {
		doc["client_secret"] = t.ClientSecret
	}
	return doc
}

func (f *Fake) serviceTokenCreate(c *call) reply {
	var in struct {
		Name     string `json:"name"`
		Duration string `json:"duration"`
	}
	if bad := c.decode(&in); bad != nil {
		return *bad
	}
	d, err := time.ParseDuration(in.Duration)
	if in.Name == "" || err != nil || d <= 0 {
		return fail(http.StatusBadRequest, 12130, "invalid service token")
	}
	now := f.clock()
	t := ServiceToken{
		ID: f.newID(5), Name: in.Name, ClientID: f.newHexID(6) + ".access", ClientSecret: f.newHexID(7) + f.newHexID(7),
		CreatedAt: now, ExpiresAt: now.Add(d), seq: f.reqSeq,
	}
	f.tokens = append(f.tokens, t)
	return ok(tokenJSON(t, true))
}

func (f *Fake) serviceTokenList(c *call) reply {
	name := strings.ToLower(c.r.URL.Query().Get("name"))
	var items []ServiceToken
	for _, t := range f.tokens {
		if f.visible(t.seq) && strings.Contains(strings.ToLower(t.Name), name) {
			items = append(items, t)
		}
	}
	return listed(c, items, func(t ServiceToken) any { return tokenJSON(t, false) })
}

func (f *Fake) serviceTokenDelete(c *call) reply {
	for i, t := range f.tokens {
		if t.ID == c.path("id") {
			f.tokens = slices.Delete(f.tokens, i, i+1)
			return ok(tokenJSON(t, false))
		}
	}
	return notFound(12130, "service token")
}
