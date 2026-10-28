package cloudflare

import (
	"strings"
	"testing"
	"unicode"

	"github.com/autarquico/supermgmt/internal/audit"
)

const (
	tunnelDoc = `{"id":"7b0a9d5e-0000-4000-8000-000000000001","name":"sm-i-n","created_at":"2026-01-01T00:00:00Z","deleted_at":null,` +
		`"status":"healthy","config_src":"cloudflare","remote_config":true,"connections":[{"id":"c1"}]}`
	configDoc = `{"tunnel_id":"7b0a9d5e-0000-4000-8000-000000000001","version":3,"source":"cloudflare",` +
		`"config":{"ingress":[{"hostname":"ssh-a.example.com","service":"ssh://localhost:22"},{"service":"http_status:404"}]}}`
	dnsDoc = `{"id":"0123456789abcdef0123456789abcdef","name":"SSH-A.example.com","type":"CNAME","content":"x.cfargotunnel.com",` +
		`"proxied":true,"comment":"supermgmt:i:n","created_on":"2026-01-01T00:00:00.123Z"}`
	zoneDoc   = `{"id":"fedcba9876543210fedcba9876543210","name":"Example.com","status":"active","account":{"id":"0123456789abcdef0123456789abcdef"}}`
	appDoc    = `{"id":"a-1","name":"supermgmt i n","domain":"ssh-a.example.com","type":"self_hosted","policies":[{"id":"p-1","precedence":1},"p-2"],"allowed_idps":["idp-1"],"created_at":"2026-01-01T00:00:00Z"}`
	policyDoc = `{"id":"p-1","name":"owners","decision":"allow","created_at":"2026-01-01T00:00:00Z",` +
		`"include":[{"email":{"email":"O@Example.com"}},{"service_token":{"token_id":"t-1"}},{"everyone":{}},{"email":{"email":"a@b.c"},"x":1}]}`
	tokenDoc  = `{"id":"t-1","name":"supermgmt-i","client_id":"abc.access","client_secret":"s3cr3t","created_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z"}`
	verifyDoc = `{"id":"ffffffffffffffffffffffffffffffff","status":"active","not_before":null,"expires_on":"2027-01-01T00:00:00Z"}`
)

func addSeeds(f *testing.F, docs ...string) {
	for _, d := range docs {
		f.Add([]byte(d))
		f.Add([]byte("[" + d + "," + d + "]"))
	}
	for _, junk := range []string{``, `null`, `[]`, `{}`, `[null]`, `"x"`, `{"id":""}`, `[`, `{"id":"a","name":"\u0000"}`, `[{"id":1}]`} {
		f.Add([]byte(junk))
	}
}

// The wrapper is the first thing every answer meets: any bytes decode to an
// envelope or an error, and what the client would show of its errors is clean.
func FuzzDecodeEnvelope(f *testing.F) {
	f.Add([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"x"},"result_info":{"page":1,"per_page":20,"count":1,"total_count":1,"total_pages":1}}`))
	f.Add([]byte(`{"success":false,"errors":[{"code":1013,"message":"tok-secret \u001b[31m taken"},{"code":2,"message":"b"}],"result":null}`))
	addSeeds(f)
	c := &Client{token: "tok-secret"}
	f.Fuzz(func(t *testing.T, body []byte) {
		env, err := decodeEnvelope(body)
		if err != nil {
			if env.Success || env.Result != nil {
				t.Fatalf("envelope %+v returned with error %v", env, err)
			}
			return
		}
		e := c.failure(400, env, false)
		if strings.Contains(e.Message, "tok-secret") || strings.ContainsFunc(e.Message, unicode.IsControl) || len([]rune(e.Message)) > maxMessageLen {
			t.Fatalf("unsafe message %q", e.Message)
		}
	})
}

func FuzzDecodeTunnel(f *testing.F) {
	addSeeds(f, tunnelDoc, configDoc, `"eyJhIjoiMSJ9"`)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if tun, err := decodeTunnel(raw); err == nil && (!validID(tun.ID) || !cleanName(tun.Name)) {
			t.Fatalf("malformed tunnel accepted: %+v", tun)
		}
		if list, err := decodeTunnels(raw); err == nil {
			for _, tun := range list {
				if !validID(tun.ID) || !cleanName(tun.Name) {
					t.Fatalf("malformed tunnel accepted: %+v", tun)
				}
			}
		}
		if cfg, err := decodeTunnelConfig(raw); err == nil && (!validID(cfg.TunnelID) || cfg.Version < 0) {
			t.Fatalf("malformed config accepted: %+v", cfg)
		}
		if token, err := decodeTunnelToken(raw); err == nil && (token == "" || strings.ContainsFunc(token.Reveal(), unicode.IsSpace)) {
			t.Fatalf("malformed token accepted: %q", token.String())
		}
	})
}

func FuzzDecodeDNS(f *testing.F) {
	addSeeds(f, dnsDoc, zoneDoc)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if rec, err := decodeDNSRecord(raw); err == nil && (!validID(rec.ID) || rec.Name != strings.ToLower(rec.Name)) {
			t.Fatalf("malformed record accepted: %+v", rec)
		}
		if list, err := decodeDNSRecords(raw); err == nil {
			for _, rec := range list {
				if !validID(rec.ID) || strings.ContainsFunc(rec.Comment, unicode.IsControl) {
					t.Fatalf("malformed record accepted: %+v", rec)
				}
			}
		}
		if zones, err := decodeZones(raw); err == nil {
			for _, z := range zones {
				if !validID(z.ID) || z.Name != strings.ToLower(z.Name) {
					t.Fatalf("malformed zone accepted: %+v", z)
				}
			}
		}
	})
}

func FuzzDecodeIdentityProviders(f *testing.F) {
	addSeeds(f, `{"id":"idp-1","name":"One-time PIN","type":"onetimepin"}`)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if list, err := decodeIdentityProviders(raw); err == nil {
			for _, p := range list {
				if !validID(p.ID) || p.Type == "" {
					t.Fatalf("malformed identity provider accepted: %+v", p)
				}
			}
		}
	})
}

func FuzzDecodeAccessApp(f *testing.F) {
	addSeeds(f, appDoc)
	f.Fuzz(func(t *testing.T, raw []byte) {
		check := func(a AccessApp) {
			if !validID(a.ID) || !cleanName(a.Name) || a.Domain != strings.ToLower(a.Domain) {
				t.Fatalf("malformed application accepted: %+v", a)
			}
			for _, id := range append(a.PolicyIDs[:len(a.PolicyIDs):len(a.PolicyIDs)], a.AllowedIdPs...) {
				if !validID(id) {
					t.Fatalf("malformed reference %q in %+v", id, a)
				}
			}
		}
		if a, err := decodeAccessApp(raw); err == nil {
			check(a)
		}
		if list, err := decodeAccessApps(raw); err == nil {
			for _, a := range list {
				check(a)
			}
		}
	})
}

// A policy is judged by its include rules: whatever is not an email or a
// service token must be counted, never dropped, so a widened policy shows.
func FuzzDecodeAccessPolicy(f *testing.F) {
	addSeeds(f, policyDoc)
	f.Fuzz(func(t *testing.T, raw []byte) {
		check := func(p AccessPolicy) {
			if !validID(p.ID) || !cleanName(p.Name) || p.UnknownRules < 0 {
				t.Fatalf("malformed policy accepted: %+v", p)
			}
			for _, e := range p.Emails {
				if e != strings.ToLower(e) || !cleanName(e) {
					t.Fatalf("malformed email %q", e)
				}
			}
		}
		if p, err := decodeAccessPolicy(raw); err == nil {
			check(p)
		}
		if list, err := decodeAccessPolicies(raw); err == nil {
			for _, p := range list {
				check(p)
			}
		}
	})
}

func FuzzDecodeServiceToken(f *testing.F) {
	addSeeds(f, tokenDoc, verifyDoc)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if tok, err := decodeServiceToken(raw); err == nil {
			if !validID(tok.ID) || !validID(tok.ClientID) || tok.ClientSecret.String() != audit.Redacted {
				t.Fatalf("malformed token accepted: %+v", tok.ServiceToken)
			}
		}
		if list, err := decodeServiceTokens(raw); err == nil {
			for _, tok := range list {
				if !validID(tok.ID) || !validID(tok.ClientID) {
					t.Fatalf("malformed token accepted: %+v", tok)
				}
			}
		}
		if info, err := decodeTokenInfo(raw); err == nil && (!validID(info.ID) || !cleanName(info.Status)) {
			t.Fatalf("malformed verification accepted: %+v", info)
		}
	})
}

// The base URL decides where the bearer token goes: whatever parses is https,
// has a host, and carries no userinfo, query or fragment.
func FuzzParseBaseURL(f *testing.F) {
	for _, s := range []string{DefaultBaseURL, "https://127.0.0.1:8443/x", "http://a", "https://u:p@a", "https://a/b/", "https://a?q", "", "://", "https://[::1]/%zz"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := parseBaseURL(raw)
		if err == nil && (u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(u.Path, "/")) {
			t.Fatalf("parseBaseURL(%q) = %v", raw, u)
		}
	})
}
