package domain_test

import (
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func TestTransportAbsentMeansDirect(t *testing.T) {
	if got := domain.Transport("").Effective(); got != domain.TransportDirect {
		t.Errorf("absent transport = %q, want direct", got)
	}
	if !(domain.NodeEndpoint{}).Transport.Valid() {
		t.Error("absent transport must be valid (old rows)")
	}
	if _, err := domain.ParseTransport("wireguard"); err == nil {
		t.Error("ParseTransport accepted wireguard")
	}
}

func TestEndpointValidateTunnelFields(t *testing.T) {
	cases := map[string]struct {
		endpoint domain.NodeEndpoint
		ok       bool
	}{
		"old row":                 {domain.NodeEndpoint{Host: "10.0.0.1"}, true},
		"direct":                  {domain.NodeEndpoint{Transport: domain.TransportDirect}, true},
		"cloudflare":              {domain.NodeEndpoint{Transport: domain.TransportCloudflare, TunnelHostname: "ssh-web1.example.com"}, true},
		"unknown transport":       {domain.NodeEndpoint{Transport: "wireguard"}, false},
		"cloudflare no hostname":  {domain.NodeEndpoint{Transport: domain.TransportCloudflare}, false},
		"hostile hostname":        {domain.NodeEndpoint{Transport: domain.TransportCloudflare, TunnelHostname: "a;b.example.com"}, false},
		"hostname on direct node": {domain.NodeEndpoint{Transport: domain.TransportDirect, TunnelHostname: "%h.example.com"}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := c.endpoint.Validate(); (err == nil) != c.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

func TestValidateDNSName(t *testing.T) {
	label49 := strings.Repeat("a", 49)
	valid := []string{
		"ssh-web1.example.com", "a.b", "x1.example.co.uk", strings.Repeat("a", 63) + ".com",
		strings.Repeat(label49+".", 5) + "com", // 248 + 3 = 253 characters
	}
	for _, name := range valid {
		if err := domain.ValidateDNSName(name); err != nil {
			t.Errorf("ValidateDNSName(%q) = %v, want ok", name, err)
		}
	}
	invalid := map[string]string{
		"empty":           "",
		"semicolon":       "a;b.example.com",
		"percent":         "%h.example.com",
		"leading hyphen":  "-x.example.com",
		"hyphen option":   "-oProxyCommand=x.example.com",
		"trailing hyphen": "x-.example.com",
		"space":           "a b.example.com",
		"tab":             "a\tb.example.com",
		"newline":         "a.example.com\nHost *",
		"uppercase":       "Web1.Example.com",
		"single label":    "localhost",
		"trailing dot":    "web1.example.com.",
		"empty label":     "a..example.com",
		"leading dot":     ".example.com",
		"underscore":      "a_b.example.com",
		"dollar":          "$(id).example.com",
		"backtick":        "`id`.example.com",
		"quote":           "a'b.example.com",
		"unicode":         "café.example.com",
		"ip literal":      "10.0.0.1",
		"label too long":  strings.Repeat("a", 64) + ".com",
		"name too long":   strings.Repeat(label49+".", 5) + "comm", // 254 characters
		"slash":           "a/b.example.com",
		"colon port":      "web1.example.com:22",
		"user at":         "root@web1.example.com",
		"wildcard":        "*.example.com",
		"numeric last":    "web1.123",
		"null byte":       "a\x00.example.com",
	}
	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := domain.ValidateDNSName(input); err == nil {
				t.Errorf("ValidateDNSName(%q) accepted", input)
			}
		})
	}
}
