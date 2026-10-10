package netguard

import (
	"errors"
	"net/netip"
	"testing"
)

func TestPermit(t *testing.T) {
	provider := Allow{AllowAllPrivate: true}
	health := Allow{PrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}}
	everything := Allow{
		AllowAllPrivate: true,
		PrivateCIDRs:    []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("::1/128")},
	}
	var none Allow

	tests := []struct {
		name    string
		allow   Allow
		ip      string
		blocked bool
	}{
		// step 3: denied for every caller, whatever the allowlist says
		{"metadata v4", everything, "169.254.169.254", true},
		{"metadata ecs", everything, "169.254.170.2", true},
		{"metadata v6", everything, "fd00:ec2::254", true},
		{"this network", everything, "0.1.2.3", true},
		{"loopback v4", everything, "127.0.0.1", true},
		{"loopback v4 high", everything, "127.255.255.254", true},
		{"unspecified v6", everything, "::", true},
		{"loopback v6", everything, "::1", true},
		{"link-local v4", everything, "169.254.1.1", true},
		{"link-local v6", everything, "fe80::1", true},
		{"multicast v4", everything, "224.0.0.1", true},
		{"multicast v6", everything, "ff02::1", true},
		{"reserved", everything, "240.0.0.1", true},
		{"broadcast", everything, "255.255.255.255", true},

		// normalization: the embedded IPv4 decides
		{"mapped loopback", everything, "::ffff:127.0.0.1", true},
		{"mapped metadata", everything, "::ffff:169.254.169.254", true},
		{"compatible loopback", everything, "::127.0.0.1", true},
		{"compatible metadata", everything, "::169.254.169.254", true},
		{"nat64 loopback", everything, "64:ff9b::7f00:1", true},
		{"nat64 metadata", everything, "64:ff9b::a9fe:a9fe", true},
		{"nat64 private denied", none, "64:ff9b::a00:1", true},
		{"nat64 private provider", provider, "64:ff9b::a00:1", false},
		{"nat64 public", none, "64:ff9b::808:808", false},
		{"mapped private denied", none, "::ffff:10.0.0.1", true},
		{"mapped public", none, "::ffff:8.8.8.8", false},
		{"compatible public", none, "::8.8.8.8", false},
		{"zone is ignored", everything, "fe80::1%eth0", true},

		// step 4: private and special ranges need an allowlist
		{"10/8 denied", none, "10.0.0.1", true},
		{"172.16/12 denied", none, "172.16.5.5", true},
		{"172.32 is public", none, "172.32.0.1", false},
		{"192.168/16 denied", none, "192.168.1.1", true},
		{"cgnat denied", none, "100.64.0.1", true},
		{"ula denied", none, "fd12:3456::1", true},
		{"ietf protocol assignments", none, "192.0.0.8", true},
		{"benchmarking", none, "198.18.0.1", true},
		{"doc 1", none, "192.0.2.1", true},
		{"doc 2", none, "198.51.100.1", true},
		{"doc 3", none, "203.0.113.1", true},
		{"doc v6", none, "2001:db8::1", true},
		{"public v4", none, "8.8.8.8", false},
		{"public v6", none, "2606:4700:4700::1111", false},

		// step 5: allowlists by caller
		{"provider allows 10/8", provider, "10.0.0.1", false},
		{"provider allows ula", provider, "fd12:3456::1", false},
		{"provider allows doc range", provider, "192.0.2.1", false},
		{"health allows listed cidr", health, "10.1.2.3", false},
		{"health denies other private", health, "10.2.0.1", true},
		{"health denies other private 192", health, "192.168.0.1", true},
		{"health allowlist leaves public open", health, "8.8.8.8", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.allow.permit(netip.MustParseAddr(tt.ip))
			if tt.blocked != errors.Is(err, ErrBlocked) {
				t.Fatalf("permit(%s) = %v, want blocked=%v", tt.ip, err, tt.blocked)
			}
		})
	}
}
