package netguard

import (
	"fmt"
	"net/netip"
)

// alwaysDenied is §21.1 step 3: no allowlist can open these.
var alwaysDenied = prefixes(
	"169.254.169.254/32", "fd00:ec2::254/128", "169.254.170.2/32",
	"0.0.0.0/8", "127.0.0.0/8", "::/128", "::1/128",
	"169.254.0.0/16", "fe80::/10",
	"224.0.0.0/4", "ff00::/8", "240.0.0.0/4", "255.255.255.255/32",
)

// specialRanges is §21.1 step 4: denied unless the caller allows them.
var specialRanges = prefixes(
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	"fc00::/7", "192.0.0.0/24", "198.18.0.0/15",
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
)

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func prefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

func containedIn(set []netip.Prefix, ip netip.Addr) bool {
	for _, p := range set {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// normalize unwraps the encodings that carry an IPv4 address inside an IPv6
// one: IPv4-mapped, IPv4-compatible (::/96) and NAT64 (64:ff9b::/96).
func normalize(ip netip.Addr) netip.Addr {
	ip = ip.WithZone("").Unmap()
	if !ip.Is6() {
		return ip
	}
	b := ip.As16()
	if nat64.Contains(ip) || isZero(b[:12]) {
		return netip.AddrFrom4([4]byte(b[12:]))
	}
	return ip
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// permit reports why ip may not be dialed, or nil. Always-denied ranges are
// checked, on the address as given and as normalized, before any allowlist.
func (a Allow) permit(ip netip.Addr) error {
	raw := ip.WithZone("").Unmap()
	norm := normalize(ip)
	if containedIn(alwaysDenied, raw) || containedIn(alwaysDenied, norm) {
		return fmt.Errorf("%w: %s is in an always-denied range", ErrBlocked, norm)
	}
	if containedIn(specialRanges, norm) && !a.AllowAllPrivate && !containedIn(a.PrivateCIDRs, norm) {
		return fmt.Errorf("%w: %s is private and not allowed", ErrBlocked, norm)
	}
	return nil
}
