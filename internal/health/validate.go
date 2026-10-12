package health

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/autarquico/supermgmt/internal/deployments/compose"
)

var checkPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,255}$`)

const (
	maxCheckTimeout = 60 * time.Second
	protoTCP        = "tcp"
)

// ValidateManifest accepts a repository-manifest check and returns where a
// node-scope check connects: the published host port on exactly 127.0.0.1 or
// ::1 that the check names. docker-health has no destination and returns the
// zero Destination.
func ValidateManifest(c Check, ports []compose.HostPort) (Destination, error) {
	if c.Origin != OriginManifest {
		return Destination{}, fmt.Errorf("health: origin %q is not %q", c.Origin, OriginManifest)
	}
	return validateNodeCheck(c, ports, nil)
}

// ValidateControlPlane accepts a control-plane check. A node-scope check may
// also target a port published on an entry of allowedBind; a control_plane
// scope check is validated as a URL and returns the zero Destination (its
// address is vetted by netguard when it runs).
func ValidateControlPlane(c Check, ports []compose.HostPort, allowedBind []netip.Addr) (Destination, error) {
	if c.Origin != OriginControlPlane {
		return Destination{}, fmt.Errorf("health: origin %q is not %q", c.Origin, OriginControlPlane)
	}
	if c.Scope == ScopeControlPlane {
		_, err := controlPlaneURL(c)
		return Destination{}, err
	}
	return validateNodeCheck(c, ports, allowedBind)
}

func validateNodeCheck(c Check, ports []compose.HostPort, allowedBind []netip.Addr) (Destination, error) {
	if c.Scope != ScopeNode {
		return Destination{}, fmt.Errorf("health: scope %q, want %q", c.Scope, ScopeNode)
	}
	if c.URL != "" {
		return Destination{}, errors.New("health: a node-scope check takes a port and path, never a URL or hostname")
	}
	if err := checkTimeout(c.Timeout); err != nil {
		return Destination{}, err
	}
	switch c.Type {
	case TypeDockerHealth:
		return Destination{}, nil
	case TypeHTTP:
		if !checkPathPattern.MatchString(c.Path) {
			return Destination{}, errors.New("health: path must match ^/[A-Za-z0-9._~/-]*$ (no query, fragment or userinfo)")
		}
	case TypeTCP:
	default:
		return Destination{}, fmt.Errorf("health: node-scope type %q is not supported", c.Type)
	}
	return publishedDestination(c.Port, ports, allowedBind)
}

// publishedDestination picks the first published tcp port that matches and is
// bound to a loopback address or an allowed bind address, in model order.
func publishedDestination(port uint16, ports []compose.HostPort, allowedBind []netip.Addr) (Destination, error) {
	if port == 0 {
		return Destination{}, errors.New("health: port is required")
	}
	for _, hp := range ports {
		if hp.Port == port && hp.Proto == protoTCP && approvedAddr(hp.Addr, allowedBind) {
			return Destination{Addr: hp.Addr, Port: port}, nil
		}
	}
	return Destination{}, fmt.Errorf("health: port %d is not published by the frozen model on an approved address", port)
}

func approvedAddr(a netip.Addr, allowedBind []netip.Addr) bool {
	if a == netip.MustParseAddr("127.0.0.1") || a == netip.IPv6Loopback() {
		return true
	}
	for _, b := range allowedBind {
		if a == b {
			return true
		}
	}
	return false
}

func checkTimeout(d time.Duration) error {
	if d < time.Second || d > maxCheckTimeout || d%time.Second != 0 {
		return fmt.Errorf("health: timeout %s must be whole seconds in 1..%d", d, int(maxCheckTimeout/time.Second))
	}
	return nil
}

// controlPlaneURL parses a control_plane-scope check: http or https matching
// the type, a host, no userinfo, query or fragment.
func controlPlaneURL(c Check) (*url.URL, error) {
	if c.Type != TypeHTTP && c.Type != TypeHTTPS {
		return nil, fmt.Errorf("health: control_plane-scope type %q is not supported", c.Type)
	}
	if err := checkTimeout(c.Timeout); err != nil {
		return nil, err
	}
	u, err := url.Parse(c.URL)
	switch {
	case err != nil:
		return nil, errors.New("health: URL is not valid")
	case u.Scheme != c.Type:
		return nil, fmt.Errorf("health: URL scheme %q does not match type %q", u.Scheme, c.Type)
	case u.Hostname() == "":
		return nil, errors.New("health: URL has no host")
	case u.User != nil:
		return nil, errors.New("health: URL userinfo is not allowed")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "":
		return nil, errors.New("health: URL query and fragment are not allowed")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("health: URL port is not valid")
		}
	}
	return u, nil
}
