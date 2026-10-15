package domain

import (
	"fmt"
	"slices"
	"strings"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Transport is how the control plane reaches a node's SSH port (ADR-0037).
// The empty value is stored on rows written before the field existed and
// means TransportDirect.
type Transport string

const (
	TransportDirect     Transport = "direct"
	TransportCloudflare Transport = "cloudflare"
)

func AllTransports() []Transport { return []Transport{TransportDirect, TransportCloudflare} }

func ParseTransport(s string) (Transport, error) { return parseEnum("transport", AllTransports(), s) }

// Valid reports whether t is stored-form: a known transport or absent.
func (t Transport) Valid() bool { return t == "" || slices.Contains(AllTransports(), t) }

// Effective resolves the absent value to direct.
func (t Transport) Effective() Transport {
	if t == "" {
		return TransportDirect
	}
	return t
}

// Validate checks the tunnel fields of an endpoint. tunnel_hostname reaches
// process argv and OpenSSH option expansion, so it is held to strict DNS
// labels; a cloudflare endpoint cannot be dialled without one.
func (e NodeEndpoint) Validate() error {
	if !e.Transport.Valid() {
		return invalidEndpoint("unknown transport %q", string(e.Transport))
	}
	if e.TunnelHostname != "" {
		if err := ValidateDNSName(e.TunnelHostname); err != nil {
			return invalidEndpoint("tunnel_hostname: %v", err)
		}
	}
	if e.Transport == TransportCloudflare && e.TunnelHostname == "" {
		return invalidEndpoint("transport cloudflare needs a tunnel_hostname")
	}
	return nil
}

func invalidEndpoint(format string, args ...any) error {
	return smerr.New(smerr.CodeInvalidArgument, "", "invalid node endpoint: "+fmt.Sprintf(format, args...))
}

const (
	maxDNSNameLen  = 253
	maxDNSLabelLen = 63
)

// ValidateDNSName accepts a lowercase, fully qualified name of at least two
// LDH labels (letters, digits, inner hyphens; 1-63 characters each; 253 in
// all), no trailing dot and a non-numeric last label (so no IP literal). It
// is deliberately narrower than RFC 1035: nothing a shell, ssh_config or
// OpenSSH `%` expansion treats specially can pass. Uppercase is rejected, not
// folded, so a stored value is always its own canonical form.
func ValidateDNSName(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if len(name) > maxDNSNameLen {
		return fmt.Errorf("longer than %d characters", maxDNSNameLen)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("must be a fully qualified name with at least two labels")
	}
	for _, label := range labels {
		if err := validateDNSLabel(label); err != nil {
			return err
		}
	}
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return fmt.Errorf("last label must not be numeric")
	}
	return nil
}

func validateDNSLabel(label string) error {
	switch {
	case label == "":
		return fmt.Errorf("empty label")
	case len(label) > maxDNSLabelLen:
		return fmt.Errorf("label longer than %d characters", maxDNSLabelLen)
	case label[0] == '-' || label[len(label)-1] == '-':
		return fmt.Errorf("label must not start or end with a hyphen")
	}
	for i := range len(label) {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("only lowercase letters, digits and hyphens are allowed")
		}
	}
	return nil
}
