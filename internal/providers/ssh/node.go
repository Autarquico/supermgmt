// Package ssh is the SSH node provider (spec §6.4, §12, ADR-0009): how a node
// that is reached over SSH is described, validated and connected to. It owns
// the connection-user rule and the mapping from configuration, and nothing
// that touches storage or a network.
package ssh

import (
	"bytes"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

const (
	// ProviderType is the providers.type of an SSH node's provider.
	ProviderType = config.ProviderSSH
	// NodeKind is the nodes.kind of an SSH node.
	NodeKind = "ssh"
	// DefaultPort is the SSH port when none is given.
	DefaultPort = 22
)

// AutomatedTarget is where an automated session connects (spec §6.4,
// ADR-0009 b): as the dedicated user, signing with the key version node.setup
// pinned, if and only if the node completed node.setup (setup != nil);
// otherwise as admin_user with the admin credential, for read-only probes. A
// joined node has no admin account (ADR-0022): until setup it is probed as the
// dedicated user with the key version enrollment pinned in its credential_ref.
func AutomatedTarget(n domain.Node, setup *runtimes.SetupMeta) ssh.Target {
	if setup == nil && n.Endpoint.AdminUser == "" {
		return DedicatedTarget(n, n.CredentialRef)
	}
	if setup == nil {
		return AdminTarget(n)
	}
	return DedicatedTarget(n, PinnedRef(*setup))
}

// AdminTarget is the human's own account: node.setup and interactive sessions.
func AdminTarget(n domain.Node) ssh.Target {
	return targetOf(n, n.Endpoint.AdminUser, n.Endpoint.AdminCredentialRef)
}

// DedicatedTarget is the dedicated user authenticating with credentialRef.
func DedicatedTarget(n domain.Node, credentialRef string) ssh.Target {
	return targetOf(n, n.Endpoint.User, credentialRef)
}

func targetOf(n domain.Node, user, credentialRef string) ssh.Target {
	return ssh.Target{
		NodeID: n.ID, Host: n.Endpoint.Host, Port: n.Endpoint.Port,
		User: user, HostKey: n.Endpoint.HostPublicKey, CredentialRef: credentialRef,
		Transport: n.Endpoint.Transport, TunnelHostname: n.Endpoint.TunnelHostname,
	}
}

// PinnedRef is the credential reference node.setup pinned: exactly the key
// version it authorized on the node, so rotating the instance identity never
// breaks a node that was set up with the previous one (ADR-0009 e).
func PinnedRef(setup runtimes.SetupMeta) string {
	if setup.KeyVersion < 1 {
		return setup.KeyRef
	}
	return setup.KeyRef + "@" + strconv.Itoa(setup.KeyVersion)
}

// Fingerprint returns the SHA256 fingerprint of an OpenSSH public key line.
func Fingerprint(authorized string) (string, error) {
	key, err := ParseHostKey(authorized)
	if err != nil {
		return "", err
	}
	return cryptossh.FingerprintSHA256(key), nil
}

// ParseHostKey accepts exactly one non-certificate public key in
// authorized_keys form.
func ParseHostKey(authorized string) (cryptossh.PublicKey, error) {
	key, _, _, rest, err := cryptossh.ParseAuthorizedKey([]byte(authorized))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "host_public_key must be one OpenSSH public key")
	}
	if _, isCert := key.(*cryptossh.Certificate); isCert {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "certificate host keys are not supported")
	}
	return key, nil
}

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// ValidateEndpoint checks the host and port of a node endpoint against
// allowlists: a DNS name or an IP literal, so the host can never be read as an
// option, a user@host or a shell word by any tool the endpoint reaches.
func ValidateEndpoint(host string, port int) error {
	if port < 1 || port > 65535 {
		return smerr.New(smerr.CodeInvalidArgument, "", "invalid ssh port")
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Zone() == "" {
		return nil
	}
	if !hostnamePattern.MatchString(host) {
		return smerr.New(smerr.CodeInvalidArgument, "", "invalid ssh host")
	}
	return nil
}

var accountPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidateAccount checks a login name against the allowlist the command
// templates and the sudoers grammar rely on (ADR-0015).
func ValidateAccount(field, user string) error {
	if !accountPattern.MatchString(user) {
		return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("%s must match %s", field, accountPattern))
	}
	return nil
}

// ValidateCredentialRef checks the closed scheme set of spec §8.4. Agent
// references are local-mode only.
func ValidateCredentialRef(field, ref string, mode config.Mode) error {
	problem := ""
	switch {
	case strings.HasPrefix(ref, "secret://"):
		if len(ref) == len("secret://") {
			problem = "secret:// reference needs a path"
		}
	case ref == "ssh-agent://default":
		if mode == config.ModeServer {
			problem = "ssh-agent:// is not allowed in server mode"
		}
	case strings.HasPrefix(ref, "file://"):
		if !path.IsAbs(strings.TrimPrefix(ref, "file://")) {
			problem = "file:// reference needs an absolute path"
		}
	default:
		problem = "unsupported credential reference (allowed: secret://<path>, ssh-agent://default, file://<abs-path>)"
	}
	if problem != "" {
		return smerr.New(smerr.CodeInvalidArgument, "", field+": "+problem)
	}
	return nil
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidateName checks the name of a node, which is also its provider's name.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return smerr.New(smerr.CodeInvalidArgument, "", "name must match "+namePattern.String())
	}
	return nil
}

// Endpoint is the validated, defaulted description of an SSH node's endpoint
// and credentials, as the inventory stores it.
type Endpoint struct {
	Host               string
	Port               int
	User               string
	AdminUser          string
	HostPublicKey      string
	CredentialRef      string
	AdminCredentialRef string
}

// Defaults fills the optional fields (spec §6.4, §8.4): port 22, user
// supermgmt, credential secret://ssh/default and, in local mode, the admin
// credential ssh-agent://default. Server mode has no admin default.
func (e Endpoint) Defaults(mode config.Mode) Endpoint {
	if e.Port == 0 {
		e.Port = DefaultPort
	}
	if e.User == "" {
		e.User = config.DefaultSSHUser
	}
	if e.CredentialRef == "" {
		e.CredentialRef = config.DefaultSSHCredentialRef
	}
	if e.AdminCredentialRef == "" && mode == config.ModeLocal {
		e.AdminCredentialRef = config.DefaultAdminCredentialRef
	}
	return e
}

// Validate checks every field. A host key is required: first trust is an
// explicit confirmation, so a node cannot exist without one (spec §12).
func (e Endpoint) Validate(mode config.Mode) error {
	if err := ValidateEndpoint(e.Host, e.Port); err != nil {
		return err
	}
	if err := ValidateAccount("user", e.User); err != nil {
		return err
	}
	if err := ValidateAccount("admin_user", e.AdminUser); err != nil {
		return err
	}
	if _, err := ParseHostKey(e.HostPublicKey); err != nil {
		return err
	}
	if err := ValidateCredentialRef("credential_ref", e.CredentialRef, mode); err != nil {
		return err
	}
	if e.AdminCredentialRef == "" {
		return smerr.New(smerr.CodeInvalidArgument, "", "admin_credential_ref is required")
	}
	return ValidateCredentialRef("admin_credential_ref", e.AdminCredentialRef, mode)
}

// FromConfig maps a configured SSH provider (spec §8.3) to its endpoint.
func FromConfig(p config.SSHProvider, mode config.Mode) Endpoint {
	return Endpoint{
		Host: p.Endpoint.Host, Port: p.Endpoint.Port, User: p.Endpoint.User, AdminUser: p.Endpoint.AdminUser,
		HostPublicKey: strings.TrimSpace(p.Endpoint.HostPublicKey), CredentialRef: p.CredentialRef,
		AdminCredentialRef: p.AdminCredentialRef,
	}.Defaults(mode)
}

// NodeEndpoint is the domain form stored in the nodes table.
func (e Endpoint) NodeEndpoint() domain.NodeEndpoint {
	return domain.NodeEndpoint{
		Host: e.Host, Port: e.Port, User: e.User, AdminUser: e.AdminUser,
		AdminCredentialRef: e.AdminCredentialRef, HostPublicKey: strings.TrimSpace(e.HostPublicKey),
	}
}
