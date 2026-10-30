package config

import (
	"fmt"
	"reflect"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	ProviderProxmox = "proxmox"
	ProviderSSH     = "ssh"
)

// SSH node defaults (spec §6.4, §8.4; ADR-0009 b, e). The admin credential
// default applies in local mode only; server mode has none.
const (
	DefaultSSHUser            = "supermgmt"
	DefaultSSHCredentialRef   = "secret://ssh/default" //nolint:gosec // a reference to a secret, not a secret
	DefaultAdminCredentialRef = "ssh-agent://default"  //nolint:gosec // names the agent socket, holds no key
)

// providerBranches maps the `type` discriminator to its branch struct (spec
// §8.3).
var providerBranches = map[string]reflect.Type{
	ProviderGitHub:  reflect.TypeFor[GitHubProvider](),
	ProviderProxmox: reflect.TypeFor[ProxmoxProvider](),
	ProviderSSH:     reflect.TypeFor[SSHProvider](),
}

// selectProviderBranch tells the strict decoder which struct describes a
// provider node, from its `type` discriminator.
func selectProviderBranch(n *yaml.Node) (reflect.Type, string) {
	kind := scalarField(n, "type")
	if branch, ok := providerBranches[kind]; ok {
		return branch, ""
	}
	return nil, fmt.Sprintf("unsupported provider type %q (supported: github, proxmox, ssh)", kind)
}

// Provider is the provider union: exactly one branch is non-nil.
type Provider struct {
	GitHub  *GitHubProvider
	Proxmox *ProxmoxProvider
	SSH     *SSHProvider
}

// ProxmoxProvider reaches Proxmox VE either directly (Endpoint) or through
// the SSH connection of a managed node (ViaNode); exactly one is set. With
// ViaNode, CredentialRef and CAFile default to what node setup recorded, and
// TLSServerName overrides the name the certificate is verified against.
type ProxmoxProvider struct {
	Type          string        `yaml:"type"`
	Name          string        `yaml:"name"`
	Endpoint      string        `yaml:"endpoint"`
	ViaNode       string        `yaml:"via_node"`
	TLSServerName string        `yaml:"tls_server_name"`
	CredentialRef string        `yaml:"credential_ref"`
	VerifyTLS     bool          `yaml:"verify_tls"`
	CAFile        string        `yaml:"ca_file"`
	SyncInterval  time.Duration `yaml:"sync_interval"`
}

// SSHProvider is one SSH node. CredentialRef signs automated sessions as
// Endpoint.User; AdminCredentialRef authenticates Endpoint.AdminUser (setup
// bootstrap, read-only probes before setup, interactive sessions).
type SSHProvider struct {
	Type               string      `yaml:"type"`
	Name               string      `yaml:"name"`
	Endpoint           SSHEndpoint `yaml:"endpoint"`
	CredentialRef      string      `yaml:"credential_ref"`
	AdminCredentialRef string      `yaml:"admin_credential_ref"`
	Environment        string      `yaml:"environment"`
	Tags               []string    `yaml:"tags"`
}

type SSHEndpoint struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	User          string `yaml:"user"`
	AdminUser     string `yaml:"admin_user"`
	HostPublicKey string `yaml:"host_public_key"`
}

func (p Provider) Type() string {
	switch {
	case p.GitHub != nil:
		return ProviderGitHub
	case p.Proxmox != nil:
		return ProviderProxmox
	case p.SSH != nil:
		return ProviderSSH
	}
	return ""
}

func (p Provider) Name() string {
	switch {
	case p.GitHub != nil:
		return p.GitHub.Name
	case p.Proxmox != nil:
		return p.Proxmox.Name
	case p.SSH != nil:
		return p.SSH.Name
	}
	return ""
}

func (p Provider) CredentialRef() string {
	switch {
	case p.GitHub != nil:
		return p.GitHub.CredentialRef
	case p.Proxmox != nil:
		return p.Proxmox.CredentialRef
	case p.SSH != nil:
		return p.SSH.CredentialRef
	}
	return ""
}

// UnmarshalYAML selects the branch by `type`. Strictness for unknown keys is
// enforced beforehand by DecodeStrict's field walk, because yaml.Node.Decode
// ignores KnownFields.
func (p *Provider) UnmarshalYAML(n *yaml.Node) error {
	kind := scalarField(n, "type")
	switch kind {
	case ProviderGitHub:
		b := GitHubProvider{APIURL: DefaultGitHubAPIURL}
		if err := n.Decode(&b); err != nil {
			return fmt.Errorf("decode github provider: %w", err)
		}
		*p = Provider{GitHub: &b}
	case ProviderProxmox:
		b := ProxmoxProvider{VerifyTLS: true, SyncInterval: 30 * time.Second}
		if err := n.Decode(&b); err != nil {
			return fmt.Errorf("decode proxmox provider: %w", err)
		}
		*p = Provider{Proxmox: &b}
	case ProviderSSH:
		b := SSHProvider{Endpoint: SSHEndpoint{Port: 22, User: DefaultSSHUser}, CredentialRef: DefaultSSHCredentialRef}
		if err := n.Decode(&b); err != nil {
			return fmt.Errorf("decode ssh provider: %w", err)
		}
		*p = Provider{SSH: &b}
	default:
		return fmt.Errorf("line %d: unsupported provider type %q (supported: github, proxmox, ssh)", n.Line, kind)
	}
	return nil
}

// scalarField returns the scalar value stored under key in a mapping node.
func scalarField(n *yaml.Node, key string) string {
	if n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key && n.Content[i+1].Kind == yaml.ScalarNode {
			return n.Content[i+1].Value
		}
	}
	return ""
}
