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

// providerBranches maps the `type` discriminator to its branch struct. M0
// accepts only these two types (spec §8.3).
var providerBranches = map[string]reflect.Type{
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
	return nil, fmt.Sprintf("unsupported provider type %q (supported: proxmox, ssh)", kind)
}

// Provider is the provider union: exactly one branch is non-nil.
type Provider struct {
	Proxmox *ProxmoxProvider
	SSH     *SSHProvider
}

type ProxmoxProvider struct {
	Type          string        `yaml:"type"`
	Name          string        `yaml:"name"`
	Endpoint      string        `yaml:"endpoint"`
	CredentialRef string        `yaml:"credential_ref"`
	VerifyTLS     bool          `yaml:"verify_tls"`
	CAFile        string        `yaml:"ca_file"`
	SyncInterval  time.Duration `yaml:"sync_interval"`
}

type SSHProvider struct {
	Type          string      `yaml:"type"`
	Name          string      `yaml:"name"`
	Endpoint      SSHEndpoint `yaml:"endpoint"`
	CredentialRef string      `yaml:"credential_ref"`
	Environment   string      `yaml:"environment"`
	Tags          []string    `yaml:"tags"`
}

type SSHEndpoint struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	User          string `yaml:"user"`
	HostPublicKey string `yaml:"host_public_key"`
}

func (p Provider) Type() string {
	switch {
	case p.Proxmox != nil:
		return ProviderProxmox
	case p.SSH != nil:
		return ProviderSSH
	}
	return ""
}

func (p Provider) Name() string {
	switch {
	case p.Proxmox != nil:
		return p.Proxmox.Name
	case p.SSH != nil:
		return p.SSH.Name
	}
	return ""
}

func (p Provider) CredentialRef() string {
	switch {
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
	case ProviderProxmox:
		b := ProxmoxProvider{VerifyTLS: true, SyncInterval: 30 * time.Second}
		if err := n.Decode(&b); err != nil {
			return fmt.Errorf("decode proxmox provider: %w", err)
		}
		*p = Provider{Proxmox: &b}
	case ProviderSSH:
		b := SSHProvider{Endpoint: SSHEndpoint{Port: 22}}
		if err := n.Decode(&b); err != nil {
			return fmt.Errorf("decode ssh provider: %w", err)
		}
		*p = Provider{SSH: &b}
	default:
		return fmt.Errorf("line %d: unsupported provider type %q (supported: proxmox, ssh)", n.Line, kind)
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
