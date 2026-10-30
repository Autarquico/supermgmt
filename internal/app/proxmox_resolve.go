package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

// Keys of providers.config_json that only a via_node provider carries.
const (
	providerConfigViaNode       = "via_node"
	providerConfigTLSServerName = "tls_server_name"
)

// proxmoxTarget is everything a Proxmox client is built from, resolved once
// per use: an endpoint provider's inputs as configured, or a via_node
// provider's as the node's setup recorded them with the configuration's
// overrides on top.
type proxmoxTarget struct {
	endpoint   string // empty for via_node
	tokenRef   string
	ca         []byte
	serverName string // via_node only
	relay      *proxmoxRelay
}

// proxmoxRelay is how a via_node provider reaches PVE.
type proxmoxRelay struct {
	node          domain.Node
	credentialRef string // the dedicated account's pinned key
	path          string // socat, as setup recorded it
	identity      string // changes whenever the node, its host key or its Proxmox metadata change
}

// resolveTarget reads the provider's inputs. A via_node provider whose node
// is missing, is not an SSH node or was not set up with --proxmox is
// unavailable, and the error names the command that fixes it.
func (s *ProxmoxSync) resolveTarget(ctx context.Context, p domain.Provider) (proxmoxTarget, error) {
	caFile, _ := p.Config[providerConfigCAFile].(string)
	viaNode, _ := p.Config[providerConfigViaNode].(string)
	if viaNode == "" {
		t := proxmoxTarget{endpoint: p.Endpoint, tokenRef: p.CredentialRef}
		var err error
		if caFile != "" {
			if t.ca, err = s.opts.ReadFile(caFile); err != nil {
				return proxmoxTarget{}, fmt.Errorf("read ca_file: %w", err)
			}
		}
		return t, nil
	}
	node, meta, err := s.viaNode(ctx, viaNode)
	if err != nil {
		return proxmoxTarget{}, err
	}
	t := proxmoxTarget{tokenRef: p.CredentialRef, ca: []byte(meta.px.CAPEM), serverName: meta.px.TLSServerName}
	if t.tokenRef == "" {
		t.tokenRef = meta.px.TokenRef
	}
	if caFile != "" {
		if t.ca, err = s.opts.ReadFile(caFile); err != nil {
			return proxmoxTarget{}, fmt.Errorf("read ca_file: %w", err)
		}
	}
	if name, _ := p.Config[providerConfigTLSServerName].(string); name != "" {
		t.serverName = name
	}
	t.relay = &proxmoxRelay{
		node: node, credentialRef: sshnode.PinnedRef(meta.setup), path: meta.px.RelayPath,
		identity: relayIdentity(node, meta),
	}
	return t, nil
}

type nodeProxmox struct {
	setup runtimes.SetupMeta
	px    runtimes.ProxmoxMeta
}

// viaNode finds the SSH node by name and the Proxmox state its setup recorded.
func (s *ProxmoxSync) viaNode(ctx context.Context, name string) (domain.Node, nodeProxmox, error) {
	q := s.cfg.DB.Reader()
	nodes, err := database.ListNodes(ctx, q)
	if err != nil {
		return domain.Node{}, nodeProxmox{}, err
	}
	var node domain.Node
	found := false
	for _, n := range nodes {
		if n.Name == name && n.Kind == sshnode.NodeKind {
			node, found = n, true
			break
		}
	}
	if !found {
		return domain.Node{}, nodeProxmox{}, smerr.New(smerr.CodeNotFound, "",
			fmt.Sprintf("via_node %q is not a node of this instance: add it with `sm nodes add`", name))
	}
	setup, err := loadSetup(ctx, q, node.ID)
	if err != nil {
		return domain.Node{}, nodeProxmox{}, err
	}
	var px *runtimes.ProxmoxMeta
	if setup != nil {
		px = setup.ProxmoxState()
	}
	if px == nil {
		return domain.Node{}, nodeProxmox{}, smerr.New(smerr.CodeCapabilityUnavailable, "",
			fmt.Sprintf("node %q has no Proxmox setup: run `sm nodes setup %s --proxmox`", name, name))
	}
	return node, nodeProxmox{setup: *setup, px: *px}, nil
}

func relayIdentity(n domain.Node, m nodeProxmox) string {
	recorded, _ := json.Marshal(m.px)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00%s\x00%s\x00%d\x00", n.ID, n.SpecRevision, n.Endpoint.HostPublicKey, m.setup.KeyRef, m.setup.KeyVersion)
	h.Write(recorded)
	return hex.EncodeToString(h.Sum(nil))
}

// dialer opens a relay to PVE through the node.
func (r proxmoxRelay) dialer(c Connector) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		return c.OpenRelay(ctx, r.node, r.credentialRef, r.path)
	}
}
