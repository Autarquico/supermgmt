package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/local"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// capabilitySetup is the observed capability node.setup writes on success
// (ADR-0009 f). Its metadata is the node's runtimes.SetupMeta.
const capabilitySetup = "node.setup"

// Dialer is the SSH connection pool as the app sees it. *ssh.Pool is the
// production implementation; tests substitute fakes.
type Dialer interface {
	For(t ssh.Target) transport.Executor
	State(node domain.ID) ssh.ConnState
}

// Connector turns a node into the Executor that reaches it, applying the
// connection-user rule of ADR-0009 (b) in one place.
type Connector struct {
	Remote Dialer             // SSH nodes
	Local  transport.Executor // the local provider's node
}

// Automated is the executor for unattended work: the dedicated user once the
// node completed setup (setup != nil), the admin account otherwise.
func (c Connector) Automated(n domain.Node, setup *runtimes.SetupMeta) (transport.Executor, error) {
	if isLocal(n) {
		return c.local()
	}
	return c.remote(sshnode.AutomatedTarget(n, setup))
}

// Admin is the executor for node.setup's bootstrap session: admin_user with the
// admin credential.
func (c Connector) Admin(n domain.Node) (transport.Executor, error) {
	if isLocal(n) {
		return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "the local provider has no admin session")
	}
	return c.remote(sshnode.AdminTarget(n))
}

// Dedicated is a fresh session as the dedicated user with credentialRef, used
// to verify setup before it is recorded.
func (c Connector) Dedicated(n domain.Node, credentialRef string) (transport.Executor, error) {
	if isLocal(n) {
		return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "the local provider has no dedicated user")
	}
	return c.remote(sshnode.DedicatedTarget(n, credentialRef))
}

// State is the pool's view of the node's connection; it never dials.
func (c Connector) State(n domain.Node) ssh.ConnState {
	if isLocal(n) || c.Remote == nil {
		return ssh.ConnState{Status: ssh.ConnUnknown}
	}
	return c.Remote.State(n.ID)
}

func isLocal(n domain.Node) bool { return n.Kind == local.NodeKind }

func (c Connector) local() (transport.Executor, error) {
	if c.Local == nil {
		return nil, smerr.New(smerr.CodeInternal, "", "no local executor is configured")
	}
	return c.Local, nil
}

func (c Connector) remote(t ssh.Target) (transport.Executor, error) {
	if c.Remote == nil {
		return nil, smerr.New(smerr.CodeInternal, "", "no ssh pool is configured")
	}
	return c.Remote.For(t), nil
}

// loadSetup returns the node's recorded node.setup metadata, or nil when the
// node has not completed setup.
func loadSetup(ctx context.Context, q database.Querier, node domain.ID) (*runtimes.SetupMeta, error) {
	capability, err := database.GetNodeCapability(ctx, q, node, capabilitySetup)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return setupOf(capability)
}

func setupOf(c database.NodeCapability) (*runtimes.SetupMeta, error) {
	if !c.Available {
		return nil, nil
	}
	raw, err := json.Marshal(c.Metadata)
	if err != nil {
		return nil, fmt.Errorf("encode node.setup metadata: %w", err)
	}
	var meta runtimes.SetupMeta
	if err := json.Unmarshal(raw, &meta); err != nil || meta.SetupVersion < 1 {
		return nil, smerr.New(smerr.CodeInternal, "", "node.setup metadata is malformed")
	}
	return &meta, nil
}

func setupCapability(meta runtimes.SetupMeta, at time.Time) (database.NodeCapability, error) {
	raw, err := json.Marshal(meta)
	if err != nil {
		return database.NodeCapability{}, fmt.Errorf("encode node.setup metadata: %w", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return database.NodeCapability{}, fmt.Errorf("encode node.setup metadata: %w", err)
	}
	return database.NodeCapability{Capability: capabilitySetup, Available: true, Metadata: metadata, CheckedAt: at}, nil
}
