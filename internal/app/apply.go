package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/local"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
)

// The apply functions below perform a direct action. They run inside the
// request transaction, or inside the control_plane.apply job's fenced
// transaction after approval. They converge: applying a change that is already
// in place returns the stored result, so a retried job is harmless.

func nodeRef(id domain.ID) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceNode, ID: id}
}

func (i *Inventory) applyNodeAdd(ctx context.Context, q database.Querier, actor domain.Actor, p nodeAddParams) (domain.Node, error) {
	existing, err := database.GetNode(ctx, q, p.NodeID)
	if err == nil {
		return existing, nil
	}
	if smerr.CodeOf(err) != smerr.CodeNotFound {
		return domain.Node{}, err
	}
	var environment *domain.ID
	if p.Environment != "" {
		env, err := environmentNamed(ctx, q, p.Environment)
		if err != nil {
			return domain.Node{}, err
		}
		environment = &env.ID
	}
	now := i.cfg.Clock.Now()
	endpoint := sshnode.Endpoint{
		Host: p.Host, Port: p.Port, User: p.User, AdminUser: p.AdminUser, HostPublicKey: p.HostPublicKey,
		CredentialRef: p.CredentialRef, AdminCredentialRef: p.AdminCredentialRef,
	}
	if _, err := database.CreateProvider(ctx, q, domain.Provider{
		ID: p.ProviderID, Type: sshnode.ProviderType, Name: p.Name, Origin: domain.ProviderAPI,
		Endpoint: net.JoinHostPort(p.Host, strconv.Itoa(p.Port)), CredentialRef: p.CredentialRef,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return domain.Node{}, err
	}
	node, err := database.CreateNode(ctx, q, domain.Node{
		ID: p.NodeID, ProviderID: p.ProviderID, NativeID: p.Name, Name: p.Name, Kind: sshnode.NodeKind,
		EnvironmentID: environment, ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown,
		Endpoint: endpoint.NodeEndpoint(), CredentialRef: p.CredentialRef, Tags: p.Tags, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domain.Node{}, err
	}
	fingerprint, _ := sshnode.Fingerprint(p.HostPublicKey)
	if err := seedReadCapability(ctx, q, node.ID, now); err != nil {
		return domain.Node{}, err
	}
	return node, i.emit(ctx, q, actor, actionNodeAdd, nodeRef(node.ID), domain.ResultSucceeded, map[string]any{
		"name": node.Name, "host": p.Host, "port": p.Port, "user": p.User, "admin_user": p.AdminUser,
		"host_key_fingerprint": fingerprint, "environment": p.Environment,
	})
}

// seedReadCapability makes a new node readable and probeable at once: node.read
// is what node.probe requires, and every probe reports it as available anyway
// (discovery.Capabilities), so waiting for the first refresher pass only made
// `sm nodes add` followed by `sm nodes probe` fail.
func seedReadCapability(ctx context.Context, q database.Querier, node domain.ID, at time.Time) error {
	return database.SetNodeCapability(ctx, q, node, database.NodeCapability{Capability: "node.read", Available: true, CheckedAt: at})
}

func (i *Inventory) applyNodeUpdate(ctx context.Context, q database.Querier, actor domain.Actor, node domain.Node, patch NodePatch) (domain.Node, error) {
	updated, changed, err := i.patched(ctx, q, node, patch)
	if err != nil || len(changed) == 0 {
		return node, err
	}
	updated.UpdatedAt = i.cfg.Clock.Now()
	stored, err := database.UpdateNodeSpec(ctx, q, updated, node.SpecRevision)
	if err != nil {
		return domain.Node{}, err
	}
	return stored, i.emit(ctx, q, actor, actionNodeUpdate, nodeRef(node.ID), domain.ResultSucceeded, map[string]any{
		"fields": changed, "spec_revision": stored.SpecRevision,
	})
}

// patched applies patch to a copy of node and names the fields that changed.
func (i *Inventory) patched(ctx context.Context, q database.Querier, node domain.Node, patch NodePatch) (domain.Node, []string, error) {
	out := node
	var changed []string
	set := func(field string, differs bool) {
		if differs {
			changed = append(changed, field)
		}
	}
	if patch.Name != nil {
		set("name", *patch.Name != node.Name)
		out.Name = *patch.Name
	}
	if patch.AdminUser != nil {
		set("admin_user", *patch.AdminUser != node.Endpoint.AdminUser)
		out.Endpoint.AdminUser = *patch.AdminUser
	}
	if patch.AdminCredentialRef != nil {
		set("admin_credential_ref", *patch.AdminCredentialRef != node.Endpoint.AdminCredentialRef)
		out.Endpoint.AdminCredentialRef = *patch.AdminCredentialRef
	}
	if patch.Tags != nil {
		tags, err := normalizeTags(*patch.Tags)
		if err != nil {
			return domain.Node{}, nil, err
		}
		set("tags", !slices.Equal(tags, node.Tags))
		out.Tags = tags
	}
	if patch.Environment != nil {
		env, err := i.environmentIDNamed(ctx, q, *patch.Environment)
		if err != nil {
			return domain.Node{}, nil, err
		}
		set("environment", !reflect.DeepEqual(env, node.EnvironmentID))
		out.EnvironmentID = env
	}
	return out, changed, nil
}

// environmentIDNamed resolves an environment name; "" means none.
func (i *Inventory) environmentIDNamed(ctx context.Context, q database.Querier, name string) (*domain.ID, error) {
	if name == "" {
		return nil, nil
	}
	env, err := environmentNamed(ctx, q, name)
	if err != nil {
		return nil, err
	}
	return &env.ID, nil
}

func (i *Inventory) applyNodeRemove(ctx context.Context, q database.Querier, actor domain.Actor, node domain.Node) (domain.Node, error) {
	if node.ManagementState == domain.ManagementRetired {
		return node, nil
	}
	node.ManagementState = domain.ManagementRetired
	node.UpdatedAt = i.cfg.Clock.Now()
	stored, err := database.UpdateNodeSpec(ctx, q, node, node.SpecRevision)
	if err != nil {
		return domain.Node{}, err
	}
	return stored, i.emit(ctx, q, actor, actionNodeRemove, nodeRef(node.ID), domain.ResultSucceeded,
		map[string]any{"name": node.Name, "spec_revision": stored.SpecRevision})
}

func (i *Inventory) applyRegisterLocal(ctx context.Context, q database.Querier, actor domain.Actor, p localParams) (domain.Provider, error) {
	if existing, found, err := i.localProvider(ctx, q); err != nil || found {
		return existing, err
	}
	now := i.cfg.Clock.Now()
	provider, err := database.CreateProvider(ctx, q, domain.Provider{
		ID: p.ProviderID, Type: local.ProviderType, Name: p.Name, Origin: domain.ProviderAPI, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domain.Provider{}, err
	}
	if node, err := database.CreateNode(ctx, q, domain.Node{
		ID: p.NodeID, ProviderID: provider.ID, NativeID: local.NativeID, Name: i.localName, Kind: local.NodeKind,
		ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return domain.Provider{}, err
	} else if err := seedReadCapability(ctx, q, node.ID, now); err != nil {
		return domain.Provider{}, err
	}
	return provider, i.emit(ctx, q, actor, actionProviderWite, domain.ResourceRef{Type: domain.ResourceProvider, ID: provider.ID},
		domain.ResultSucceeded, map[string]any{"type": local.ProviderType, "node_id": p.NodeID.String()})
}

// applyApproved performs the change an approved control_plane.apply job carries.
func (i *Inventory) applyApproved(ctx context.Context, q database.Querier, actor domain.Actor, action string, job jobs.Job) error {
	switch action {
	case actionNodeAdd:
		p, err := payloadOf[nodeAddParams](job)
		if err != nil {
			return err
		}
		_, err = i.applyNodeAdd(ctx, q, actor, p)
		return err
	case actionNodeUpdate:
		patch, err := payloadOf[NodePatch](job)
		if err != nil {
			return err
		}
		node, err := database.GetNode(ctx, q, job.Resource.ID)
		if err != nil {
			return err
		}
		_, err = i.applyNodeUpdate(ctx, q, actor, node, patch)
		return err
	case actionNodeRemove:
		node, err := database.GetNode(ctx, q, job.Resource.ID)
		if err != nil {
			return err
		}
		_, err = i.applyNodeRemove(ctx, q, actor, node)
		return err
	case actionProviderWite:
		p, err := payloadOf[localParams](job)
		if err != nil {
			return err
		}
		_, err = i.applyRegisterLocal(ctx, q, actor, p)
		return err
	}
	return smerr.New(smerr.CodeInternal, "", "control_plane.apply: unsupported action "+action)
}

func payloadOf[T any](job jobs.Job) (T, error) {
	var out T
	dec := json.NewDecoder(bytes.NewReader(job.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, smerr.Wrap(err, smerr.CodeInternal, "", fmt.Sprintf("job %s has an unreadable payload", job.ID))
	}
	return out, nil
}
