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
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/github"
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
	if p.Tunnel {
		// An enrollment is advanced by its own job; this path would insert a node with no host.
		return domain.Node{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "tunnel enrollment is not available: the instance has no cloudflare: block")
	}
	existing, err := database.GetNode(ctx, q, p.NodeID)
	if err == nil {
		return existing, nil
	}
	if smerr.CodeOf(err) != smerr.CodeNotFound {
		return domain.Node{}, err
	}
	if err := requireNameFree(ctx, q, p.Name, ""); err != nil {
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
	return node, i.emit(ctx, q, actor, actionNodeAdd, nodeRef(node.ID), domain.ResultSucceeded, map[string]any{
		"name": node.Name, "host": p.Host, "port": p.Port, "user": p.User, "admin_user": p.AdminUser,
		"host_key_fingerprint": fingerprint, "environment": p.Environment,
	})
}

// applyNodeUpdate applies patch to node. A new host key re-pins first (it is
// its own audited event), then the other fields change under the new revision.
func (i *Inventory) applyNodeUpdate(ctx context.Context, q database.Querier, actor domain.Actor, node domain.Node, patch NodePatch) (domain.Node, error) {
	if patch.HostPublicKey != nil {
		repinned, err := i.applyRepin(ctx, q, actor, node, strings.TrimSpace(*patch.HostPublicKey))
		if err != nil {
			return domain.Node{}, err
		}
		node, patch.HostPublicKey = repinned, nil
	}
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
	if _, err := database.CreateNode(ctx, q, domain.Node{
		ID: p.NodeID, ProviderID: provider.ID, NativeID: local.NativeID, Name: i.localName, Kind: local.NodeKind,
		ManagementState: domain.ManagementManaged, Reachability: domain.ReachabilityUnknown, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return domain.Provider{}, err
	}
	return provider, i.emit(ctx, q, actor, actionProviderWite, domain.ResourceRef{Type: domain.ResourceProvider, ID: provider.ID},
		domain.ResultSucceeded, map[string]any{"type": local.ProviderType, "node_id": p.NodeID.String()})
}

// runApproved executes a control_plane.apply job. Key operations manage their
// own transactions (rotation rewraps every secret in one), so they cannot run
// inside the fenced transaction the other direct actions use.
func (i *Inventory) runApproved(ctx context.Context, lease jobs.Lease, apps *Apps) error {
	action, err := i.approvedAction(ctx, lease)
	if err != nil {
		return err
	}
	if action == actionSecretWrite {
		return i.runSecretWrite(ctx, lease)
	}
	return i.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		job, err := i.jobs.Get(ctx, tx, lease.JobID)
		if err != nil {
			return err
		}
		actor, err := loadActor(ctx, tx, job.ActorID, credentialOf(job))
		if err != nil {
			return err
		}
		if apps.handles(action, job) {
			return apps.applyApproved(ctx, tx, actor, action, job)
		}
		return i.applyApproved(ctx, tx, actor, action, job)
	})
}

// approvedAction is the action of the plan the job carries.
func (i *Inventory) approvedAction(ctx context.Context, lease jobs.Lease) (string, error) {
	job, err := i.jobs.Get(ctx, i.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return "", err
	}
	if job.PlanID == nil {
		return "", smerr.New(smerr.CodeInternal, "", "control_plane.apply job has no plan")
	}
	rec, err := database.GetPlan(ctx, i.cfg.DB.Reader(), *job.PlanID)
	return rec.Action, err
}

func (i *Inventory) runSecretWrite(ctx context.Context, lease jobs.Lease) error {
	if i.keys == nil {
		return smerr.New(smerr.CodeInternal, "", "key management is not available on this instance")
	}
	return i.keys.runApproved(ctx, lease)
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
	case actionMCPClientRegister:
		p, err := payloadOf[mcpRegisterParams](job)
		if err != nil {
			return err
		}
		_, err = i.applyMCPClientRegister(ctx, q, actor, p, &job)
		return err
	case actionMCPClientDelete:
		p, err := payloadOf[mcpDeleteParams](job)
		if err != nil {
			return err
		}
		_, err = i.applyMCPClientDelete(ctx, q, actor, p)
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

// ---- approved changes of the apps catalog -------------------------------------

// handles reports whether the approved change belongs to the apps catalog: app
// and app target writes, and the registration of a GitHub provider.
func (a *Apps) handles(action string, job jobs.Job) bool {
	switch {
	case a == nil:
		return false
	case action == appWriteAction, action == appTargetWriteAction:
		return true
	case action == actionProviderWite:
		return payloadHasKey(job, githubAPIURLKey)
	}
	return false
}

func payloadHasKey(job jobs.Job, key string) bool {
	var keys map[string]json.RawMessage
	return json.Unmarshal(job.Payload, &keys) == nil && keys[key] != nil
}

// applyApproved performs the approved change of an app, an app target or a
// GitHub provider. Each apply function validates again what it stores, because
// the world may have moved while the request waited; a change to an existing
// app or target also refuses while a deployment holds it.
func (a *Apps) applyApproved(ctx context.Context, q database.Querier, actor domain.Actor, action string, job jobs.Job) error {
	switch action {
	case appWriteAction:
		return a.applyApprovedApp(ctx, q, actor, job)
	case appTargetWriteAction:
		return a.applyApprovedTarget(ctx, q, actor, job)
	case actionProviderWite:
		p, err := payloadOf[githubProviderParams](job)
		if err != nil {
			return err
		}
		_, err = a.applyCreateGitHubProvider(ctx, q, actor, p)
		return err
	}
	return smerr.New(smerr.CodeInternal, "", "control_plane.apply: unsupported action "+action)
}

func (a *Apps) applyApprovedApp(ctx context.Context, q database.Querier, actor domain.Actor, job jobs.Job) error {
	if !payloadHasKey(job, expectedRevisionKey) {
		p, err := payloadOf[appCreateParams](job)
		if err != nil {
			return err
		}
		_, err = a.applyCreate(ctx, q, actor, p)
		return err
	}
	p, err := payloadOf[appUpdateParams](job)
	if err != nil {
		return err
	}
	if err := requireNotLockedByJobs(ctx, q, appRef(p.AppID)); err != nil {
		return err
	}
	_, err = a.applyUpdate(ctx, q, actor, p)
	return err
}

func (a *Apps) applyApprovedTarget(ctx context.Context, q database.Querier, actor domain.Actor, job jobs.Job) error {
	if !payloadHasKey(job, expectedRevisionKey) {
		p, err := payloadOf[appTargetCreateParams](job)
		if err != nil {
			return err
		}
		_, err = a.applyCreateTarget(ctx, q, actor, p)
		return err
	}
	p, err := payloadOf[appTargetUpdateParams](job)
	if err != nil {
		return err
	}
	if err := requireNotLockedByJobs(ctx, q, appTargetRef(p.TargetID)); err != nil {
		return err
	}
	_, err = a.applyUpdateTarget(ctx, q, actor, p)
	return err
}

// applyCreateGitHubProvider stores the provider with the convention the GitHub
// client factory reads (api_url in Endpoint, the token reference in
// CredentialRef, ca_file and webhook_secret_ref in Config). It converges: a
// provider already stored under the id is returned unchanged.
func (a *Apps) applyCreateGitHubProvider(ctx context.Context, q database.Querier, actor domain.Actor, p githubProviderParams) (domain.Provider, error) {
	if err := p.validate(); err != nil {
		return domain.Provider{}, err
	}
	if existing, err := database.GetProvider(ctx, q, p.ProviderID); err == nil {
		return existing, nil
	} else if smerr.CodeOf(err) != smerr.CodeNotFound {
		return domain.Provider{}, err
	}
	if err := requireFreeProviderName(ctx, q, p.Name); err != nil {
		return domain.Provider{}, err
	}
	now := a.cfg.Clock.Now()
	provider, err := database.CreateProvider(ctx, q, domain.Provider{
		ID: p.ProviderID, Type: github.ProviderType, Name: p.Name, Origin: domain.ProviderAPI,
		Endpoint: p.APIURL, CredentialRef: p.CredentialRef, Config: githubProviderConfig(p),
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return domain.Provider{}, err
	}
	return provider, a.emit(ctx, q, actor, actionProviderWite, domain.ResourceRef{Type: domain.ResourceProvider, ID: provider.ID},
		domain.ResultSucceeded, map[string]any{"type": github.ProviderType, "name": provider.Name, "api_url": provider.Endpoint})
}

func githubProviderConfig(p githubProviderParams) map[string]any {
	config := map[string]any{}
	if p.CAFile != "" {
		config[providerConfigCAFile] = p.CAFile
	}
	if p.WebhookSecretRef != "" {
		config[providerConfigWebhookSecretRef] = p.WebhookSecretRef
	}
	return config
}
