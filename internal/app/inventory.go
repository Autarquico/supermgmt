package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/local"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

const (
	defaultStaleAfter = 3 * time.Minute
	defaultLocalName  = "local"
	maxTags           = 64
	maxTagLength      = 64
	maxNodesPage      = wire.MaxLimit
)

// InventoryOptions are the collaborators of the Inventory.
type InventoryOptions struct {
	Store     *jobs.Store
	Connector Connector
	Mode      config.Mode // instance.mode: decides the credential defaults
	Focus     *Focus      // focus leases shared with the Refresher; nil disables them
	// StaleAfter is how old a node's last observation may be before the view
	// says stale; default 3m.
	StaleAfter time.Duration
	// Scan reads a host key (spec §12 step 2); default ssh.ScanHostKey.
	Scan func(ctx context.Context, host string, port int) (ssh.HostKey, error)
	// LocalName names the local provider's node; default "local".
	LocalName string
	// KeepLogsRaw turns off the redaction of secret patterns in command output
	// served to clients (security.redact_command_output: false).
	KeepLogsRaw bool
}

// Inventory is the node and service catalog: it adds, edits and retires nodes
// (`direct` actions, spec §11.2) and answers reads from the database and the
// pool state without ever dialing, except for logs and the first-trust scan.
type Inventory struct {
	core
	plans      *Plans
	jobs       *jobs.Store
	conn       Connector
	mode       config.Mode
	focus      *Focus
	staleAfter time.Duration
	scan       func(ctx context.Context, host string, port int) (ssh.HostKey, error)
	localName  string
	adapters   Adapters
	redactLogs bool
}

// NewInventory validates cfg and the options.
func NewInventory(cfg Config, o InventoryOptions) (*Inventory, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	plans, err := NewPlans(cfg, o.Store)
	if err != nil {
		return nil, err
	}
	if o.Mode != config.ModeLocal && o.Mode != config.ModeServer {
		return nil, errors.New("app: instance mode is required")
	}
	inv := &Inventory{
		core: c, plans: plans, jobs: o.Store, conn: o.Connector, mode: o.Mode, focus: o.Focus,
		staleAfter: o.StaleAfter, scan: o.Scan, localName: o.LocalName, adapters: DefaultAdapters(), redactLogs: !o.KeepLogsRaw,
	}
	if inv.staleAfter <= 0 {
		inv.staleAfter = defaultStaleAfter
	}
	if inv.scan == nil {
		inv.scan = ssh.ScanHostKey
	}
	if inv.localName == "" {
		inv.localName = defaultLocalName
	}
	return inv, nil
}

// ---- requests ----------------------------------------------------------------

// AddSSHNode asks for a node reached over SSH. HostKey is the key the user
// confirmed after ScanHostKey; it becomes the only trust anchor of the node
// (ADR-0015), so a key that changes before the first authenticated probe is
// SSH_HOST_KEY_MISMATCH.
type AddSSHNode struct {
	Name               string
	Host               string
	Port               int
	User               string
	AdminUser          string
	HostKey            string
	CredentialRef      string
	AdminCredentialRef string
	Environment        string
	Tags               []string
}

// ScanHostKey reads the key a host presents so the user can confirm its
// fingerprint (spec §12 steps 2-3). It writes nothing; it needs node.add.
func (i *Inventory) ScanHostKey(ctx context.Context, by Caller, host string, port int) (ssh.HostKey, error) {
	if port == 0 {
		port = sshnode.DefaultPort
	}
	if err := sshnode.ValidateEndpoint(host, port); err != nil {
		return ssh.HostKey{}, err
	}
	if _, err := i.authorizeScan(ctx, by); err != nil {
		return ssh.HostKey{}, err
	}
	return i.scan(ctx, host, port)
}

func (i *Inventory) authorizeScan(ctx context.Context, by Caller) (domain.Actor, error) {
	var actor domain.Actor
	err := i.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		var err error
		if actor, err = i.beginRequest(ctx, tx, by); err != nil {
			return err
		}
		target := policy.Target{Ref: domain.ResourceRef{Type: domain.ResourceNode}}
		res := i.authorize(policy.Request{Actor: actor, Action: actionNodeAdd, Targets: []policy.Target{target}})
		if err := i.auditDecision(ctx, tx, actor, actionNodeAdd, target.Ref, res); err != nil {
			return err
		}
		if err := decisionError(res); err != nil {
			return reject(err)
		}
		return nil
	})
	return actor, err
}

// beginRequest identifies the caller and checks that its credential is live.
func (c core) beginRequest(ctx context.Context, q database.Querier, by Caller) (domain.Actor, error) {
	actor, err := loadCaller(ctx, q, by)
	if err != nil {
		return domain.Actor{}, err
	}
	return actor, c.requireActive(ctx, by.Credential)
}

// AddSSHNode adds the node (action node.add). Policy may wrap the request in a
// control_plane.apply job that waits for approval, e.g. for a production
// environment; then Pending is set instead of Applied.
func (i *Inventory) AddSSHNode(ctx context.Context, by Caller, r AddSSHNode) (DirectResult[wire.Node], error) {
	return commit(ctx, i.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[wire.Node], error) {
		actor, err := i.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		p, err := i.addParams(ctx, tx, r)
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		params, err := toParams(p)
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		b, err := build(ctx, tx, actionNodeAdd, by.ID, domain.ResourceRef{Type: domain.ResourceNode, ID: p.NodeID}, params)
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		return i.applyOrWrap(ctx, tx, by, actor, b, func() (domain.Node, error) { return i.applyNodeAdd(ctx, tx, actor, p) })
	})
}

// applyOrWrap authorizes b and either applies it inside the request
// transaction or, when policy requires approval, wraps it in a job.
func (i *Inventory) applyOrWrap(ctx context.Context, tx *database.Tx, by Caller, actor domain.Actor, b built, apply func() (domain.Node, error)) (DirectResult[wire.Node], error) {
	res, err := i.evaluate(ctx, tx, actor, b)
	if err != nil {
		return DirectResult[wire.Node]{}, err
	}
	if res.ApprovalRequired {
		submission, err := i.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		return DirectResult[wire.Node]{Pending: &submission}, err
	}
	node, err := apply()
	if err != nil {
		return DirectResult[wire.Node]{}, err
	}
	view, err := i.nodeView(ctx, tx, node)
	return DirectResult[wire.Node]{Applied: &view}, err
}

// addParams validates and completes the request: defaults, the allowlists of
// ADR-0015, a unique name and fresh ids for the node and its provider.
func (i *Inventory) addParams(ctx context.Context, q database.Querier, r AddSSHNode) (nodeAddParams, error) {
	endpoint := sshnode.Endpoint{
		Host: r.Host, Port: r.Port, User: r.User, AdminUser: r.AdminUser, HostPublicKey: strings.TrimSpace(r.HostKey),
		CredentialRef: r.CredentialRef, AdminCredentialRef: r.AdminCredentialRef,
	}.Defaults(i.mode)
	if err := sshnode.ValidateName(r.Name); err != nil {
		return nodeAddParams{}, err
	}
	if err := endpoint.Validate(i.mode); err != nil {
		return nodeAddParams{}, err
	}
	tags, err := normalizeTags(r.Tags)
	if err != nil {
		return nodeAddParams{}, err
	}
	if err := i.requireFreeName(ctx, q, r.Name); err != nil {
		return nodeAddParams{}, err
	}
	return nodeAddParams{
		NodeID: i.cfg.IDs.NewID(), ProviderID: i.cfg.IDs.NewID(), Name: r.Name,
		Host: endpoint.Host, Port: endpoint.Port, User: endpoint.User, AdminUser: endpoint.AdminUser,
		HostPublicKey: endpoint.HostPublicKey, CredentialRef: endpoint.CredentialRef,
		AdminCredentialRef: endpoint.AdminCredentialRef, Environment: r.Environment, Tags: tags,
	}, nil
}

func (i *Inventory) requireFreeName(ctx context.Context, q database.Querier, name string) error {
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(providers, func(p domain.Provider) bool { return p.Name == name }) {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("a node or provider named %q already exists", name))
	}
	return nil
}

// normalizeTags validates and sorts tags (control-plane-owned authorization
// attributes, spec §11.3); duplicates collapse.
func normalizeTags(tags []string) ([]string, error) {
	if len(tags) > maxTags {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("at most %d tags", maxTags))
	}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag == "" || utf8.RuneCountInString(tag) > maxTagLength || !utf8.ValidString(tag) || strings.ContainsAny(tag, " \t\r\n\x00") {
			return nil, smerr.New(smerr.CodeInvalidArgument, "", "a tag must be 1-64 characters without whitespace")
		}
		out = append(out, tag)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// UpdateNode changes the configured fields of a node (action node.update).
// ifMatch is the spec_revision the caller saw; a stale one is CONFLICT.
func (i *Inventory) UpdateNode(ctx context.Context, by Caller, id domain.ID, ifMatch int64, patch NodePatch) (DirectResult[wire.Node], error) {
	return commit(ctx, i.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[wire.Node], error) {
		actor, node, err := i.beginMutation(ctx, tx, by, id, ifMatch)
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		if err := i.validatePatch(patch); err != nil {
			return DirectResult[wire.Node]{}, err
		}
		params, err := toParams(patch)
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		b, err := build(ctx, tx, actionNodeUpdate, by.ID, domain.ResourceRef{Type: domain.ResourceNode, ID: node.ID}, params)
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		return i.applyOrWrap(ctx, tx, by, actor, b, func() (domain.Node, error) { return i.applyNodeUpdate(ctx, tx, actor, node, patch) })
	})
}

// RemoveNode retires a node (action node.remove): it stays in the database
// for audit but is no longer managed (plan Q9).
func (i *Inventory) RemoveNode(ctx context.Context, by Caller, id domain.ID, ifMatch int64) (DirectResult[wire.Node], error) {
	return commit(ctx, i.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[wire.Node], error) {
		actor, node, err := i.beginMutation(ctx, tx, by, id, ifMatch)
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		b, err := build(ctx, tx, actionNodeRemove, by.ID, domain.ResourceRef{Type: domain.ResourceNode, ID: node.ID}, map[string]any{})
		if err != nil {
			return DirectResult[wire.Node]{}, err
		}
		return i.applyOrWrap(ctx, tx, by, actor, b, func() (domain.Node, error) { return i.applyNodeRemove(ctx, tx, actor, node) })
	})
}

// beginMutation identifies the caller and loads the node an update or removal
// names, checking everything that does not depend on policy: the revision the
// caller saw, that the node is not defined in the configuration file, and that
// no job holds a lock on it (spec §23).
func (i *Inventory) beginMutation(ctx context.Context, tx *database.Tx, by Caller, id domain.ID, ifMatch int64) (domain.Actor, domain.Node, error) {
	actor, err := i.beginRequest(ctx, tx, by)
	if err != nil {
		return domain.Actor{}, domain.Node{}, err
	}
	node, err := database.GetNode(ctx, tx, id)
	if err != nil {
		return domain.Actor{}, domain.Node{}, err
	}
	if err := i.requireAPIOrigin(ctx, tx, node); err != nil {
		return domain.Actor{}, domain.Node{}, err
	}
	if node.SpecRevision != ifMatch {
		return domain.Actor{}, domain.Node{}, staleRevision("node", ifMatch, node.SpecRevision)
	}
	if locked, err := database.ResourceLocked(ctx, tx, domain.ResourceRef{Type: domain.ResourceNode, ID: id}); err != nil {
		return domain.Actor{}, domain.Node{}, err
	} else if locked {
		return domain.Actor{}, domain.Node{}, smerr.FromReason(smerr.ReasonResourceLocked, "a job holds a lock on this node")
	}
	return actor, node, nil
}

func staleRevision(what string, expected, current int64) error {
	e := smerr.New(smerr.CodeConflict, "", fmt.Sprintf("%s changed concurrently: expected spec_revision %d, found %d", what, expected, current))
	e.Details = map[string]any{"expected_spec_revision": expected, "current_spec_revision": current}
	return e
}

// requireAPIOrigin refuses to change a node defined in the configuration file:
// the file is its source of truth and the next start would undo the edit.
func (i *Inventory) requireAPIOrigin(ctx context.Context, q database.Querier, node domain.Node) error {
	provider, err := database.GetProvider(ctx, q, node.ProviderID)
	if err != nil {
		return err
	}
	if provider.Origin == domain.ProviderStatic {
		return smerr.New(smerr.CodeConflict, "", "this node is defined in the configuration file; change it there")
	}
	return nil
}

func (i *Inventory) validatePatch(p NodePatch) error {
	if p.HostPublicKey != nil { // re-pin lands with ADR-0021 (M2 T4); refuse rather than ignore
		return smerr.New(smerr.CodeInvalidArgument, "", "host_public_key cannot be changed yet")
	}
	if p.Name != nil {
		if err := sshnode.ValidateName(*p.Name); err != nil {
			return err
		}
	}
	if p.AdminUser != nil {
		if err := sshnode.ValidateAccount("admin_user", *p.AdminUser); err != nil {
			return err
		}
	}
	if p.AdminCredentialRef != nil {
		if err := sshnode.ValidateCredentialRef("admin_credential_ref", *p.AdminCredentialRef, i.mode); err != nil {
			return err
		}
	}
	if p.Tags != nil {
		if _, err := normalizeTags(*p.Tags); err != nil {
			return err
		}
	}
	return nil
}

// RegisterLocal records the user's consent to manage this machine (spec §14):
// the local provider and its single node (action provider.write).
func (i *Inventory) RegisterLocal(ctx context.Context, by Caller) (DirectResult[domain.Provider], error) {
	return commit(ctx, i.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[domain.Provider], error) {
		actor, err := i.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[domain.Provider]{}, err
		}
		if existing, found, err := i.localProvider(ctx, tx); err != nil {
			return DirectResult[domain.Provider]{}, err
		} else if found {
			return DirectResult[domain.Provider]{Applied: &existing}, nil
		}
		p := localParams{ProviderID: i.cfg.IDs.NewID(), NodeID: i.cfg.IDs.NewID(), Name: local.ProviderType}
		params, err := toParams(p)
		if err != nil {
			return DirectResult[domain.Provider]{}, err
		}
		b, err := build(ctx, tx, actionProviderWite, by.ID, domain.ResourceRef{Type: domain.ResourceProvider, ID: p.ProviderID}, params)
		if err != nil {
			return DirectResult[domain.Provider]{}, err
		}
		res, err := i.evaluate(ctx, tx, actor, b)
		if err != nil {
			return DirectResult[domain.Provider]{}, err
		}
		if res.ApprovalRequired {
			submission, err := i.plans.planAndSubmit(ctx, tx, by, actor, b, res)
			return DirectResult[domain.Provider]{Pending: &submission}, err
		}
		provider, err := i.applyRegisterLocal(ctx, tx, actor, p)
		return DirectResult[domain.Provider]{Applied: &provider}, err
	})
}

func (i *Inventory) localProvider(ctx context.Context, q database.Querier) (domain.Provider, bool, error) {
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return domain.Provider{}, false, err
	}
	for _, p := range providers {
		if p.Type == local.ProviderType {
			return p, true, nil
		}
	}
	return domain.Provider{}, false, nil
}

// ---- reads -------------------------------------------------------------------

func (i *Inventory) viewer() viewer {
	return viewer{conn: i.conn, now: i.cfg.Clock.Now(), staleAfter: i.staleAfter}
}

func (i *Inventory) nodeView(ctx context.Context, q database.Querier, n domain.Node) (wire.Node, error) {
	v := i.viewer()
	l, err := v.lookups(ctx, q)
	if err != nil {
		return wire.Node{}, err
	}
	return v.node(ctx, q, l, n)
}

// ListProviders lists the providers the caller may read.
func (i *Inventory) ListProviders(ctx context.Context, by Caller) ([]wire.Provider, error) {
	q := i.cfg.DB.Reader()
	actor, err := i.beginRequest(ctx, q, by)
	if err != nil {
		return nil, err
	}
	providers, err := database.ListProviders(ctx, q)
	if err != nil {
		return nil, err
	}
	out := []wire.Provider{}
	for _, p := range providers {
		target := policy.Target{Ref: domain.ResourceRef{Type: domain.ResourceProvider, ID: p.ID}, Attrs: policy.Attributes{Provider: p.Name}}
		if i.authorize(policy.Request{Actor: actor, Action: "provider.read", Targets: []policy.Target{target}}).Decision == policy.DecisionAllow {
			out = append(out, ProviderView(p))
		}
	}
	return out, nil
}

// ListNodes lists the nodes the caller may read, from the database and the
// pool state. It never dials. Retired nodes are listed too; filters narrow.
func (i *Inventory) ListNodes(ctx context.Context, by Caller, f wire.NodeQuery) (wire.Page[wire.Node], error) {
	q := i.cfg.DB.Reader()
	actor, err := i.beginRequest(ctx, q, by)
	if err != nil {
		return wire.Page[wire.Node]{}, err
	}
	nodes, err := database.ListNodes(ctx, q)
	if err != nil {
		return wire.Page[wire.Node]{}, err
	}
	v := i.viewer()
	l, err := v.lookups(ctx, q)
	if err != nil {
		return wire.Page[wire.Node]{}, err
	}
	visible := slices.DeleteFunc(nodes, func(n domain.Node) bool { return !i.nodeMatches(l, n, f) || !i.mayRead(actor, l, n) })
	page, err := paginate(visible, f.PageQuery, func(n domain.Node) domain.ID { return n.ID })
	if err != nil {
		return wire.Page[wire.Node]{}, err
	}
	out := wire.Page[wire.Node]{Items: []wire.Node{}, NextCursor: page.next}
	for _, n := range page.items {
		view, err := v.node(ctx, q, l, n)
		if err != nil {
			return wire.Page[wire.Node]{}, err
		}
		out.Items = append(out.Items, view)
	}
	return out, nil
}

func (i *Inventory) nodeMatches(l lookups, n domain.Node, f wire.NodeQuery) bool {
	if f.Environment != "" && l.envs[derefID(n.EnvironmentID)].Name != f.Environment {
		return false
	}
	if f.Tag != "" && !slices.Contains(n.Tags, f.Tag) {
		return false
	}
	return f.Reachability == "" || n.Reachability == f.Reachability
}

// mayRead evaluates node.read for n from data the listing already loaded.
func (i *Inventory) mayRead(actor domain.Actor, l lookups, n domain.Node) bool {
	target := policy.Target{
		Ref:   domain.ResourceRef{Type: domain.ResourceNode, ID: n.ID},
		Attrs: policy.Attributes{Tags: n.Tags, Node: n.Name, Provider: l.providers[n.ProviderID].Name},
	}
	if env, ok := l.envs[derefID(n.EnvironmentID)]; ok {
		target.Attrs.Environment, target.Attrs.EnvironmentRisk, target.Attrs.ApprovalsRequired = env.Name, env.RiskLevel, env.ApprovalsRequired
	}
	return i.authorize(policy.Request{Actor: actor, Action: "node.read", Targets: []policy.Target{target}}).Decision == policy.DecisionAllow
}

// GetNode returns one node. focus=true renews the node's focus lease so the
// refresher keeps it fresh while a client has it open (plan Q6).
func (i *Inventory) GetNode(ctx context.Context, by Caller, id domain.ID, focus bool) (wire.Node, error) {
	node, err := i.readableNode(ctx, by, id, "node.read")
	if err != nil {
		return wire.Node{}, err
	}
	if focus {
		i.focus.Touch(id)
	}
	return i.nodeView(ctx, i.cfg.DB.Reader(), node)
}

// readableNode loads the node after authorizing action on it, auditing a refusal.
func (i *Inventory) readableNode(ctx context.Context, by Caller, id domain.ID, action string) (domain.Node, error) {
	q := i.cfg.DB.Reader()
	if _, err := i.authorizeOn(ctx, by, action, domain.ResourceRef{Type: domain.ResourceNode, ID: id}); err != nil {
		return domain.Node{}, err
	}
	return database.GetNode(ctx, q, id)
}

// authorizeOn evaluates a query action on a node or service for the caller.
// A refusal is audited (spec §11.3) and returned.
func (c core) authorizeOn(ctx context.Context, by Caller, action string, ref domain.ResourceRef) (domain.Actor, error) {
	q := c.cfg.DB.Reader()
	actor, err := c.beginRequest(ctx, q, by)
	if err != nil {
		return domain.Actor{}, err
	}
	target, err := resolve(ctx, q, ref)
	if err != nil {
		return domain.Actor{}, err
	}
	res := c.authorize(policy.Request{Actor: actor, Action: action, Targets: []policy.Target{target.target}})
	if res.Decision == policy.DecisionAllow {
		return actor, nil
	}
	err = c.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := c.auditDecision(ctx, tx, actor, action, ref, res); err != nil {
			return err
		}
		return reject(decisionError(res))
	})
	return domain.Actor{}, err
}

// ConnectInfo is what an interactive client needs to run OpenSSH against the
// node as admin_user (spec §8.4). The request is audited as node.connect.
func (i *Inventory) ConnectInfo(ctx context.Context, by Caller, id domain.ID) (wire.ConnectInfo, error) {
	actor, err := i.authorizeOn(ctx, by, "node.connect", domain.ResourceRef{Type: domain.ResourceNode, ID: id})
	if err != nil {
		return wire.ConnectInfo{}, err
	}
	node, err := database.GetNode(ctx, i.cfg.DB.Reader(), id)
	if err != nil {
		return wire.ConnectInfo{}, err
	}
	info := connectInfoOf(node)
	err = i.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		return i.emit(ctx, tx, actor, "node.connect", domain.ResourceRef{Type: domain.ResourceNode, ID: id},
			domain.ResultSucceeded, map[string]any{"user": info.User, "host": info.Host, "port": info.Port})
	})
	return info, err
}

func connectInfoOf(n domain.Node) wire.ConnectInfo {
	return wire.ConnectInfo{
		NodeID: n.ID, Host: n.Endpoint.Host, Port: n.Endpoint.Port, User: n.Endpoint.AdminUser,
		HostPublicKey: n.Endpoint.HostPublicKey, HostKeyAlias: "sm-" + n.ID.String(),
	}
}

// ListServices lists the services of a node the caller may read.
func (i *Inventory) ListServices(ctx context.Context, by Caller, node domain.ID, page wire.PageQuery) (wire.Page[wire.Service], error) {
	if _, err := i.authorizeOn(ctx, by, "service.read", domain.ResourceRef{Type: domain.ResourceNode, ID: node}); err != nil {
		return wire.Page[wire.Service]{}, err
	}
	q := i.cfg.DB.Reader()
	n, err := database.GetNode(ctx, q, node)
	if err != nil {
		return wire.Page[wire.Service]{}, err
	}
	services, err := database.ListServices(ctx, q, node)
	if err != nil {
		return wire.Page[wire.Service]{}, err
	}
	runtimesByID, err := runtimeTypes(ctx, q, node)
	if err != nil {
		return wire.Page[wire.Service]{}, err
	}
	setup, err := loadSetup(ctx, q, node)
	if err != nil {
		return wire.Page[wire.Service]{}, err
	}
	paged, err := paginate(services, page, func(s domain.Service) domain.ID { return s.ID })
	if err != nil {
		return wire.Page[wire.Service]{}, err
	}
	out := wire.Page[wire.Service]{Items: make([]wire.Service, len(paged.items)), NextCursor: paged.next}
	for k, s := range paged.items {
		out.Items[k] = serviceView(s, n.Name, runtimesByID[s.RuntimeID], setup)
	}
	return out, nil
}

func runtimeTypes(ctx context.Context, q database.Querier, node domain.ID) (map[domain.ID]domain.RuntimeType, error) {
	all, err := database.ListRuntimes(ctx, q, node)
	if err != nil {
		return nil, err
	}
	out := make(map[domain.ID]domain.RuntimeType, len(all))
	for _, r := range all {
		out[r.ID] = domain.RuntimeType(r.Type)
	}
	return out, nil
}

// GetService returns one service.
func (i *Inventory) GetService(ctx context.Context, by Caller, id domain.ID) (wire.Service, error) {
	if _, err := i.authorizeOn(ctx, by, "service.read", domain.ResourceRef{Type: domain.ResourceService, ID: id}); err != nil {
		return wire.Service{}, err
	}
	q := i.cfg.DB.Reader()
	s, err := database.GetService(ctx, q, id)
	if err != nil {
		return wire.Service{}, err
	}
	node, err := database.GetNode(ctx, q, s.NodeID)
	if err != nil {
		return wire.Service{}, err
	}
	runtime, err := database.GetRuntime(ctx, q, s.RuntimeID)
	if err != nil {
		return wire.Service{}, err
	}
	setup, err := loadSetup(ctx, q, node.ID)
	if err != nil {
		return wire.Service{}, err
	}
	return serviceView(s, node.Name, domain.RuntimeType(runtime.Type), setup), nil
}

// ServiceLogs reads the last lines of the service's logs from the node. This
// is one of the few reads that dials (ADR-0014); the transport bounds it by
// ssh.command_timeout and by output limits, and the text is sanitized.
func (i *Inventory) ServiceLogs(ctx context.Context, by Caller, id domain.ID, lines int) (wire.LogChunk, error) {
	if lines == 0 {
		lines = wire.DefaultLogLines
	}
	if lines < 1 || lines > runtimes.MaxLogLines {
		return wire.LogChunk{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("lines must be in 1..%d", runtimes.MaxLogLines))
	}
	if _, err := i.authorizeOn(ctx, by, "service.logs", domain.ResourceRef{Type: domain.ResourceService, ID: id}); err != nil {
		return wire.LogChunk{}, err
	}
	q := i.cfg.DB.Reader()
	s, err := database.GetService(ctx, q, id)
	if err != nil {
		return wire.LogChunk{}, err
	}
	node, err := database.GetNode(ctx, q, s.NodeID)
	if err != nil {
		return wire.LogChunk{}, err
	}
	setup, err := loadSetup(ctx, q, node.ID)
	if err != nil {
		return wire.LogChunk{}, err
	}
	adapter, err := i.adapters.For(domain.ServiceKind(s.Kind))
	if err != nil {
		return wire.LogChunk{}, err
	}
	ex, err := i.conn.Automated(node, setup)
	if err != nil {
		return wire.LogChunk{}, err
	}
	chunk, err := adapter.Logs(ctx, ex, serviceRef(s), runtimes.LogQuery{Lines: lines, Mode: logsModeOf(setup)})
	if err != nil {
		return wire.LogChunk{}, err
	}
	return wire.LogChunk{ServiceID: id, Lines: i.redacted(chunk.Lines), Truncated: chunk.Truncated, CollectedAt: i.cfg.Clock.Now()}, nil
}

// redacted scrubs secret patterns from the whole text before it is split
// again, so a credential that spans lines (a PEM block) cannot survive.
func (i *Inventory) redacted(lines []string) []string {
	if !i.redactLogs || len(lines) == 0 {
		return nonNil(lines)
	}
	return strings.Split(audit.ScrubString(strings.Join(lines, "\n")), "\n")
}

func logsModeOf(setup *runtimes.SetupMeta) runtimes.LogsMode {
	if setup != nil && setup.LogsMode != "" {
		return setup.LogsMode
	}
	return runtimes.LogsJournalGroup
}

func serviceRef(s domain.Service) runtimes.ServiceRef {
	return runtimes.ServiceRef{NodeID: s.NodeID, Kind: domain.ServiceKind(s.Kind), NativeID: s.NativeID, Name: s.Name}
}

// ---- pagination ----------------------------------------------------------------

type pageOf[T any] struct {
	items []T
	next  string
}

// paginate slices items, already in a stable order, by an opaque cursor that
// is the id of the last item of the previous page.
func paginate[T any](items []T, q wire.PageQuery, idOf func(T) domain.ID) (pageOf[T], error) {
	limit := q.Limit
	if limit <= 0 {
		limit = wire.DefaultLimit
	}
	limit = min(limit, maxNodesPage)
	start := 0
	if q.Cursor != "" {
		start = slices.IndexFunc(items, func(item T) bool { return idOf(item).String() == q.Cursor })
		if start < 0 {
			return pageOf[T]{}, smerr.New(smerr.CodeInvalidArgument, "", "invalid cursor")
		}
		start++
	}
	end := min(start+limit, len(items))
	page := pageOf[T]{items: items[start:end]}
	if end < len(items) {
		page.next = idOf(items[end-1]).String()
	}
	return page, nil
}
