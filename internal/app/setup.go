package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/discovery"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	sshnode "github.com/autarquico/supermgmt/internal/providers/ssh"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/textsafe"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	adminRoot = "root"

	// bootstrapRequirement is the preflight failure of ADR-0009 (c).
	bootstrapRequirement = "admin_user needs root or passwordless sudo for setup"

	eventPrivilegedSession = "node.setup.privileged_session"
	eventSetupCompleted    = "node.setup.completed"
)

// SSHIdentity returns the instance SSH identity, generating it on first use
// (ADR-0016). It is a function so tests need no key files.
type SSHIdentity func(ctx context.Context) (secrets.Identity, error)

// EnsureInstanceIdentity returns the instance SSH identity, generating it on
// the first start and auditing that once (event ssh_identity.generated, by the
// system actor, with the fingerprint only; ADR-0016). Call it after the
// instance row exists, so the event can name the instance.
func EnsureInstanceIdentity(ctx context.Context, cfg Config, store *secrets.Store) (secrets.Identity, error) {
	c, err := newCore(cfg)
	if err != nil {
		return secrets.Identity{}, err
	}
	id, err := secrets.EnsureSSHIdentity(ctx, store)
	if err != nil || !id.Generated {
		return id, err
	}
	err = c.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		instance, err := database.GetInstance(ctx, tx)
		if err != nil && smerr.CodeOf(err) != smerr.CodeNotFound {
			return err
		}
		return c.emit(ctx, tx, systemActor, "ssh_identity.generated",
			domain.ResourceRef{Type: domain.ResourceInstance, ID: instance.ID}, domain.ResultSucceeded,
			map[string]any{"name": id.Ref.Name, "version": id.Ref.Version, "fingerprint": id.FingerprintSHA256})
	})
	return id, err
}

// SSHIdentityOf adapts the secret store.
func SSHIdentityOf(store *secrets.Store) SSHIdentity {
	return func(ctx context.Context) (secrets.Identity, error) { return secrets.EnsureSSHIdentity(ctx, store) }
}

// setupHandler executes node.setup (ADR-0009): it provisions the dedicated
// user over admin_user, verifies it over a fresh session as that user, and only
// then records the capability. The job is idempotent, so an interrupted run is
// requeued and every step converges.
type setupHandler struct {
	core
	store    *jobs.Store
	conn     Connector
	identity SSHIdentity
	prober   *Prober
}

func (h setupHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.store.Get(ctx, h.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	node, err := database.GetNode(ctx, h.cfg.DB.Reader(), job.Resource.ID)
	if err != nil {
		return err
	}
	params, err := setupParamsOf(job)
	if err != nil {
		return err
	}
	req, err := parseSetupRequest(params)
	if err != nil {
		return err
	}
	deployRoot, err := deployRootOf(params)
	if err != nil {
		return err
	}
	id, err := h.identity(ctx)
	if err != nil {
		return err
	}
	outcome, err := h.provision(ctx, lease, job, node, req, deployRoot, id)
	if err != nil {
		return err
	}
	if err := h.verify(ctx, node, req, id, outcome); err != nil {
		return err
	}
	if err := h.record(ctx, lease, job, node, req, deployRoot, id, outcome); err != nil {
		return err
	}
	_ = h.prober.Probe(ctx, node.ID, ProbeFull, nil) // best effort: the refresher repeats it
	return nil
}

func setupParamsOf(job jobs.Job) (map[string]any, error) {
	var params map[string]any
	if err := json.Unmarshal(job.Payload, &params); err != nil {
		return nil, smerr.Wrap(err, smerr.CodeInternal, "", "node.setup job has an unreadable payload")
	}
	return params, nil
}

// deployRootParam is the node.setup plan parameter that names deploy_root (ADR-0030).
const deployRootParam = "deploy_root"

// deployRootOf reads deploy_root from the plan parameters: the default when
// absent, an INVALID_ARGUMENT unless absolute and clean.
func deployRootOf(params map[string]any) (string, error) {
	raw, present := params[deployRootParam]
	if !present {
		return templates.DefaultDeployRoot, nil
	}
	root, ok := raw.(string)
	if !ok {
		return "", smerr.New(smerr.CodeInvalidArgument, "", deployRootParam+" must be a string")
	}
	if err := templates.ValidateDeployRoot(root); err != nil {
		return "", smerr.New(smerr.CodeInvalidArgument, "", err.Error())
	}
	return root, nil
}

// provision runs the ensure steps as admin_user, bracketed by the audit events
// of the privileged session.
func (h setupHandler) provision(ctx context.Context, lease jobs.Lease, job jobs.Job, node domain.Node, req setupRequest, deployRoot string, id secrets.Identity) (systemd.SetupOutcome, error) {
	if isLocal(node) {
		return systemd.SetupOutcome{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "the local provider cannot be set up")
	}
	admin, err := h.conn.Admin(node)
	if err != nil {
		return systemd.SetupOutcome{}, err
	}
	instance, err := database.GetInstance(ctx, h.cfg.DB.Reader())
	if err != nil {
		return systemd.SetupOutcome{}, err
	}
	asRoot := node.Endpoint.AdminUser == adminRoot
	if err := h.requireBootstrap(ctx, admin, asRoot); err != nil {
		return systemd.SetupOutcome{}, err
	}
	if err := requireJQ(ctx, admin); err != nil {
		return systemd.SetupOutcome{}, err
	}
	h.sessionEvent(ctx, lease, job, node, "start", asRoot, nil)
	outcome, err := systemd.Setup(ctx, admin, systemd.SetupParams{
		User: node.Endpoint.User, InstanceID: instance.ID.String(), AuthorizedKey: id.AuthorizedKey,
		Grants: req.Grants, LogsMode: req.LogsMode, DockerAccess: req.DockerAccess, AdminIsRoot: asRoot,
	})
	if err == nil {
		err = ensureDeployRoot(ctx, admin, node.Endpoint.User, deployRoot, asRoot)
	}
	h.sessionEvent(context.WithoutCancel(ctx), lease, job, node, "end", asRoot, err)
	return outcome, err
}

// requireBootstrap checks, before anything changes, that admin_user can do
// what setup needs: be root, or run sudo without a password (ADR-0009 c).
func (h setupHandler) requireBootstrap(ctx context.Context, admin transport.Executor, asRoot bool) error {
	if asRoot {
		return nil
	}
	snapshot, err := discovery.Probe(ctx, admin)
	if err != nil {
		return err
	}
	if !snapshot.PasswordlessSudo {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", bootstrapRequirement)
	}
	return nil
}

// requireJQ refuses a node without jq before anything changes: the
// resolved-environment check of deployments needs it (ADR-0010, ADR-0030).
func requireJQ(ctx context.Context, ex transport.Executor) error {
	c, err := templates.Render("setup.jq_path", nil)
	if err != nil {
		return err
	}
	res, err := ex.Run(ctx, c)
	if err != nil {
		return err
	}
	if res.ExitStatus != 0 {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "jq is required on the node for deployments; install it and run setup again")
	}
	return nil
}

// ensureDeployRoot creates deploy_root owned by the dedicated user, 0750, so it
// can create project directories below it; it converges when the directory
// already exists (ADR-0030).
func ensureDeployRoot(ctx context.Context, ex transport.Executor, user, deployRoot string, asRoot bool) error {
	name := "setup.deploy_root"
	if !asRoot {
		name += templates.SudoVariantSuffix
	}
	c, err := templates.RenderSetup(name, map[string]string{"user": user, "path": deployRoot}, nil)
	if err != nil {
		return err
	}
	res, err := ex.Run(ctx, c)
	if err != nil {
		return fmt.Errorf("create deploy_root: %w", err)
	}
	if res.ExitStatus != 0 {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "cannot create deploy_root "+deployRoot+" (exit "+strconv.Itoa(res.ExitStatus)+")")
	}
	return nil
}

// sessionEvent audits the start or end of the privileged bootstrap session.
// A lost lease or a failed write must not mask the setup's own outcome.
func (h setupHandler) sessionEvent(ctx context.Context, lease jobs.Lease, job jobs.Job, node domain.Node, phase string, asRoot bool, cause error) {
	via, result := "sudo", domain.ResultSucceeded
	if asRoot {
		via = adminRoot
	}
	if cause != nil {
		result = domain.ResultFailed
	}
	_ = h.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		actor, err := loadActor(ctx, tx, job.ActorID, credentialOf(job))
		if err != nil {
			return err
		}
		return h.emit(ctx, tx, actor, eventPrivilegedSession, nodeRef(node.ID), result, map[string]any{
			"phase": phase, "admin_user": node.Endpoint.AdminUser, "via": via, "job_id": job.ID.String(),
		})
	})
}

// verify is ADR-0009 (f) step 8: a fresh session as the dedicated user, with
// the key version just authorized.
func (h setupHandler) verify(ctx context.Context, node domain.Node, req setupRequest, id secrets.Identity, outcome systemd.SetupOutcome) error {
	h.conn.Invalidate(node, node.Endpoint.User)
	dedicated, err := h.conn.Dedicated(node, pinnedIdentityRef(id))
	if err != nil {
		return err
	}
	if err := systemd.Verify(ctx, dedicated, systemd.VerifyParams{
		User: node.Endpoint.User, SystemctlPath: outcome.SystemctlPath, Grants: req.Grants, LogsMode: req.LogsMode,
	}); err != nil {
		return err
	}
	return verifyGroups(ctx, dedicated, node.Endpoint.User, req)
}

// verifyGroups checks the groups the fresh session really has: the account's
// own, the journal group in journal-group mode, docker with docker_access, and
// nothing else. Docker access is root-equivalent, so it is verified, not assumed.
func verifyGroups(ctx context.Context, ex transport.Executor, user string, req setupRequest) error {
	c, err := templates.Render("setup.verify_groups", map[string]string{})
	if err != nil {
		return err
	}
	res, err := ex.Run(ctx, c)
	if err != nil {
		return err
	}
	if res.ExitStatus != 0 {
		return verifyFailure("cannot read the groups of the dedicated user")
	}
	var journal, docker bool
	for _, group := range strings.Fields(string(res.Stdout)) {
		switch group {
		case user:
		case "systemd-journal", "adm":
			journal = true
		case "docker":
			docker = true
		default:
			return verifyFailure("the dedicated user belongs to the unrequested group " + textsafe.Line(group))
		}
	}
	if docker != req.DockerAccess || journal != (req.LogsMode == runtimes.LogsJournalGroup) {
		return verifyFailure("the groups of the dedicated user do not match the requested setup")
	}
	return nil
}

func verifyFailure(why string) error {
	return smerr.New(smerr.CodeCapabilityUnavailable, "", "node.setup verification failed: "+why)
}

func pinnedIdentityRef(id secrets.Identity) string {
	return sshnode.PinnedRef(runtimes.SetupMeta{KeyRef: identityRef(id), KeyVersion: id.Ref.Version})
}

func identityRef(id secrets.Identity) string { return "secret://" + id.Ref.Name }

// record writes the node.setup capability, fenced: a worker that lost its
// lease writes nothing.
func (h setupHandler) record(ctx context.Context, lease jobs.Lease, job jobs.Job, node domain.Node, req setupRequest, deployRoot string, id secrets.Identity, outcome systemd.SetupOutcome) error {
	meta := runtimes.SetupMeta{
		SetupVersion: runtimes.SetupVersion, SystemctlPath: outcome.SystemctlPath, Units: req.Grants,
		LogsMode: req.LogsMode, DockerAccess: req.DockerAccess, DeployRoot: deployRoot,
		KeyRef: identityRef(id), KeyVersion: id.Ref.Version, KeyFingerprint: id.FingerprintSHA256,
	}
	capability, err := setupCapability(meta, h.cfg.Clock.Now())
	if err != nil {
		return err
	}
	return h.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := lease.Fence(ctx, tx); err != nil {
			return err
		}
		actor, err := loadActor(ctx, tx, job.ActorID, credentialOf(job))
		if err != nil {
			return err
		}
		if err := database.SetNodeCapability(ctx, tx, node.ID, capability); err != nil {
			return err
		}
		return h.emit(ctx, tx, actor, eventSetupCompleted, nodeRef(node.ID), domain.ResultSucceeded, map[string]any{
			"key_fingerprint": id.FingerprintSHA256, "docker_access": req.DockerAccess,
			"logs_mode": string(req.LogsMode), "units": len(req.Grants), "deploy_root": deployRoot,
		})
	})
}
