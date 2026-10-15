package app

import (
	"context"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// serviceTokenAttempts bounds create-then-find cycles after lost answers.
const serviceTokenAttempts = 3

// ensureInstanceAccess makes sure the instance's runtime service token and its
// two reusable policies exist and are recorded (cloudflare_state). The caller
// holds the instance-wide job lock, so no other tunnel job interleaves.
func (r *tunnelRun) ensureInstanceAccess(ctx context.Context) (database.CloudflareState, error) {
	state, err := r.ensureServiceToken(ctx)
	if err != nil {
		return state, err
	}
	return r.ensurePolicies(ctx, state)
}

func (r *tunnelRun) instanceRef() domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceInstance, ID: domain.ID(r.instanceID)}
}

// auditInstance writes one event about an instance-level Cloudflare object.
func (r *tunnelRun) auditInstance(ctx context.Context, action string, data map[string]any) error {
	return r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		return r.emitInstance(ctx, tx, action, data)
	})
}

func (r *tunnelRun) emitInstance(ctx context.Context, tx *database.Tx, action string, data map[string]any) error {
	actor, err := loadActor(ctx, tx, r.job.ActorID, credentialOf(r.job))
	if err != nil {
		return err
	}
	data["job_id"] = r.job.ID.String()
	if r.op.ID != "" {
		data["operation_id"] = r.op.ID.String()
	}
	return r.emit(ctx, tx, actor, action, r.instanceRef(), domain.ResultSucceeded, data)
}

// saveState stores the instance state against the revision it was read at and
// audits the change in the same transaction.
func (r *tunnelRun) saveState(ctx context.Context, state database.CloudflareState, action string, data map[string]any) (database.CloudflareState, error) {
	var saved database.CloudflareState
	err := r.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := r.lease.Fence(ctx, tx); err != nil {
			return err
		}
		var err error
		saved, err = database.SaveCloudflareState(ctx, tx, state, state.Revision, r.cfg.Clock.Now())
		if err != nil {
			return err
		}
		return r.emitInstance(ctx, tx, action, data)
	})
	if err != nil {
		return state, err
	}
	return saved, nil
}

func (r *tunnelRun) accessSecretName() string {
	name, _ := secretName(r.opts.Config.AccessTokenRef) // validated when the engine was built
	return name
}

// ensureServiceToken creates the instance's Access service token on first use.
// The token's ID is recorded before its secret is stored; a token whose answer
// was lost, or whose secret never reached the store, is deleted (found by name)
// and created again.
func (r *tunnelRun) ensureServiceToken(ctx context.Context) (database.CloudflareState, error) {
	name := cloudflare.ServiceTokenName(r.instanceID)
	state, err := database.GetCloudflareState(ctx, r.cfg.DB.Reader())
	switch {
	case err == nil:
		if state.AccountID != r.opts.Config.AccountID {
			return state, smerr.New(smerr.CodeConflict, "", "the instance's Cloudflare state belongs to another account; one instance uses one account")
		}
		if state.Rotation != database.RotationIdle {
			return state, nil // a rotation owns the token until it finishes
		}
		healthy, err := r.tokenHealthy(ctx, state)
		if err != nil || healthy {
			return state, err
		}
		// The recorded token (which a rotation may have renamed) is replaced.
		if err := r.deleteTokensNamed(ctx, state.Token.Name); err != nil {
			return state, err
		}
	case smerr.CodeOf(err) != smerr.CodeNotFound:
		return state, err
	}
	if err := r.deleteTokensNamed(ctx, name); err != nil {
		return state, err
	}
	created, err := r.createServiceToken(ctx, name)
	if err != nil {
		return state, err
	}
	state.AccountID = r.opts.Config.AccountID
	state.Token = database.CloudflareToken{ID: created.ID, Name: created.Name, CreatedAt: created.CreatedAt, ExpiresAt: created.ExpiresAt}
	state, err = r.saveState(ctx, state, eventServiceTokenNew, map[string]any{"token_id": created.ID, "name": created.Name})
	if err != nil {
		return state, err
	}
	packed := audit.Secret(created.ClientID + ":" + created.ClientSecret.Reveal())
	if _, err := r.opts.Secrets.Put(ctx, r.accessSecretName(), packed, map[string]any{"purpose": "cloudflare access service token"}); err != nil {
		return state, err
	}
	return state, nil
}

// tokenHealthy reports whether the recorded token still exists and the stored
// secret belongs to it.
func (r *tunnelRun) tokenHealthy(ctx context.Context, state database.CloudflareState) (bool, error) {
	tokens, err := r.api.FindServiceTokens(ctx, state.Token.Name)
	if err != nil {
		return false, err
	}
	i := slices.IndexFunc(tokens, func(t cloudflare.ServiceToken) bool { return t.ID == state.Token.ID })
	if i < 0 {
		return false, r.auditVanished(ctx, "service token", state.Token.ID)
	}
	stored, err := r.opts.Secrets.Get(ctx, secrets.Ref{Name: r.accessSecretName()})
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	parsed, err := ssh.ParseAccessToken(stored.Reveal())
	return err == nil && parsed.ClientID == tokens[i].ClientID, nil
}

// deleteTokensNamed deletes every service token carrying the instance's name:
// an orphan holds a secret nobody has.
func (r *tunnelRun) deleteTokensNamed(ctx context.Context, name string) error {
	tokens, err := r.api.FindServiceTokens(ctx, name)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if err := r.mayMutate(ctx); err != nil {
			return err
		}
		if err := r.api.DeleteServiceToken(ctx, t.ID); err != nil && !cloudflare.IsNotFound(err) {
			return err
		}
		if err := r.auditInstance(ctx, eventServiceTokenGone, map[string]any{"token_id": t.ID, "name": t.Name}); err != nil {
			return err
		}
	}
	return nil
}

func (r *tunnelRun) createServiceToken(ctx context.Context, name string) (cloudflare.NewServiceToken, error) {
	var lastErr error
	for range serviceTokenAttempts {
		if err := r.mayMutate(ctx); err != nil {
			return cloudflare.NewServiceToken{}, err
		}
		created, err := r.api.CreateServiceToken(ctx, name)
		if err == nil {
			return created, nil
		}
		if !cloudflare.IsAmbiguous(err) {
			return cloudflare.NewServiceToken{}, err
		}
		lastErr = err
		// It may exist without anyone holding its secret.
		if err := r.deleteTokensNamed(ctx, name); err != nil {
			return cloudflare.NewServiceToken{}, err
		}
	}
	return cloudflare.NewServiceToken{}, lastErr
}

// ensurePolicies creates or repairs the instance's two reusable policies: the
// Service Auth policy admitting the service token and the Allow policy for the
// owners. Their IDs are recorded in the instance state.
func (r *tunnelRun) ensurePolicies(ctx context.Context, state database.CloudflareState) (database.CloudflareState, error) {
	service := cloudflare.PolicySpec{
		Name: cloudflare.ServicePolicyName(r.instanceID), Kind: cloudflare.PolicyServiceAuth, ServiceTokenIDs: []string{state.Token.ID},
	}
	if state.Rotation != database.RotationIdle {
		service.ServiceTokenIDs = nil // a rotation owns the token list; only existence is ensured
	}
	owners := cloudflare.PolicySpec{
		Name: cloudflare.OwnersPolicyName(r.instanceID), Kind: cloudflare.PolicyAllow, Emails: r.opts.Config.OwnerEmails,
	}
	state, err := r.ensurePolicy(ctx, state, state.ServicePolicyID, service)
	if err != nil {
		return state, err
	}
	return r.ensurePolicy(ctx, state, state.OwnersPolicyID, owners)
}

// ensurePolicy returns the state with the ID of the policy spec describes.
func (r *tunnelRun) ensurePolicy(ctx context.Context, state database.CloudflareState, recorded string, spec cloudflare.PolicySpec) (database.CloudflareState, error) {
	listOnlyExistence := spec.Kind == cloudflare.PolicyServiceAuth && len(spec.ServiceTokenIDs) == 0
	matches := func(p cloudflare.AccessPolicy) bool {
		if listOnlyExistence {
			return p.UnknownRules == 0
		}
		return p.UnknownRules == 0 && p.Decision == decisionOf(spec.Kind) &&
			sameSet(p.ServiceTokenIDs, spec.ServiceTokenIDs) && sameSet(lower(p.Emails), lower(spec.Emails))
	}
	policy, how, err := ensureNamed(ctx, r, namedObject[cloudflare.AccessPolicy]{
		kind: "Access policy", name: spec.Name, known: recorded, recreate: true,
		find: func(ctx context.Context) ([]cloudflare.AccessPolicy, error) {
			return r.api.FindAccessPolicies(ctx, spec.Name)
		},
		create: func(ctx context.Context) (cloudflare.AccessPolicy, error) { return r.api.CreateAccessPolicy(ctx, spec) },
		idOf:   func(p cloudflare.AccessPolicy) string { return p.ID },
		adoptable: func(p cloudflare.AccessPolicy) bool {
			return r.createdSince(p.CreatedAt) && matches(p)
		},
	})
	if err != nil {
		return state, err
	}
	action := eventPolicyCreated
	switch {
	case how == foundRecorded && matches(policy):
		return state, nil
	case how == foundRecorded:
		if err := r.mayMutate(ctx); err != nil {
			return state, err
		}
		if _, err := r.api.UpdateAccessPolicy(ctx, policy.ID, spec); err != nil {
			return state, err
		}
		action = eventPolicyUpdated
	case how == foundAdopted:
		action = eventPolicyAdopted
	}
	if policy.ID == recorded {
		return state, r.auditInstance(ctx, action, map[string]any{"policy_id": policy.ID, "name": spec.Name})
	}
	next := state
	if spec.Kind == cloudflare.PolicyServiceAuth {
		next.ServicePolicyID = policy.ID
	} else {
		next.OwnersPolicyID = policy.ID
	}
	if recorded != "" {
		// The policy was recreated under a new ID: every application of the
		// instance still refers to the dead one. Repair them before the new ID
		// is recorded, so a crash in between repeats the repair.
		if err := r.reattachAccessApps(ctx, next); err != nil {
			return state, err
		}
	}
	return r.saveState(ctx, next, action, map[string]any{"policy_id": policy.ID, "name": spec.Name})
}

func decisionOf(kind cloudflare.PolicyKind) string {
	if kind == cloudflare.PolicyServiceAuth {
		return "non_identity"
	}
	return "allow"
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// reattachAccessApps points every Access application this instance owns at the
// policies of state. Applications that are gone or already right are left
// alone.
func (r *tunnelRun) reattachAccessApps(ctx context.Context, state database.CloudflareState) error {
	nodes, err := database.ListNodes(ctx, r.cfg.DB.Reader())
	if err != nil {
		return err
	}
	want := []string{state.ServicePolicyID, state.OwnersPolicyID}
	for _, node := range nodes {
		recorded, err := r.recordedAccessApp(ctx, node.ID)
		if err != nil {
			return err
		}
		if recorded == "" {
			continue
		}
		name := cloudflare.AccessAppName(r.instanceID, node.ID.String())
		apps, err := r.api.FindAccessApps(ctx, name)
		if err != nil {
			return err
		}
		for _, app := range apps {
			if app.ID != recorded || slices.Equal(app.PolicyIDs, want) {
				continue
			}
			if err := r.mayMutate(ctx); err != nil {
				return err
			}
			spec := cloudflare.AppSpec{Name: app.Name, Domain: app.Domain, PolicyIDs: want, AllowedIdPs: app.AllowedIdPs}
			if _, err := r.api.UpdateAccessApp(ctx, app.ID, spec); err != nil {
				return err
			}
			if err := r.auditInstance(ctx, eventAccessAppUpdated, map[string]any{"access_app_id": app.ID, "name": app.Name, "node_id": node.ID.String()}); err != nil {
				return err
			}
		}
	}
	return nil
}

// recordedAccessApp is the ID of the node's Access application as its newest
// operation record holds it, "" for a node without one in the configured
// account (never tunnelled, or disabled since).
func (r *tunnelRun) recordedAccessApp(ctx context.Context, nodeID domain.ID) (string, error) {
	ops, err := database.ListTunnelOperations(ctx, r.cfg.DB.Reader(), nodeID)
	if err != nil {
		return "", err
	}
	for _, op := range ops {
		switch {
		case op.AccountID != r.opts.Config.AccountID:
			return "", nil
		case op.Kind == database.TunnelDisable && op.Phase.Finished():
			return "", nil
		case op.Objects.AccessAppID != "":
			return op.Objects.AccessAppID, nil
		}
	}
	return "", nil
}
