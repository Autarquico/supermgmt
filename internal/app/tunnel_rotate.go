package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// Audit events of the service-token rotation.
const (
	eventRotationStarted  = "cloudflare.access_token.rotation_started"
	eventTokenAdmitted    = "cloudflare.access_token.admitted" //nolint:gosec // an audit action name, not a credential
	eventTokenSwitched    = "cloudflare.access_token.switched" //nolint:gosec // an audit action name, not a credential
	eventTokenRetired     = "cloudflare.access_token.retired"  //nolint:gosec // an audit action name, not a credential
	eventRotationFinished = "cloudflare.access_token.rotated"
)

// pendingSecretSuffix names the secret that holds the new token's credential
// between its creation (the only moment Cloudflare shows it) and the switch of
// the runtime secret.
const pendingSecretSuffix = "-pending"

// retiredCredential replaces the pending credential once the rotation is
// over. The store keeps every version and has no delete, so the latest
// version of the pending secret is overwritten with a value that is no
// credential.
const retiredCredential = audit.Secret("retired")

// tunnelRotateHandler executes cloudflare.access_token.rotate (ADR-0037):
// create the new token, admit it next to the old one in the owned Service Auth
// policy, switch the runtime secret, remove the old token from the policy and
// delete it. At every step the credential the dialler holds is admitted.
type tunnelRotateHandler struct {
	store  *jobs.Store
	tunnel *tunnelEngine
}

func (h tunnelRotateHandler) Run(ctx context.Context, lease jobs.Lease) error {
	job, err := h.store.Get(ctx, h.tunnel.cfg.DB.Reader(), lease.JobID)
	if err != nil {
		return err
	}
	run, err := h.tunnel.newInstanceRun(ctx, lease, job)
	if err != nil {
		return err
	}
	return run.rotate(ctx)
}

// rotatedTokenName is the name of the token that replaces the one with
// currentID. It differs from the name of the current token, so both can be
// found by name without confusing them, and it is deterministic, so a token
// whose answer was lost is found and deleted by the retry.
func rotatedTokenName(instanceID, currentID string) string {
	sum := sha256.Sum256([]byte(currentID))
	return cloudflare.ServiceTokenName(instanceID) + "-" + hex.EncodeToString(sum[:4])
}

func (r *tunnelRun) pendingSecretName() string { return r.accessSecretName() + pendingSecretSuffix }

// rotate walks the rotation phases of the instance state from wherever a
// previous attempt stopped.
func (r *tunnelRun) rotate(ctx context.Context) error {
	state, err := database.GetCloudflareState(ctx, r.cfg.DB.Reader())
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "no Access service token exists yet: run a tunnel setup first")
	}
	if err != nil {
		return err
	}
	if state.AccountID != r.opts.Config.AccountID {
		return smerr.New(smerr.CodeConflict, "", "the instance's Cloudflare state belongs to another account; one instance uses one account")
	}
	steps := []struct {
		from database.RotationPhase
		name string
		run  func(context.Context, database.CloudflareState) (database.CloudflareState, error)
	}{
		{database.RotationIdle, "creation of the new token", r.rotationCreate},
		{database.RotationCreated, "admission of the new token", r.rotationAdmit},
		{database.RotationPolicyUpdated, "switch of the runtime secret", r.rotationSwitch},
		{database.RotationRetiring, "retirement of the old token", r.rotationRetire},
	}
	for _, s := range steps {
		if state.Rotation != s.from {
			continue
		}
		if state, err = s.run(ctx, state); err != nil {
			return fmt.Errorf("token rotation failed at %s: %w", s.name, err)
		}
	}
	return r.auditInstance(ctx, eventRotationFinished, map[string]any{"token_id": state.Token.ID})
}

// rotationCreate creates the new token and keeps its credential before
// anything refers to it: a crash after the token exists leaves an orphan found
// by its name, never a recorded token without a credential.
func (r *tunnelRun) rotationCreate(ctx context.Context, state database.CloudflareState) (database.CloudflareState, error) {
	name := rotatedTokenName(r.instanceID, state.Token.ID)
	if err := r.deleteTokensNamed(ctx, name); err != nil {
		return state, err
	}
	created, err := r.createServiceToken(ctx, name)
	if err != nil {
		return state, err
	}
	packed := audit.Secret(created.ClientID + ":" + created.ClientSecret.Reveal())
	if _, err := r.opts.Secrets.Put(ctx, r.pendingSecretName(), packed, map[string]any{"purpose": "cloudflare access service token (rotation)"}); err != nil {
		return state, err
	}
	state.Rotation = database.RotationCreated
	state.Pending = &database.CloudflareToken{ID: created.ID, Name: created.Name, CreatedAt: created.CreatedAt, ExpiresAt: created.ExpiresAt}
	return r.saveState(ctx, state, eventRotationStarted, map[string]any{"old_token_id": state.Token.ID, "new_token_id": created.ID})
}

// rotationAdmit adds the new token to the owned Service Auth policy next to
// the old one. From here both are admitted.
func (r *tunnelRun) rotationAdmit(ctx context.Context, state database.CloudflareState) (database.CloudflareState, error) {
	state, err := r.setServiceTokens(ctx, state, []string{state.Token.ID, state.Pending.ID})
	if err != nil {
		return state, err
	}
	state.Rotation = database.RotationPolicyUpdated
	return r.saveState(ctx, state, eventTokenAdmitted, map[string]any{"new_token_id": state.Pending.ID, "policy_id": state.ServicePolicyID})
}

// rotationSwitch stores the new credential as the next version of the runtime
// secret. The dialler reads the secret on every dial, so the next connection
// presents the new token; both tokens are admitted, so connections already
// open and dials in flight are unaffected.
func (r *tunnelRun) rotationSwitch(ctx context.Context, state database.CloudflareState) (database.CloudflareState, error) {
	pending, err := r.pendingCredential(ctx, state)
	if err != nil {
		return state, err
	}
	if current, err := r.opts.Secrets.Get(ctx, secrets.Ref{Name: r.accessSecretName()}); err != nil || !holdsClientID(current, pending.ClientID) {
		if err != nil && smerr.CodeOf(err) != smerr.CodeNotFound {
			return state, err
		}
		if err := r.mayMutate(ctx); err != nil {
			return state, err
		}
		packed := audit.Secret(pending.ClientID + ":" + pending.ClientSecret.Reveal())
		if _, err := r.opts.Secrets.Put(ctx, r.accessSecretName(), packed, map[string]any{"purpose": "cloudflare access service token"}); err != nil {
			return state, err
		}
	}
	old := state.Token
	state.Token, state.Pending = *state.Pending, &old // from here the new token is the active one
	state.Rotation = database.RotationRetiring
	return r.saveState(ctx, state, eventTokenSwitched, map[string]any{"token_id": state.Token.ID, "retiring_token_id": old.ID})
}

// pendingCredential reads the new token's credential and checks it is the one
// of the pending token Cloudflare lists.
func (r *tunnelRun) pendingCredential(ctx context.Context, state database.CloudflareState) (ssh.AccessToken, error) {
	stored, err := r.opts.Secrets.Get(ctx, secrets.Ref{Name: r.pendingSecretName()})
	if err != nil {
		return ssh.AccessToken{}, err
	}
	parsed, err := ssh.ParseAccessToken(stored.Reveal())
	if err != nil {
		return ssh.AccessToken{}, err
	}
	tokens, err := r.api.FindServiceTokens(ctx, state.Pending.Name)
	if err != nil {
		return ssh.AccessToken{}, err
	}
	if !slices.ContainsFunc(tokens, func(t cloudflare.ServiceToken) bool {
		return t.ID == state.Pending.ID && t.ClientID == parsed.ClientID
	}) {
		return ssh.AccessToken{}, smerr.New(smerr.CodeConflict, "", "the new Access service token or its stored credential is missing or does not match; remove the new token in Cloudflare and rotate again")
	}
	return parsed, nil
}

func holdsClientID(secret audit.Secret, clientID string) bool {
	parsed, err := ssh.ParseAccessToken(secret.Reveal())
	return err == nil && parsed.ClientID == clientID
}

// rotationRetire removes the old token from the policy, which leaves only the
// token the dialler holds, and only then deletes it.
func (r *tunnelRun) rotationRetire(ctx context.Context, state database.CloudflareState) (database.CloudflareState, error) {
	old := *state.Pending
	state, err := r.setServiceTokens(ctx, state, []string{state.Token.ID})
	if err != nil {
		return state, err
	}
	tokens, err := r.api.FindServiceTokens(ctx, old.Name)
	if err != nil {
		return state, err
	}
	if slices.ContainsFunc(tokens, func(t cloudflare.ServiceToken) bool { return t.ID == old.ID }) {
		if err := r.mayMutate(ctx); err != nil {
			return state, err
		}
		if err := r.api.DeleteServiceToken(ctx, old.ID); err != nil && !cloudflare.IsNotFound(err) {
			return state, err
		}
	}
	if _, err := r.opts.Secrets.Put(ctx, r.pendingSecretName(), retiredCredential, map[string]any{"purpose": "cloudflare access service token (rotation finished)"}); err != nil {
		return state, err
	}
	state.Rotation, state.Pending = database.RotationIdle, nil
	return r.saveState(ctx, state, eventTokenRetired, map[string]any{"token_id": old.ID})
}

// setServiceTokens makes the owned Service Auth policy admit exactly ids. A
// policy that vanished is created again with them.
func (r *tunnelRun) setServiceTokens(ctx context.Context, state database.CloudflareState, ids []string) (database.CloudflareState, error) {
	return r.ensurePolicyPair(ctx, state, ids)
}
