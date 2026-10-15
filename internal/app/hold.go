package app

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
)

// ActionRestoreComplete is the admin-socket operation that ends a restore
// hold (spec §29.2, `sm admin restore-complete`). It is not a catalog action.
const ActionRestoreComplete = "restore.complete"

// The admin-socket operations that write (spec §23.1). The transport stamps
// them on the request (WithAction) so the shared write paths know which
// operation they serve; both are on the hold exception list, because they are
// the recovery path: a bootstrap code and a role grant are how an admin gets
// back in during restore hold (spec §11.5, §29.2).
const (
	ActionAdminBootstrapCode = "admin.bootstrap_code"
	ActionAdminGrant         = "admin.grant"
)

// The route exemptions the transport stamps on requests that are not catalog
// actions (ADR-0012). Login, bootstrap, logout and revoking one's own token
// only create or end credentials; none of them is a control-plane write.
const (
	actionExemptAuth = "exempt:auth"
	actionExemptSelf = "exempt:self"
)

const (
	eventRestoreCompleted = "backup.restore.completed"
	holdMessage           = "the control plane is in restore hold: review sm doctor and the interrupted jobs, then an admin runs sm admin restore-complete"
)

// holdExceptions are the actions that still write during a restore hold
// (ADR-0020): resolving an interrupted job, ending the hold, the admin-socket
// recovery operations and the credential routes. Reads never
// reach the write paths. The remaining exceptions are not actions: a write
// with no principal and no action is the daemon acting for itself or a
// protocol that authenticates by other means (OIDC login and session
// creation, the bootstrap code issue and exchange, reconciliation and
// observation writes, expiry sweeps, the audit of a refused read).
var holdExceptions = []string{
	policy.ActionJobResolve, ActionRestoreComplete,
	ActionAdminBootstrapCode, ActionAdminGrant, actionExemptAuth, actionExemptSelf,
}

type actionKey struct{}

// WithAction names the API action a request stands for. The transport sets
// it from the route table on every request, so the shared write paths know
// which action they serve. A caller with a principal and no action is guarded
// during hold (fail closed).
func WithAction(ctx context.Context, action string) context.Context {
	return context.WithValue(ctx, actionKey{}, action)
}

func actionOf(ctx context.Context) string {
	action, _ := ctx.Value(actionKey{}).(string)
	return action
}

// guardsHold reports whether a write by `by` for `action` is refused while a
// restore hold is in force.
func guardsHold(action string, by Caller) bool {
	if slices.Contains(holdExceptions, action) {
		return false
	}
	return action != "" || by.ID != ""
}

// guardHold returns CONFLICT/RESTORE_HOLD when the write is guarded and the
// hold is in force. The hold is read from the database each time, inside the
// caller's transaction when it has one, so it cannot disagree with the write;
// a value that cannot be read refuses the write (fail closed).
func guardHold(ctx context.Context, q database.Querier, action string, by Caller) error {
	if !guardsHold(action, by) {
		return nil
	}
	held, err := database.GetRestoreHold(ctx, q)
	if err != nil {
		return smerr.Wrap(err, smerr.CodeConflict, smerr.ReasonRestoreHold, "the restore hold cannot be read; refusing the write")
	}
	if held {
		return smerr.FromReason(smerr.ReasonRestoreHold, holdMessage)
	}
	return nil
}

// HoldService implements the Hold port (spec §29.2 phase C, ADR-0020). It
// keeps the job engine's claim gate (jobs.Store.SetRestoreHold) in step with
// the persisted setting and refuses writes while the hold is in force.
type HoldService struct {
	core
	jobs         *jobs.Store
	afterRelease []func(context.Context)
}

var _ Hold = (*HoldService)(nil)

// NewHold validates cfg.
func NewHold(cfg Config, store *jobs.Store) (*HoldService, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("app: job store is required")
	}
	return &HoldService{core: c, jobs: store}, nil
}

// Load reads the persisted hold and closes or opens the claim gate to match.
// Call it after migrations and before any worker starts. When the value
// cannot be read the gate is closed and the error refuses the start.
func (h *HoldService) Load(ctx context.Context) (bool, error) {
	held, err := database.GetRestoreHold(ctx, h.cfg.DB.Reader())
	if err != nil {
		h.jobs.SetRestoreHold(true)
		return true, fmt.Errorf("read the restore hold: %w", err)
	}
	h.jobs.SetRestoreHold(held)
	return held, nil
}

// Guard returns CONFLICT/RESTORE_HOLD when action by `by` may not write now.
// The transport calls it for every route that writes, with the route's
// action; the shared write path calls the same check for the writes that
// reach it.
func (h *HoldService) Guard(ctx context.Context, action string, by Caller) error {
	return guardHold(ctx, h.cfg.DB.Reader(), action, by)
}

// Complete ends the hold (action restore.complete, admin socket only): it
// clears the persisted setting and audits the decision in one transaction,
// then opens the claim gate. Completing when no hold is in force changes
// nothing.
func (h *HoldService) Complete(ctx context.Context, peerUID int) error {
	ctx = WithAction(ctx, ActionRestoreComplete)
	released := false
	_, err := commit(ctx, h.core, Caller{Source: adminSocketSource}, func(ctx context.Context, tx *database.Tx) (struct{}, error) {
		held, err := database.GetRestoreHold(ctx, tx)
		if err != nil || !held {
			return struct{}{}, err
		}
		if err := database.SetRestoreHold(ctx, tx, false, h.cfg.Clock.Now()); err != nil {
			return struct{}{}, err
		}
		released = true
		instance, err := database.GetInstance(ctx, tx)
		if err != nil && smerr.CodeOf(err) != smerr.CodeNotFound {
			return struct{}{}, err
		}
		return struct{}{}, h.emit(ctx, tx, systemActor, eventRestoreCompleted,
			domain.ResourceRef{Type: domain.ResourceInstance, ID: instance.ID}, domain.ResultSucceeded,
			map[string]any{"peer_uid": peerUID, "via": adminSocketSource})
	})
	if err == nil && released {
		h.jobs.SetRestoreHold(false)
		for _, fn := range h.afterRelease {
			fn(ctx)
		}
	}
	return err
}

// AfterRelease registers work to start once a restore hold ended (the tunnel
// reconciliation). fn runs after the gate opened, on the restore-complete
// request, and must not block.
func (h *HoldService) AfterRelease(fn func(context.Context)) {
	h.afterRelease = append(h.afterRelease, fn)
}
