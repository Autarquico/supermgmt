// Package app holds the application services of the control plane: plan
// creation and submission, approvals, and the claim-time Revalidator and
// LockPlanner the job engine calls (spec §11.3, §11.4, §20.4, §20.5, §23).
//
// Every service method runs in one writer transaction, so its state change and
// its audit events commit together (ADR-0013). Callers authenticate the
// request and hand over a Caller; roles and actor type are always read from
// the database, never from the caller.
package app

import (
	"context"
	"errors"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/policy"
)

const (
	defaultPlanTTL     = 24 * time.Hour
	defaultApprovalTTL = 15 * time.Minute
	eventSource        = "app"
)

// Config wires the services. DB, Clock, IDs, Policy and Credentials are required.
type Config struct {
	DB          *database.DB
	Clock       domain.Clock
	IDs         domain.IDGenerator
	Policy      *policy.Policy
	Credentials CredentialStatus

	PlanTTL           time.Duration // default 24h (spec §11.4)
	ApprovalTTL       time.Duration // security.approval_ttl; default 15m
	AllowSelfApproval bool          // security.allow_self_approval
}

func (c Config) validated() (Config, error) {
	switch {
	case c.DB == nil:
		return Config{}, errors.New("app: database is required")
	case c.Clock == nil:
		return Config{}, errors.New("app: clock is required")
	case c.IDs == nil:
		return Config{}, errors.New("app: id generator is required")
	case c.Policy == nil:
		return Config{}, errors.New("app: policy is required")
	case c.Credentials == nil:
		return Config{}, errors.New("app: credential status is required")
	}
	if c.PlanTTL <= 0 {
		c.PlanTTL = defaultPlanTTL
	}
	if c.ApprovalTTL <= 0 {
		c.ApprovalTTL = defaultApprovalTTL
	}
	return c, nil
}

// Caller is an authenticated request: the daemon-issued identity and the
// credential it presented (spec §11.1).
type Caller struct {
	ID         domain.ID
	Credential domain.CredentialContext
}

// core is what every service shares.
type core struct {
	cfg     Config
	emitter audit.Emitter
}

func newCore(cfg Config) (core, error) {
	cfg, err := cfg.validated()
	if err != nil {
		return core{}, err
	}
	return core{cfg: cfg, emitter: audit.Emitter{Clock: cfg.Clock, IDs: cfg.IDs, Source: eventSource}}, nil
}

// rejection is an outcome the caller must see as an error although what the
// transaction wrote before it (an audit event, a plan expiry) has to commit.
type rejection struct{ err error }

func (r rejection) Error() string { return r.err.Error() }
func (r rejection) Unwrap() error { return r.err }

// reject ends a write with err while keeping what the transaction has written.
func reject(err error) error { return rejection{err} }

// write runs fn in one writer transaction. A plain error rolls everything back;
// an error wrapped by reject commits and is then returned.
func (c core) write(ctx context.Context, fn func(ctx context.Context, tx *database.Tx) error) error {
	var rejected error
	err := c.cfg.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		err := fn(ctx, tx)
		var r rejection
		if errors.As(err, &r) {
			rejected = r.err
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	return rejected
}

func severityOf(result domain.Result) domain.Severity {
	switch result {
	case domain.ResultDenied:
		return domain.SeverityWarning
	case domain.ResultFailed:
		return domain.SeverityError
	case domain.ResultSucceeded, domain.ResultPending:
		return domain.SeverityInfo
	}
	return domain.SeverityInfo
}

func (c core) emit(ctx context.Context, q database.Querier, actor domain.Actor, action string, ref domain.ResourceRef, result domain.Result, data map[string]any) error {
	_, err := c.emitter.Emit(ctx, database.EventsIn(q), domain.Event{
		ActorType:    actor.Type,
		ActorID:      actor.ID,
		Action:       action,
		ResourceType: ref.Type,
		ResourceID:   ref.ID,
		Severity:     severityOf(result),
		Result:       result,
		Data:         data,
	})
	return err
}
