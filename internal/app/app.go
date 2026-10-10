// Package app holds the application services of the control plane: plan
// creation and submission, approvals, and the claim-time Revalidator and
// LockPlanner the job engine calls (spec §11.3, §11.4, §20.4, §20.5, §23); the
// node inventory with its direct actions; service actions, node.setup and
// node.probe as job handlers; and the background Refresher and Sweeper.
//
// Every service method runs in one writer transaction, so its state change and
// its audit events commit together (ADR-0013). Mutating methods take a Caller
// that may carry an Idempotency-Key: the mutation, the response bytes and the
// stored record then commit together (ADR-0014). Callers authenticate the
// request and hand over a Caller; roles and actor type are always read from
// the database, never from the caller. Reads answer from the database and the
// connection pool state and never dial, except for logs and the first-trust
// scan.
package app

import (
	"context"
	"errors"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/runtimes"
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

	// DefaultLogsMode is ssh.logs_mode: the logs_mode a node.setup plan gets
	// when it names none. Default journal-group.
	DefaultLogsMode runtimes.LogsMode
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
	if c.DefaultLogsMode == "" {
		c.DefaultLogsMode = runtimes.LogsJournalGroup
	}
	return c, nil
}

// Caller is an authenticated request: the daemon-issued identity and the
// credential it presented (spec §11.1). Source names the transport the request
// arrived on ("api"); it is stamped on the audit events the request causes.
// Idempotency is set for mutating requests that carry an Idempotency-Key.
type Caller struct {
	ID          domain.ID
	Credential  domain.CredentialContext
	Source      string
	Idempotency *Idempotency
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
		Source:       sourceOf(ctx),
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
