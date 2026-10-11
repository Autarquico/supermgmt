package app

import (
	"context"
	"errors"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// idempotencyTTL is how long a stored response can be replayed (spec §23).
const idempotencyTTL = 24 * time.Hour

// Idempotency is the idempotent-request protocol of spec §23 and ADR-0014.
// RequestHash is the request identity the API computed (method, route pattern,
// concrete path, If-Match and raw body); Respond turns the outcome of the
// mutation into the exact wire bytes that are stored with it.
type Idempotency struct {
	Key, Method, Path, RequestHash string
	Respond                        Responder
}

// Responder builds the final HTTP status and the exact envelope bytes of a
// response. It runs INSIDE the write transaction, so the bytes that are
// replayed later are the bytes the first caller received. The app calls it
// only for a successful mutation (err is nil): a request that fails or is
// refused stores nothing, and its caller renders the error itself.
type Responder func(result any, err error) (status int, envelope []byte)

// Replay is returned, as the error, instead of executing a request whose
// Idempotency-Key already has a stored answer. The API writes Status and
// Envelope verbatim and adds Idempotent-Replayed: true.
type Replay struct {
	Status   int
	Envelope []byte
}

func (*Replay) Error() string { return "idempotent replay" }

// jobCarrier is implemented by results that created a job, so the idempotency
// record can point at it.
type jobCarrier interface{ createdJob() *domain.ID }

// DirectResult is the outcome of a `direct` action (spec §11.2): Applied when
// it ran inside the request transaction, Pending when policy required
// approval and it became a control_plane.apply job. Exactly one is non-nil.
type DirectResult[T any] struct {
	Applied *T
	Pending *Submission
}

func (d DirectResult[T]) createdJob() *domain.ID {
	if d.Pending == nil {
		return nil
	}
	return &d.Pending.Job.ID
}

func (s Submission) createdJob() *domain.ID { return &s.Job.ID }

type sourceKey struct{}

func sourceOf(ctx context.Context) string {
	source, _ := ctx.Value(sourceKey{}).(string)
	return source
}

// rejection is an outcome the caller must see as an error although what the
// transaction wrote before it (an audit event, a plan expiry) has to commit.
type rejection struct{ err error }

func (r rejection) Error() string { return r.err.Error() }
func (r rejection) Unwrap() error { return r.err }

// reject ends a write with err while keeping what the transaction has written.
func reject(err error) error { return rejection{err} }

// commit runs fn in one writer transaction. While a restore hold is in force
// it first refuses, with RESTORE_HOLD, every write that is not on the hold's
// exception list (hold.go). A plain error rolls everything
// back; an error wrapped by reject commits and is then returned. When by
// carries an Idempotency-Key the transaction first looks for a stored answer
// (replayed as a *Replay error, fn not run) and otherwise stores the answer
// next to the mutation. Nothing is stored for an error: a rolled-back mutation
// leaves no record (spec §23).
func commit[T any](ctx context.Context, c core, by Caller, fn func(ctx context.Context, tx *database.Tx) (T, error)) (T, error) {
	var (
		out      T
		rejected error
	)
	if by.Source != "" {
		ctx = context.WithValue(ctx, sourceKey{}, by.Source)
	}
	action := actionOf(ctx)
	err := c.cfg.DB.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := guardHold(ctx, tx, action, by); err != nil {
			return err
		}
		if by.Idempotency != nil {
			if replay, err := c.storedAnswer(ctx, tx, by); replay != nil || err != nil {
				return replayOr(replay, err)
			}
		}
		result, err := fn(ctx, tx)
		var r rejection
		if errors.As(err, &r) {
			rejected = r.err
			return nil
		}
		if err != nil {
			return err
		}
		out = result
		if by.Idempotency == nil {
			return nil
		}
		return c.storeAnswer(ctx, tx, by, result)
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return out, rejected
}

func replayOr(replay *Replay, err error) error {
	if err != nil {
		return err
	}
	return replay
}

// storedAnswer returns the answer recorded for the caller's key, or nil.
func (c core) storedAnswer(ctx context.Context, q database.Querier, by Caller) (*Replay, error) {
	rec, err := database.GetIdempotencyRecord(ctx, q, by.ID, by.Idempotency.Key)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := c.cfg.Clock.Now()
	if !now.Before(rec.ExpiresAt) {
		_, err := database.SweepIdempotencyRecords(ctx, q, now)
		return nil, err
	}
	if rec.RequestHash != by.Idempotency.RequestHash {
		return nil, smerr.FromReason(smerr.ReasonIdempotencyMismatch, "the Idempotency-Key was used for a different request")
	}
	return &Replay{Status: rec.StatusCode, Envelope: rec.ResponseJSON}, nil
}

func (c core) storeAnswer(ctx context.Context, q database.Querier, by Caller, result any) error {
	status, envelope := by.Idempotency.Respond(result, nil)
	now := c.cfg.Clock.Now()
	var job *domain.ID
	if carrier, ok := result.(jobCarrier); ok {
		job = carrier.createdJob()
	}
	return database.InsertIdempotencyRecord(ctx, q, database.IdempotencyRecord{
		IdentityID:   by.ID,
		Key:          by.Idempotency.Key,
		Method:       by.Idempotency.Method,
		Path:         by.Idempotency.Path,
		RequestHash:  by.Idempotency.RequestHash,
		StatusCode:   status,
		ResponseJSON: envelope,
		JobID:        job,
		CreatedAt:    now,
		ExpiresAt:    now.Add(idempotencyTTL),
	})
}

// write runs fn like commit for services that return no result and take no key.
func (c core) write(ctx context.Context, fn func(ctx context.Context, tx *database.Tx) error) error {
	_, err := commit(ctx, c, Caller{}, func(ctx context.Context, tx *database.Tx) (struct{}, error) {
		return struct{}{}, fn(ctx, tx)
	})
	return err
}
