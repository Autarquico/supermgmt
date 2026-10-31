package app

import (
	"context"
	"fmt"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// clockSkewAllowance is subtracted from the phase start when deciding whether
// an object was created by this operation: Cloudflare stamps objects with its
// own clock, and this host's clock may be minutes off (ADR-0037).
const clockSkewAllowance = 5 * time.Minute

// ownershipConflict means a Cloudflare object has the expected name but this
// operation did not create it. It is never adopted (ADR-0037).
type ownershipConflict struct{ inner *smerr.Error }

func (e *ownershipConflict) Error() string { return e.inner.Error() }
func (e *ownershipConflict) Unwrap() error { return e.inner }

// recordGone means a Cloudflare object this operation recorded no longer
// exists or no longer fits, and the record cannot change its IDs. The
// operation ends as failed; a new setup starts a fresh generation that
// inherits the objects, and `sm nodes tunnel disable` abandons them.
type recordGone struct{ inner *smerr.Error }

func (e *recordGone) Error() string { return e.inner.Error() }
func (e *recordGone) Unwrap() error { return e.inner }

func (r *tunnelRun) newRecordGone(what string) error {
	return &recordGone{inner: smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
		"%s; run setup again to repair it, or `sm nodes tunnel disable %s` to abandon the tunnel", what, r.node.Name))}
}

// lookupBackoff is the wait before each lookup that follows an ambiguous or
// conflicting create: Cloudflare may list a new object a few seconds late.
var lookupBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

func newOwnershipConflict(kind, name string) error {
	return &ownershipConflict{inner: smerr.New(smerr.CodeConflict, "",
		fmt.Sprintf("a Cloudflare %s named %q already exists and was not created by this operation; resolve it in Cloudflare and run setup again", kind, name))}
}

// howFound says how ensureNamed came by the object.
type howFound int

const (
	foundRecorded howFound = iota // the recorded ID matched
	foundAdopted                  // looked up by name after an ambiguous attempt
	foundCreated
)

// namedObject describes one Cloudflare object whose name is its ownership marker.
type namedObject[T any] struct {
	kind string // for messages
	name string
	// known is the recorded ID, empty when nothing was recorded yet.
	known string
	// recreate allows creating a new object when the known one is gone, after
	// auditing it. The IDs the operation itself recorded are immutable, so
	// those objects fail instead; only an ID inherited from an earlier
	// operation (or kept in the instance state) is repaired.
	recreate bool
	find     func(ctx context.Context) ([]T, error)
	create   func(ctx context.Context) (T, error)
	idOf     func(T) string
	// adoptable says whether an unrecorded object with this name is the one an
	// earlier attempt of this operation created: created no earlier than the
	// phase start and with the content this operation would have written.
	adoptable func(T) bool
}

// ensureNamed returns the object, creating it at most once. It looks up by
// name first; after an ambiguous or conflicting create it looks up again with
// a backoff, and declares a conflict only for an object it can see. The lease is checked before the
// only mutation.
func ensureNamed[T any](ctx context.Context, r *tunnelRun, o namedObject[T]) (T, howFound, error) {
	var zero T
	found, err := o.find(ctx)
	if err != nil {
		return zero, 0, err
	}
	var others []T
	for _, obj := range found {
		if o.known != "" && o.idOf(obj) == o.known {
			return obj, foundRecorded, nil
		}
		others = append(others, obj)
	}
	if o.known != "" {
		if !o.recreate {
			return zero, 0, r.newRecordGone(fmt.Sprintf("the %s recorded for this node no longer exists in Cloudflare", o.kind))
		}
		if err := r.auditVanished(ctx, o.kind, o.known); err != nil {
			return zero, 0, err
		}
	}
	return adoptOrCreate(ctx, r.fenced(), o, others)
}

// fencedCreate is what the adopt-or-create step needs of its caller: the check that precedes the only
// mutation, the wait between lookups and the error of an object that is not ours.
type fencedCreate struct {
	mayMutate func(context.Context) error
	sleep     func(context.Context, time.Duration) error
	conflict  func(kind, name string) error
}

func (r *tunnelRun) fenced() fencedCreate {
	return fencedCreate{mayMutate: r.mayMutate, sleep: r.opts.sleep, conflict: newOwnershipConflict}
}

// adoptOrCreate adopts the one unrecorded object an earlier attempt created, or creates it once. others are
// the objects of the name that are not the recorded one. After an ambiguous or conflicting create it looks
// up again with a backoff, and declares a conflict only for an object it can see.
func adoptOrCreate[T any](ctx context.Context, f fencedCreate, o namedObject[T], others []T) (T, howFound, error) {
	var zero T
	if obj, verdict := pickAdoption(others, o.adoptable); verdict != adoptNone {
		if verdict == adoptConflict {
			return zero, 0, f.conflict(o.kind, o.name)
		}
		return obj, foundAdopted, nil
	}
	if err := f.mayMutate(ctx); err != nil {
		return zero, 0, err
	}
	obj, err := o.create(ctx)
	if err == nil {
		return obj, foundCreated, nil
	}
	ambiguous := cloudflare.IsAmbiguous(err)
	if !ambiguous && !cloudflare.IsConflict(err) {
		return zero, 0, err
	}
	for _, wait := range lookupBackoff {
		if err := f.sleep(ctx, wait); err != nil {
			return zero, 0, err
		}
		if found, ferr := o.find(ctx); ferr != nil {
			return zero, 0, ferr
		} else if len(found) > 0 {
			if obj, verdict := pickAdoption(found, o.adoptable); verdict == adoptYes {
				return obj, foundAdopted, nil
			}
			return zero, 0, f.conflict(o.kind, o.name)
		}
	}
	// Nothing is visible after the backoff: the object may be this operation's
	// own and not listed yet, so it is not a conflict. The retry looks again.
	return zero, 0, err
}

// ensureRouteNamed is ensureNamed for the objects of an app route (ADR-0040). A recorded object that no
// longer exists is drift the route cannot repair, because its IDs are written once: gone says so instead of
// creating the object again. Adoption still needs the caller's adoptable rule, which fences it to objects
// created since the phase started.
func ensureRouteNamed[T any](ctx context.Context, f fencedCreate, o namedObject[T], gone func() error) (T, howFound, error) {
	var zero T
	found, err := o.find(ctx)
	if err != nil {
		return zero, 0, err
	}
	var others []T
	for _, obj := range found {
		if o.known != "" && o.idOf(obj) == o.known {
			return obj, foundRecorded, nil
		}
		others = append(others, obj)
	}
	if o.known != "" {
		return zero, 0, gone()
	}
	return adoptOrCreate(ctx, f, o, others)
}

type adoption int

const (
	adoptNone     adoption = iota // nothing to adopt
	adoptYes                      // exactly one adoptable object
	adoptConflict                 // something is there and it is not ours
)

func pickAdoption[T any](objects []T, adoptable func(T) bool) (T, adoption) {
	var zero T
	switch {
	case len(objects) == 0:
		return zero, adoptNone
	case len(objects) == 1 && adoptable(objects[0]):
		return objects[0], adoptYes
	}
	return zero, adoptConflict
}

// createdSince reports whether an object stamped created belongs to an attempt
// of the current phase.
func (r *tunnelRun) createdSince(created time.Time) bool {
	return !created.Before(r.record().PhaseStartedAt().Add(-clockSkewAllowance))
}
