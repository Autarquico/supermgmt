package oidc

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// registry is a bounded in-memory map (ADR-0018 "State and restarts"). A put
// first drops the entries that expired, then keeps one owner (the client
// address that started the login) to perOwnerLimit live entries by evicting
// that owner's oldest, then evicts the oldest overall past limit. So an
// unauthenticated caller can only churn its own slots, not other users'.
type registry[V any] struct {
	mu       sync.Mutex
	limit    int
	perOwner int
	items    map[string]entry[V]
	order    []string
}

type entry[V any] struct {
	value   V
	owner   string
	expires time.Time
}

func newRegistry[V any](limit, perOwner int) *registry[V] {
	return &registry[V]{limit: limit, perOwner: perOwner, items: make(map[string]entry[V])}
}

func (r *registry[V]) put(id, owner string, v V, expires, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropExpired(now)
	for r.ownedBy(owner) >= r.perOwner {
		r.remove(r.oldestOf(owner))
	}
	for len(r.order) >= r.limit {
		r.remove(r.order[0])
	}
	r.items[id] = entry[V]{value: v, owner: owner, expires: expires}
	r.order = append(r.order, id)
}

func (r *registry[V]) dropExpired(now time.Time) {
	for _, id := range slices.Clone(r.order) {
		if !now.Before(r.items[id].expires) {
			r.remove(id)
		}
	}
}

func (r *registry[V]) ownedBy(owner string) int {
	n := 0
	for _, e := range r.items {
		if e.owner == owner {
			n++
		}
	}
	return n
}

func (r *registry[V]) oldestOf(owner string) string {
	for _, id := range r.order {
		if r.items[id].owner == owner {
			return id
		}
	}
	return ""
}

func (r *registry[V]) get(id string) (V, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.items[id]
	return e.value, ok
}

// take removes and returns the entry: the single-use read.
func (r *registry[V]) take(id string) (V, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.items[id]
	r.remove(id)
	return e.value, ok
}

func (r *registry[V]) drop(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remove(id)
}

func (r *registry[V]) remove(id string) {
	if _, ok := r.items[id]; !ok {
		return
	}
	delete(r.items, id)
	if i := slices.Index(r.order, id); i >= 0 {
		r.order = slices.Delete(r.order, i, i+1)
	}
}

type clientKey struct{}

// WithClient tags ctx with the address of the requester, so a login started
// under it counts against that address's share of the registry.
func WithClient(ctx context.Context, client string) context.Context {
	return context.WithValue(ctx, clientKey{}, client)
}

func clientOf(ctx context.Context) string {
	client, _ := ctx.Value(clientKey{}).(string)
	return client
}

// ReplayStore remembers ID-token jti values so a token is accepted once
// (oidc_replay). Implementations drop entries past their expiry.
type ReplayStore interface {
	// Remember records (issuer, jti) until expiresAt and reports whether the
	// pair was new.
	Remember(ctx context.Context, issuer, jti string, expiresAt time.Time) (fresh bool, err error)
}

type replayKey struct{ issuer, jti string }

// memoryReplay is the ReplayStore used when the caller supplies none.
type memoryReplay struct {
	clock domain.Clock
	mu    sync.Mutex
	seen  map[replayKey]time.Time
}

func newMemoryReplay(clock domain.Clock) *memoryReplay {
	return &memoryReplay{clock: clock, seen: make(map[replayKey]time.Time)}
}

func (m *memoryReplay) Remember(_ context.Context, issuer, jti string, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	for k, exp := range m.seen {
		if !exp.After(now) {
			delete(m.seen, k)
		}
	}
	key := replayKey{issuer, jti}
	if _, dup := m.seen[key]; dup {
		return false, nil
	}
	m.seen[key] = expiresAt
	return true, nil
}
