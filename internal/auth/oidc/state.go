package oidc

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// registry is a bounded in-memory map: past its limit the oldest entry is
// evicted (ADR-0018 "State and restarts").
type registry[V any] struct {
	mu    sync.Mutex
	limit int
	items map[string]V
	order []string
}

func newRegistry[V any](limit int) *registry[V] {
	return &registry[V]{limit: limit, items: make(map[string]V)}
}

func (r *registry[V]) put(id string, v V) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.order) >= r.limit {
		delete(r.items, r.order[0])
		r.order = r.order[1:]
	}
	r.items[id] = v
	r.order = append(r.order, id)
}

func (r *registry[V]) get(id string) (V, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.items[id]
	return v, ok
}

// take removes and returns the entry: the single-use read.
func (r *registry[V]) take(id string) (V, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.items[id]
	r.remove(id)
	return v, ok
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
