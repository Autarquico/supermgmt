package app

import (
	"fmt"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/docker"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
)

// Adapters are the runtime adapters by type.
type Adapters map[domain.RuntimeType]runtimes.Adapter

// DefaultAdapters are the systemd and Docker adapters of M1.
func DefaultAdapters() Adapters {
	return Adapters{domain.RuntimeSystemd: systemd.New(), domain.RuntimeDocker: docker.New()}
}

// For returns the adapter that manages services of kind.
func (a Adapters) For(kind domain.ServiceKind) (runtimes.Adapter, error) {
	adapter, ok := a[kind.Runtime()]
	if !ok {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("no runtime adapter for service kind %q", kind))
	}
	return adapter, nil
}

// Focus remembers which nodes a client currently has open (plan Q6): the
// refresher keeps those fresh at refresh.focused_interval. A lease lasts twice
// that interval and is renewed by every request that asks for focus. It is
// in-memory and unrelated to daemon residency.
type Focus struct {
	clock domain.Clock
	ttl   time.Duration

	mu     sync.Mutex
	leases map[domain.ID]time.Time
}

// NewFocus builds a focus set whose leases last ttl.
func NewFocus(clock domain.Clock, ttl time.Duration) *Focus {
	return &Focus{clock: clock, ttl: ttl, leases: map[domain.ID]time.Time{}}
}

// Touch renews the lease of node. A nil Focus ignores it.
func (f *Focus) Touch(node domain.ID) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leases[node] = f.clock.Now().Add(f.ttl)
}

// Active reports whether node's lease is still valid, dropping expired ones.
func (f *Focus) Active(node domain.ID) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	until, ok := f.leases[node]
	if ok && !f.clock.Now().Before(until) {
		delete(f.leases, node)
		return false
	}
	return ok
}
