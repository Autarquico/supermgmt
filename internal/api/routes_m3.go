package api

import (
	"context"
	"net/http"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
)

// refreshRate bounds on-demand discovery per caller and provider: a refresh
// reads the whole cluster, and concurrent ones share one run anyway (ADR-0024).
var refreshRate = bucketRate{perMinute: 6, burst: 3}

// ---- proxmox (ADR-0024) -------------------------------------------------------

func (rs *routeSet) proxmox() {
	s := rs.s
	// Not keyed: a refresh changes nothing a repeat would not change again.
	rs.add(route{
		method: http.MethodPost, pattern: wire.PathProviderRefresh, action: "provider.read",
		do: s.requireProxmox(reading(s, s.refreshProvider)),
	})
}

func (s *Server) refreshProvider(ctx context.Context, by app.Caller, in input) (wire.Provider, error) {
	id, err := in.id("id")
	if err != nil {
		return wire.Provider{}, err
	}
	if ok, after := s.refreshLimit.allow(by.ID.String() + "/" + id.String()); !ok {
		return wire.Provider{}, &rateLimited{after: after}
	}
	return s.svc.Proxmox.Refresh(ctx, by, id)
}

func (s *Server) requireProxmox(next endpoint) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		if s.svc.Proxmox == nil {
			return unavailable("Proxmox discovery")
		}
		return next(w, r)
	}
}
