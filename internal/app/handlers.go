package app

import (
	"errors"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// HandlersOptions are the collaborators of the job handlers.
type HandlersOptions struct {
	Store     *jobs.Store
	Connector Connector
	Adapters  Adapters // default DefaultAdapters
	Inventory *Inventory
	Prober    *Prober
	Identity  SSHIdentity
	Settle    Settle
}

// Handlers are the executors of the job types M1 adds.
type Handlers struct {
	probe  probeHandler
	setup  setupHandler
	action actionHandler
	apply  applyHandler
}

// NewHandlers validates the options.
func NewHandlers(cfg Config, o HandlersOptions) (*Handlers, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	switch {
	case o.Store == nil:
		return nil, errors.New("app: job store is required")
	case o.Inventory == nil:
		return nil, errors.New("app: inventory is required")
	case o.Prober == nil:
		return nil, errors.New("app: prober is required")
	case o.Identity == nil:
		return nil, errors.New("app: ssh identity source is required")
	}
	if o.Adapters == nil {
		o.Adapters = DefaultAdapters()
	}
	return &Handlers{
		probe:  probeHandler{prober: o.Prober, store: o.Store},
		setup:  setupHandler{core: c, store: o.Store, conn: o.Connector, identity: o.Identity, prober: o.Prober},
		action: actionHandler{core: c, store: o.Store, conn: o.Connector, adapters: o.Adapters, settle: o.Settle.withDefaults()},
		apply:  applyHandler{inv: o.Inventory},
	}, nil
}

// Map is the handler table for jobs.EngineConfig.Handlers, keyed by job type.
func (h *Handlers) Map() map[string]jobs.Handler {
	table := map[string]jobs.Handler{
		"node.probe":         h.probe,
		"node.setup":         h.setup,
		JobControlPlaneApply: h.apply,
	}
	for _, verb := range domain.AllServiceVerbs() {
		table[verb.Action()] = h.action
	}
	return table
}
