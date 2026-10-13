package app

import (
	"errors"
	"time"

	"github.com/autarquico/supermgmt/internal/providers/proxmox"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
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

	// Proxmox enables the proxmox.vm.power job; without it the type has no
	// handler. ProxmoxHTTPTimeout must equal the proxmox.WithHTTPTimeout the
	// sync's clients use (zero means 30s, the client default): the correlation
	// window of an uncertain dispatch depends on it.
	Proxmox            *ProxmoxSync
	ProxmoxHTTPTimeout time.Duration

	// Apps lets the control_plane.apply job apply approved app, app target and
	// GitHub provider writes; without it those jobs fail loudly.
	Apps *Apps

	// Deploy enables deployment.create and deployment.rollback; without it the
	// types have no handler.
	Deploy *DeployOptions
}

// Handlers are the executors of the job types M1 adds.
type Handlers struct {
	probe  probeHandler
	setup  setupHandler
	action actionHandler
	apply  applyHandler
	power  *proxmoxPowerHandler // nil unless Proxmox is configured
	deploy *deployHandler       // nil unless deployments are configured
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
	h := &Handlers{
		probe:  probeHandler{prober: o.Prober, store: o.Store},
		setup:  setupHandler{core: c, store: o.Store, conn: o.Connector, identity: o.Identity, prober: o.Prober},
		action: actionHandler{core: c, store: o.Store, conn: o.Connector, adapters: o.Adapters, settle: o.Settle.withDefaults()},
		apply:  applyHandler{inv: o.Inventory, apps: o.Apps},
	}
	if o.Proxmox != nil {
		h.power = &proxmoxPowerHandler{
			core: c, store: o.Store, sync: o.Proxmox, settle: o.Settle.withDefaults(),
			httpTimeout: orDefaultDuration(o.ProxmoxHTTPTimeout, proxmox.DefaultTimeout),
		}
	}
	if o.Deploy != nil {
		if h.deploy, err = newDeployHandler(c, o.Store, o.Connector, *o.Deploy); err != nil {
			return nil, err
		}
	}
	return h, nil
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
	if h.power != nil {
		table[policy.ActionProxmoxVMPower] = h.power
	}
	if h.deploy != nil {
		table[deploymentCreateAction] = h.deploy
		table[deploymentRollbackAction] = h.deploy
	}
	return table
}
