package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// EvidenceRouter implements jobs.EvidenceSource for the dispatched intents of
// service actions (ADR-0015, spec §20.4). It first reads the node-side marker:
// a marker that is absent proves the command never began; otherwise the
// runtime adapter judges the resulting state. Anything it cannot establish is
// an error, which the reconciler reads as "no evidence yet".
type EvidenceRouter struct {
	core
	conn     Connector
	adapters Adapters
	proxmox  *ProxmoxEvidence
}

var _ jobs.EvidenceSource = (*EvidenceRouter)(nil)

// EvidenceOption adds an evidence source to the router.
type EvidenceOption func(*EvidenceRouter)

// WithProxmoxEvidence routes the intents of Proxmox operations to p.
func WithProxmoxEvidence(p *ProxmoxEvidence) EvidenceOption {
	return func(r *EvidenceRouter) { r.proxmox = p }
}

// NewEvidenceRouter validates cfg. A nil adapters means DefaultAdapters.
func NewEvidenceRouter(cfg Config, conn Connector, adapters Adapters, opts ...EvidenceOption) (*EvidenceRouter, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if adapters == nil {
		adapters = DefaultAdapters()
	}
	r := &EvidenceRouter{core: c, conn: conn, adapters: adapters}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Collect gathers evidence for one dispatched intent.
func (r *EvidenceRouter) Collect(ctx context.Context, intent jobs.Intent) (jobs.Evidence, error) {
	if strings.HasPrefix(intent.Operation, proxmox.OperationPrefix) {
		if r.proxmox == nil {
			return jobs.Evidence{}, fmt.Errorf("no Proxmox evidence source for intent %s (%s)", intent.ID, intent.Operation)
		}
		return r.proxmox.Collect(ctx, intent)
	}
	if intent.TargetType != string(domain.ResourceService) || intent.DispatchedAt == nil {
		return jobs.Evidence{}, fmt.Errorf("no evidence source for intent %s (%s on %s)", intent.ID, intent.Operation, intent.TargetType)
	}
	verb, err := domain.ParseServiceVerb(strings.TrimPrefix(intent.Operation, "service."))
	if err != nil {
		return jobs.Evidence{}, err
	}
	q := r.cfg.DB.Reader()
	svc, err := database.GetService(ctx, q, domain.ID(intent.TargetID))
	if err != nil {
		return jobs.Evidence{}, err
	}
	node, err := database.GetNode(ctx, q, svc.NodeID)
	if err != nil {
		return jobs.Evidence{}, err
	}
	setup, err := loadSetup(ctx, q, node.ID)
	if err != nil {
		return jobs.Evidence{}, err
	}
	adapter, err := r.adapters.For(domain.ServiceKind(svc.Kind))
	if err != nil {
		return jobs.Evidence{}, err
	}
	ex, err := r.conn.Automated(node, setup)
	if err != nil {
		return jobs.Evidence{}, err
	}
	state, err := markerState(ctx, ex, intent.Marker)
	if err != nil {
		return jobs.Evidence{}, err
	}
	switch state.Kind {
	case templates.MarkerAbsent:
		return markerAbsent(intent), nil
	case templates.MarkerStarted, templates.MarkerDone:
		ev, err := adapter.Observe(ctx, ex, serviceRef(svc), verb, intent.Marker, intent.PreState, *intent.DispatchedAt)
		if err != nil {
			return jobs.Evidence{}, err
		}
		return withFingerprint(ev, intent)
	case templates.MarkerUnavailable:
	}
	return jobs.Evidence{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "the node's markers directory cannot be read")
}

func markerState(ctx context.Context, ex transport.Executor, marker string) (templates.MarkerState, error) {
	c, err := templates.Render("marker.state", map[string]string{"marker": marker})
	if err != nil {
		return templates.MarkerState{}, err
	}
	res, err := ex.Run(ctx, c)
	if err != nil {
		return templates.MarkerState{}, err
	}
	if res.ExitStatus != 0 {
		return templates.MarkerState{}, fmt.Errorf("marker.state exited with status %d", res.ExitStatus)
	}
	return templates.ParseMarkerState(res.Stdout)
}

// markerAbsent is the proof that a dispatched command never began: the
// reconciler only asks once the intent is quiescent, i.e. past its deadline
// plus the grace period, so a late start is no longer possible.
func markerAbsent(intent jobs.Intent) jobs.Evidence {
	return jobs.Evidence{
		Done: true, ExitStatus: 0, Proof: jobs.ProofMarkerAbsent, Classification: jobs.ClassNotStarted,
		Fingerprint: json.RawMessage(`{"marker":"absent"}`), Pre: intent.PreState,
	}
}

// withFingerprint insists on a fingerprint: evidence without one would pair
// with any other empty sample in jobs.confirm.
func withFingerprint(ev jobs.Evidence, intent jobs.Intent) (jobs.Evidence, error) {
	if len(ev.Fingerprint) == 0 {
		return jobs.Evidence{}, fmt.Errorf("adapter returned evidence without a fingerprint for %s", intent.Operation)
	}
	if len(ev.Pre) == 0 {
		ev.Pre = intent.PreState
	}
	return ev, nil
}
