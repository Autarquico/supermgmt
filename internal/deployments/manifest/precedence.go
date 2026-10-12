package manifest

import (
	"maps"
	"slices"

	"github.com/autarquico/supermgmt/internal/health"
)

// Effective applies spec §19 precedence: the control plane always wins and the
// manifest can only tighten. m may be nil (no manifest in the commit).
//
//   - rollback: a stateful target is always manual; a manifest "manual"
//     downgrades automatic; a manifest "automatic" never upgrades manual.
//   - health: the control-plane check is used when defined; otherwise the
//     manifest hint becomes a node-scope check with origin manifest.
//   - stateful, backup and bind addresses are control-plane only.
func Effective(cp DeploymentPolicy, m *Manifest) (EffectivePolicy, error) {
	if !validRollbackMode(cp.Rollback) {
		return EffectivePolicy{}, invalid("deployment policy: rollback must be automatic or manual")
	}
	return EffectivePolicy{
		Rollback:             effectiveRollback(cp, m),
		Stateful:             cp.Stateful,
		PreDeployBackup:      copyBackup(cp.PreDeployBackup),
		AllowedBindAddresses: slices.Clone(cp.AllowedBindAddresses),
		Health:               effectiveHealth(cp.Health, m),
	}, nil
}

func effectiveRollback(cp DeploymentPolicy, m *Manifest) string {
	if cp.Stateful || cp.Rollback == rollbackManual {
		return rollbackManual
	}
	if m != nil && m.Spec.Rollback != nil && m.Spec.Rollback.Mode == rollbackManual {
		return rollbackManual
	}
	return cp.Rollback
}

func effectiveHealth(cp *health.Check, m *Manifest) *health.Check {
	if cp != nil {
		c := *cp
		c.Origin = health.OriginControlPlane
		return &c
	}
	if m == nil || m.Spec.Health == nil {
		return nil
	}
	h := m.Spec.Health
	return &health.Check{
		Origin:   health.OriginManifest,
		Type:     h.Type,
		Scope:    health.ScopeNode,
		Port:     h.Port,
		Path:     h.Path,
		Timeout:  h.Timeout,
		Interval: h.Interval,
		Attempts: h.Attempts,
	}
}

func copyBackup(b *Backup) *Backup {
	if b == nil {
		return nil
	}
	c := *b
	c.Args = maps.Clone(b.Args)
	return &c
}
