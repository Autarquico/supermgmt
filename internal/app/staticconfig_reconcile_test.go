package app

import (
	"context"

	"github.com/autarquico/supermgmt/internal/config"
)

// Reconcile is Activate without the configuration snapshot: the tests of the
// reconciliation itself do not care about the snapshot. Production code only
// activates.
func (s *StaticReconciler) Reconcile(ctx context.Context, envs []config.Environment, providers []config.Provider) error {
	return s.reconcile(ctx, envs, providers, nil)
}
