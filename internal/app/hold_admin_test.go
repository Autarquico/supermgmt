package app

import (
	"context"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestTheAdminRecoveryOperationsAndCredentialRoutesPassTheHoldStampedWithTheirAction(t *testing.T) {
	f := newFixture(t)
	hold := f.newHold()
	f.setHold(true)
	ctx := context.Background()
	admin := Caller{Source: adminSocketSource}

	for _, action := range []string{ActionAdminGrant, ActionAdminBootstrapCode, ActionRestoreComplete} {
		if err := hold.Guard(ctx, action, admin); err != nil {
			t.Errorf("%s was refused during hold: %v", action, err)
		}
	}
	for _, action := range []string{actionExemptAuth, actionExemptSelf} {
		if err := hold.Guard(ctx, action, f.caller(f.alice)); err != nil {
			t.Errorf("%s was refused during hold: %v", action, err)
		}
	}
	wantError(t, hold.Guard(ctx, "admin.doctor.write", admin), smerr.CodeConflict, smerr.ReasonRestoreHold)
}
