//go:build !crashpoints

package backup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/autarquico/supermgmt/internal/backup"
)

// A build without the crashpoints tag is what ships: its crash hooks must
// compile to nothing, whatever a caller injects (ADR-0020).
func TestReleaseBuildHasNoCrashPoints(t *testing.T) {
	if backup.CrashpointsCompiled {
		t.Fatal("crash points are compiled into a build without the crashpoints tag")
	}
	_, tg := newWorld(t)
	hits := 0
	crash := func(string) error { hits++; return errors.New("injected") }

	if err := backup.RestoreWith(context.Background(), tg.options(), backup.TestEnv{Crash: crash}); err != nil {
		t.Fatalf("an injected crash changed a release build's behavior: %v", err)
	}
	if hits != 0 {
		t.Errorf("crash hook was called %d times in a release build", hits)
	}
}
