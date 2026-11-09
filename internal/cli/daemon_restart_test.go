package cli

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStopLocalDaemonReportsNoneWhenTheDatabaseIsFree(t *testing.T) {
	stopped, err := stopLocalDaemon(filepath.Join(t.TempDir(), "sm.db"), time.Second)
	if err != nil || stopped {
		t.Errorf("stopped=%t err=%v", stopped, err)
	}
}
