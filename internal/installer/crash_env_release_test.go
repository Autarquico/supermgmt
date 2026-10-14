//go:build !crashpoints

package installer

import (
	"context"
	"testing"
)

func TestCrashEnv_ReleaseBuildIgnoresTheVariable(t *testing.T) {
	for _, point := range []string{"U:staged", "U:swap:before", "U:done:recorded"} {
		t.Run(point, func(t *testing.T) {
			h := newUHost(t)
			d := h.deps()
			d.Host.Env = map[string]string{"SUPERMGMT_CRASH_AT": point}
			if err := New(d).upgrade(context.Background(), h.upgradeOpts(), defaultHooks()); err != nil {
				t.Fatalf("upgrade: %v", err)
			}
			if st, ok := h.state(); !ok || st.Phase != upDone {
				t.Errorf("state = %+v", st)
			}
		})
	}
}
