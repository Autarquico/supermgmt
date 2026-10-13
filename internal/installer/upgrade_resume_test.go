package installer

import (
	"errors"
	"strings"
	"testing"
)

const staleArchive = "/var/lib/supermgmt/backups/pre-0.tar.zst"

func TestUpgrade_ResumeRetakesArchive(t *testing.T) {
	tests := []struct {
		name    string
		running bool
	}{
		{"service stopped since the backup", false},
		{"service running again", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newUHost(t)
			h.seedUpgrade(t, upgradeState{Phase: upBackedUp, Archive: staleArchive}, binV2)
			h.put(staleArchive, "stale")
			h.put(applianceLayout().Binary+".new", binV2)
			h.running = tc.running
			if err := h.upgrade(defaultHooks()); err != nil {
				t.Fatalf("%v\n%s", err, h.out.String())
			}
			st, _ := h.state()
			if st.Phase != upDone || !strings.Contains(st.Archive, "pre-1") {
				t.Errorf("state = %+v, want the retaken archive", st)
			}
			if h.Exists(staleArchive) || h.liveArchives() != 1 {
				t.Errorf("%d live archives, stale one present: %t", h.liveArchives(), h.Exists(staleArchive))
			}
			h.noViolations(t)
		})
	}
}

func TestUpgrade_FailedRetakeAbortsAndRestartsTheOldVersion(t *testing.T) {
	h := newUHost(t)
	h.seedUpgrade(t, upgradeState{Phase: upBackedUp, Archive: staleArchive}, binV2)
	h.put(applianceLayout().Binary+".new", binV2)
	h.backupErr = errors.New("disk full")
	err := h.upgrade(defaultHooks())
	if err == nil || h.live() != binV1 || !h.running || h.startedAs != binV1 {
		t.Fatalf("err %v live %q running %t as %q", err, h.live(), h.running, h.startedAs)
	}
	if _, ok := h.state(); ok {
		t.Error("state left behind")
	}
}
