//go:build crashpoints

package installer

import (
	"context"
	"errors"
	"testing"
)

func (h *uhost) crashUpgradeAt(point string, sans ...string) error {
	hooks := defaultHooks()
	hooks.crash = func(p string) error {
		if p == point {
			return errCrashed
		}
		return nil
	}
	o := h.upgradeOpts()
	o.TLSSANs = sans
	return New(h.deps()).upgrade(context.Background(), o, hooks)
}

func TestUpgrade_TLSSANResumesWithoutTheFlagFromBothSidesOfTheReplacement(t *testing.T) {
	cases := []struct {
		point       string
		wantCovered bool // the leaf already holds the names when the crash happens
	}{
		{"U:swapped:recorded", false},
		{"U:tls:resigned", true},
	}
	for _, tc := range cases {
		t.Run(tc.point, func(t *testing.T) {
			h := newUHost(t)
			h.selfSigned(t)
			if err := h.crashUpgradeAt(tc.point, tailscaleIP); !errors.Is(err, errCrashed) {
				t.Fatalf("crash err = %v", err)
			}
			if h.covers(t, tailscaleIP) != tc.wantCovered {
				t.Fatalf("covered = %t at the crash, want %t", !tc.wantCovered, tc.wantCovered)
			}
			crashed := h.content(selfSignedFiles(applianceLayout()).Cert)
			if err := h.upgradeWith(); err != nil {
				t.Fatalf("rerun: %v\n%s", err, h.out.String())
			}
			if !h.covers(t, tailscaleIP) || !h.covers(t, "sm.example.com") {
				t.Error("the leaf must cover the new and the old names after the rerun")
			}
			if tc.wantCovered && h.content(selfSignedFiles(applianceLayout()).Cert) != crashed {
				t.Error("a leaf that already covers the names was signed again")
			}
			if st, ok := h.state(); !ok || st.Phase != upDone || !h.running || h.startedAs != binV2 {
				t.Errorf("state %+v running %t as %q", st, h.running, h.startedAs)
			}
			h.noViolations(t)
		})
	}
}
