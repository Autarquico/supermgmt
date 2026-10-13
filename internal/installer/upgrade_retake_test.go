package installer

import (
	"errors"
	"testing"
)

func TestUpgrade_ForgedSupersededArchiveIsNeverRemoved(t *testing.T) {
	backups := applianceLayout().BackupsDir
	const name = "supermgmt-x-20260101T000000Z.tar.zst"
	cases := map[string]struct {
		path  string
		setup func(*uhost, string)
	}{
		"outside the backup directory": {"/etc/" + name, func(h *uhost, p string) { h.put(p, "precious") }},
		"a directory":                  {backups + "/" + name, func(h *uhost, p string) { h.dirs[p] = true; h.put(p+"/inside", "precious") }},
		"a symlink": {backups + "/" + name, func(h *uhost, p string) {
			h.put(p, "precious")
			h.linkedFiles = map[string]bool{p: true}
		}},
		"not named like an archive": {backups + "/notes.txt", func(h *uhost, p string) { h.put(p, "precious") }},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			h := newUHost(t)
			h.seedUpgrade(t, upgradeState{Phase: upBackedUp, Archive: c.path}, binV2)
			h.put(applianceLayout().Binary+".new", binV2)
			c.setup(h, c.path)
			if err := h.upgrade(defaultHooks()); err != nil {
				t.Fatalf("upgrade: %v\n%s", err, h.out.String())
			}
			if !h.Exists(c.path) {
				t.Errorf("%s was removed", c.path)
			}
		})
	}
}

func TestUpgrade_ServiceThatCannotHoldFailsTheUpgrade(t *testing.T) {
	h := newUHost(t)
	h.holdErr = errors.New("no hold")
	if err := h.upgrade(defaultHooks()); err == nil {
		t.Fatal("upgrade succeeded without the hold")
	}
	if h.index("disable ") >= 0 || h.index("stop ") >= 0 || h.live() != binV1 {
		t.Errorf("the upgrade went on without the hold: %v", h.events)
	}
}
