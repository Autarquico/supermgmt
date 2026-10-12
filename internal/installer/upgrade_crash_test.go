//go:build crashpoints

package installer

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Run with: go test -tags crashpoints ./internal/installer/...

func (h *uhost) crashUpgrade(at int) (*crasher, error) {
	c := &crasher{at: at, prefix: "U:"}
	hooks := defaultHooks()
	hooks.crash = c.hit
	return c, New(h.deps()).upgrade(context.Background(), h.upgradeOpts(), hooks)
}

// rerun is the operator running `sm install upgrade` again after the crash.
func (h *uhost) rerun() error { return h.upgrade(defaultHooks()) }

// upgradePoints lists the crash points one uninterrupted run passes.
func upgradePoints(t *testing.T, setup func(*uhost)) []string {
	t.Helper()
	h := newUHost(t)
	setup(h)
	c, _ := h.crashUpgrade(0)
	return c.seen
}

func crashAfter(t *testing.T, h *uhost, point string) {
	t.Helper()
	at := slices.Index(upgradePoints(t, func(*uhost) {}), point) + 1
	if at == 0 {
		t.Fatalf("crash point %q does not exist", point)
	}
	if _, err := h.crashUpgrade(at); !errors.Is(err, errCrashed) {
		t.Fatalf("crash err = %v", err)
	}
}

func TestUpgrade_CrashAtEveryBoundaryConverges(t *testing.T) {
	points := upgradePoints(t, func(*uhost) {})
	for _, want := range []string{
		"U:staged", "U:prev-linked", "U:prepared:recorded", "U:stopped:applied", "U:stopped:recorded",
		"U:backed_up:applied", "U:backed_up:recorded", "U:swap:before", "U:swap:renamed", "U:swapped:recorded",
		"U:started:applied", "U:started:recorded", "U:done:recorded",
	} {
		if !slices.Contains(points, want) {
			t.Errorf("crash point %q is never reached", want)
		}
	}
	recorded := slices.Index(points, "U:backed_up:recorded")
	for k, point := range points {
		t.Run(point, func(t *testing.T) {
			h := newUHost(t)
			if _, err := h.crashUpgrade(k + 1); !errors.Is(err, errCrashed) {
				t.Fatalf("crash err = %v", err)
			}
			if err := h.rerun(); err != nil {
				t.Fatalf("rerun: %v\n%s", err, h.out.String())
			}
			l := applianceLayout()
			if h.live() != binV2 || h.content(l.Binary+".prev") != binV1 || !h.running || h.startedAs != binV2 || h.dbSchema != 4 {
				t.Errorf("live %q prev %q running %t as %q schema %d", h.live(), h.content(l.Binary+".prev"), h.running, h.startedAs, h.dbSchema)
			}
			if st, ok := h.state(); !ok || st.Phase != upDone {
				t.Errorf("state = %+v", st)
			}
			if k >= recorded && h.archives != 1 {
				t.Errorf("a second backup was taken after the first was recorded (%d archives)", h.archives)
			}
			h.noViolations(t)
		})
	}
}

func TestUpgrade_CrashDuringFailurePolicyConverges(t *testing.T) {
	scenarios := []struct {
		name  string
		setup func(*uhost)
		check func(*testing.T, *uhost)
	}{
		{
			"backup fails, old service restarted",
			func(h *uhost) { h.backupErr = errors.New("disk full") },
			func(t *testing.T, h *uhost) {
				if h.live() != binV1 || !h.running || h.startedAs != binV1 {
					t.Errorf("live %q running %t as %q", h.live(), h.running, h.startedAs)
				}
				if _, ok := h.state(); ok {
					t.Error("state left behind")
				}
			},
		},
		{
			"health fails, schema unchanged: binary reverted",
			func(h *uhost) { h.put("/usr/local/src/sm-new", binV2+";boot=fail") },
			func(t *testing.T, h *uhost) {
				if h.live() != binV1 || !h.running || h.startedAs != binV1 || h.dbSchema != 3 {
					t.Errorf("live %q running %t as %q schema %d", h.live(), h.running, h.startedAs, h.dbSchema)
				}
				if h.content(applianceLayout().Binary+".prev") != binV1 {
					t.Error("sm.prev lost")
				}
				if _, ok := h.state(); ok {
					t.Error("state left behind")
				}
			},
		},
		{
			"health fails, schema advanced: stays stopped",
			func(h *uhost) { h.put("/usr/local/src/sm-new", binV2+";boot=fail-migrated") },
			func(t *testing.T, h *uhost) {
				if h.running || h.dbSchema != 4 {
					t.Errorf("running %t schema %d", h.running, h.dbSchema)
				}
				if st, ok := h.state(); !ok || st.Phase != upFailed {
					t.Errorf("state = %+v", st)
				}
				if !strings.Contains(h.out.String(), "backup restore --offline") {
					t.Error("restore commands not printed")
				}
			},
		},
	}
	for _, sc := range scenarios {
		points := upgradePoints(t, sc.setup)
		for k, point := range points {
			t.Run(sc.name+"/"+point, func(t *testing.T) {
				h := newUHost(t)
				sc.setup(h)
				if _, err := h.crashUpgrade(k + 1); !errors.Is(err, errCrashed) {
					t.Fatalf("crash err = %v", err)
				}
				h.out.Reset()
				if err := h.rerun(); ExitCode(err) != ExitRestore {
					t.Fatalf("rerun err = %v\n%s", err, h.out.String())
				}
				sc.check(t, h)
				h.noViolations(t)
			})
		}
	}
}

func TestUpgrade_ResumeWithAnotherBinaryBeforeTheSwapAbandonsTheOldUpgrade(t *testing.T) {
	h := newUHost(t)
	crashAfter(t, h, "U:stopped:recorded")
	if h.running {
		t.Fatal("the crash was meant to leave the service stopped")
	}
	binV3 := "sm;version=1.2.0;schema=5"
	h.put("/usr/local/src/sm-new", binV3)
	if err := h.rerun(); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.live() != binV3 || h.content(applianceLayout().Binary+".prev") != binV1 || h.dbSchema != 5 || !h.running {
		t.Errorf("live %q prev %q schema %d running %t", h.live(), h.content(applianceLayout().Binary+".prev"), h.dbSchema, h.running)
	}
	h.noViolations(t)
}

func TestUpgrade_ResumeAfterTheSwapFinishesTheSameUpgrade(t *testing.T) {
	h := newUHost(t)
	crashAfter(t, h, "U:swapped:recorded")
	h.put("/usr/local/src/sm-new", "sm;version=9.9.9;schema=9") // whatever the operator points at now
	if err := h.rerun(); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.live() != binV2 || h.startedAs != binV2 || h.dbSchema != 4 {
		t.Errorf("live %q as %q schema %d", h.live(), h.startedAs, h.dbSchema)
	}
	h.noViolations(t)
}

func TestUpgrade_ResumeRepairsDamageFromTheCrash(t *testing.T) {
	l := applianceLayout()
	cases := map[string]func(*uhost){
		"sm.new torn":     func(h *uhost) { h.put(l.Binary+".new", "torn") },
		"sm.new missing":  func(h *uhost) { _ = h.RemoveAll(l.Binary + ".new") },
		"sm.prev missing": func(h *uhost) { _ = h.RemoveAll(l.Binary + ".prev") },
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			h := newUHost(t)
			crashAfter(t, h, "U:stopped:recorded")
			h.prevOld = false
			damage(h)
			if err := h.rerun(); err != nil {
				t.Fatalf("%v\n%s", err, h.out.String())
			}
			if h.live() != binV2 || h.content(l.Binary+".prev") != binV1 {
				t.Errorf("live %q prev %q", h.live(), h.content(l.Binary+".prev"))
			}
			h.noViolations(t)
		})
	}
}
