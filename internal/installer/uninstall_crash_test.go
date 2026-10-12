//go:build crashpoints

package installer

import (
	"errors"
	"slices"
	"testing"
)

func crashHooks(prefix string, at int) (*crasher, provisionHooks) {
	c := &crasher{at: at, prefix: prefix}
	hooks := defaultHooks()
	hooks.crash = c.hit
	return c, hooks
}

func TestUninstall_CrashAtEveryBoundaryConverges(t *testing.T) {
	for _, purge := range []bool{false, true} {
		o := Options{Mode: ModeUninstall, Yes: true, PurgeData: purge}
		probe := newUHost(t)
		counter, hooks := crashHooks("UN:", 0)
		if err := probe.uninstall(o, hooks); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"UN:stopped", "UN:disabled", "UN:unit-removed", "UN:binary-removed"} {
			if !slices.Contains(counter.seen, want) {
				t.Errorf("crash point %q is never reached", want)
			}
		}
		if purge && !slices.Contains(counter.seen, "UN:purged") {
			t.Error("purge has no crash point")
		}
		for k, point := range counter.seen {
			h := newUHost(t)
			keep := h.seedUserData()
			_, hooks := crashHooks("UN:", k+1)
			if err := h.uninstall(o, hooks); !errors.Is(err, errCrashed) {
				t.Fatalf("purge=%t crash at %s: err = %v", purge, point, err)
			}
			if err := h.uninstall(o, defaultHooks()); err != nil && ExitCode(err) != ExitPrerequisite {
				t.Fatalf("purge=%t rerun after %s: %v", purge, point, err)
			}
			l := applianceLayout()
			for _, p := range []string{l.Binary, l.Binary + ".prev", l.UnitPath} {
				if h.Exists(p) {
					t.Errorf("purge=%t after %s: %s survived the rerun", purge, point, p)
				}
			}
			for _, p := range keep {
				if h.Exists(p) == purge {
					t.Errorf("purge=%t after %s: %s exists = %t", purge, point, p, h.Exists(p))
				}
			}
		}
	}
}

func TestUninstallAppliance_CrashAtEveryBoundaryConverges(t *testing.T) {
	for _, purge := range []bool{false, true} {
		o := Options{Mode: ModeUninstall, Yes: true, PurgeData: purge, VMID: 900}
		setup := func(t *testing.T) *pveWrap {
			p := newPVEWrap(t)
			p.installAppliance(t, 900)
			p.installAppliance(t, 901)
			return p
		}
		probe := setup(t)
		counter, hooks := crashHooks("UN:", 0)
		if err := probe.run(o, hooks, false); err != nil {
			t.Fatal(err)
		}
		if len(counter.seen) == 0 {
			t.Fatal("no crash points")
		}
		for k, point := range counter.seen {
			p := setup(t)
			first, second := p.record(t, 900), p.record(t, 901)
			othersBefore, _ := p.identitiesOf(t, 901)
			_, hooks := crashHooks("UN:", k+1)
			if err := p.run(o, hooks, false); !errors.Is(err, errCrashed) {
				t.Fatalf("purge=%t crash at %s: err = %v", purge, point, err)
			}
			// After the last point the purge is complete and its record gone: the rerun says so.
			finished := purge && point == "UN:record-removed"
			if err := p.run(o, fastHooks(), false); (err != nil) != finished || (finished && ExitCode(err) != ExitInvalid) {
				t.Fatalf("purge=%t rerun after %s: %v\n%s", purge, point, err, p.out.String())
			}
			if purge {
				assertPurged(t, p, first)
			} else if present, absent := p.identitiesOf(t, 900); len(absent) != 0 || p.guests[900].status != "stopped" {
				t.Errorf("after %s: default uninstall lost %v (present %v)", point, absent, present)
			}
			if present, absent := p.identitiesOf(t, 901); !slices.Equal(present, othersBefore) || len(absent) != 0 {
				t.Errorf("purge=%t after %s: the other appliance changed: %v / %v", purge, point, present, absent)
			}
			if p.record(t, 901).InstallID != second.InstallID {
				t.Errorf("after %s: the other appliance's record changed", point)
			}
		}
	}
}
