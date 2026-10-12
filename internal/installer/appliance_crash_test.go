//go:build crashpoints

package installer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Run with: go test -tags crashpoints ./internal/installer/...

type crasher struct {
	at     int // 1-based; 0 only records
	prefix string
	seen   []string
	n      int
}

func (c *crasher) hit(point string) error {
	if !strings.HasPrefix(point, c.prefix) {
		return nil
	}
	c.n++
	c.seen = append(c.seen, point)
	if c.at != 0 && c.n == c.at {
		return errCrashed
	}
	return nil
}

func (w *aw) crashRun(at int, prefix string) (*crasher, error) {
	c := &crasher{at: at, prefix: prefix}
	h := fastHooks()
	h.crash = c.hit
	return c, New(w.deps(false)).provision(context.Background(), w.opts(), h)
}

func TestProxmoxLXC_CrashAtEveryJournalBoundary(t *testing.T) {
	probe := newAW(t)
	counter, err := probe.crashRun(0, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"journal:created", "S7:intent", "S7:applied", "S7:recorded", "S12d:intent", "S12d:applied", "S12e:applied", "S12f:pushed", "S12h:removed", "S13:imported", "S15b:enabled", "S16:record", "S16:committed", "S16:cleaned"} {
		found := false
		for _, p := range counter.seen {
			found = found || p == want
		}
		if !found {
			t.Errorf("crash point %q is never reached", want)
		}
	}
	installed, rolledBack := 0, 0
	for k := 1; k <= counter.n; k++ {
		w := newAW(t)
		c, err := w.crashRun(k, "")
		if !errors.Is(err, errCrashed) {
			t.Fatalf("crash %d: err = %v", k, err)
		}
		label := "crash at " + c.seen[k-1]
		if len(w.hostPaths(appliancesDir+"/")) > 0 {
			installed++
			if err := w.recoverStale(); err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			assertInstalledAfterCommit(t, w, label)
			continue
		}
		rolledBack++
		if err := w.recoverStale(); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		assertClean(t, w, label, nil)
		if got := w.hostPaths("/var/tmp/supermgmt-installer-"); len(got) > 0 {
			t.Errorf("%s: journal debris: %v", label, got)
		}
	}
	if installed == 0 || rolledBack == 0 {
		t.Errorf("crash points ended installed %d times and rolled back %d times; both must occur", installed, rolledBack)
	}
	t.Logf("%d crash points: %d recovered as installed, %d rolled back", counter.n, installed, rolledBack)
}

// TestProxmoxLXC_CommitBoundaries pins ADR-0026's commit protocol: before the
// record the install is rolled back, from the record on it is never undone.
func TestProxmoxLXC_CommitBoundaries(t *testing.T) {
	cases := map[string]bool{"S15b:enabled": false, "S16:record": true, "S16:committed": true, "S16:cleaned": true}
	for point, survives := range cases {
		t.Run(point, func(t *testing.T) {
			probe := newAW(t)
			counter, _ := probe.crashRun(0, "")
			at := 0
			for i, p := range counter.seen {
				if p == point {
					at = i + 1
				}
			}
			w := newAW(t)
			if _, err := w.crashRun(at, ""); !errors.Is(err, errCrashed) {
				t.Fatalf("err = %v", err)
			}
			if err := w.recoverStale(); err != nil {
				t.Fatal(err)
			}
			if got := len(w.guests) == 1; got != survives {
				t.Errorf("container survives = %t, want %t", got, survives)
			}
			if got := len(w.hostPaths(appliancesDir+"/")) == 1; got != survives {
				t.Errorf("record present = %t, want %t", got, survives)
			}
			if len(w.hostPaths("/var/tmp/supermgmt-installer-")) != 0 {
				t.Error("journal left after recovery")
			}
		})
	}
}

func TestProxmoxLXC_CrashDuringRollbackIsRecoverable(t *testing.T) {
	probe := newAW(t)
	probe.mustInstall(t)
	importOp := probe.opIndex("ct.exec /usr/local/bin/sm secrets import") + 1
	for k := 1; ; k++ {
		w := newAW(t)
		w.failAt = importOp
		c, err := w.crashRun(k, "rollback:")
		if !errors.Is(err, errCrashed) {
			if k == 1 {
				t.Fatal("rollback has no crash points")
			}
			return // past the last point
		}
		label := "crash at " + c.seen[k-1]
		if err := w.recoverStale(); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		assertClean(t, w, label, nil)
		if got := w.hostPaths("/var/tmp/supermgmt-installer-"); len(got) > 0 {
			t.Errorf("%s: journal debris: %v", label, got)
		}
	}
}
