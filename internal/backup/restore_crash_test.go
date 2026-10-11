//go:build crashpoints

package backup_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/backup"
)

// Run with: go test -tags crashpoints ./internal/backup/...

var errCrash = errors.New("simulated crash")

// crasher ends the run at its at-th crash point (1-based); at == 0 only counts.
type crasher struct {
	at     int
	points []string
}

func (c *crasher) hit(point string) error {
	c.points = append(c.points, point)
	if c.at > 0 && len(c.points) == c.at {
		return errCrash
	}
	return nil
}

func (c *crasher) env() backup.TestEnv { return backup.TestEnv{Crash: c.hit} }

// pristine remembers the target machine before any restore and puts it back.
type pristine struct {
	t    *testing.T
	tg   *target
	copy string
	tree map[string]string
}

func savePristine(t *testing.T, tg *target) *pristine {
	t.Helper()
	p := &pristine{t: t, tg: tg, copy: filepath.Join(t.TempDir(), "pristine")}
	copyTree(t, tg.root, p.copy)
	p.tree = relTree(t, tg.root)
	return p
}

// reset returns the target to the saved machine state.
func (p *pristine) reset() { replaceTree(p.t, p.copy, p.tg.root) }

func replaceTree(t *testing.T, from, to string) {
	t.Helper()
	if err := os.RemoveAll(to); err != nil {
		t.Fatal(err)
	}
	copyTree(t, from, to)
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		dst := filepath.Join(to, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(dst, info.Mode().Perm())
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		return errors.Join(err, out.Close())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func relTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for path, v := range treeOf(t, root) {
		rel, _ := filepath.Rel(root, path)
		out[rel] = v
	}
	return out
}

// assertOldOrNew checks the invariant of ADR-0020 after recovery: either the
// machine is exactly as it was, or the restore completed in full.
func assertOldOrNew(t *testing.T, p *pristine, context string) (restored bool) {
	t.Helper()
	tg := p.tg
	assertNoRestoreLeftovers(t, tg.dataDir)
	if now := relTree(t, tg.root); sameTree(now, p.tree) {
		return false
	}
	if got := marker(t, tg.dbPath); got != "from-archive" {
		t.Fatalf("%s: live database marker = %q: neither the old nor the new state", context, got)
	}
	pre := glob(t, filepath.Join(tg.dataDir, "pre-restore-*"))
	if len(pre) != 1 {
		t.Fatalf("%s: pre-restore directories = %v", context, pre)
	}
	if got := marker(t, filepath.Join(pre[0], "supermgmt.db")); got != liveMarker {
		t.Errorf("%s: the old database was lost (marker %q)", context, got)
	}
	for file, want := range map[string]string{
		filepath.Join(tg.dataDir, "known_hosts"):                             "node ssh-ed25519 AAAA\n",
		filepath.Join(tg.dataDir, backup.RestoredConfigDir, "config.yaml"):   "listen: local\n",
		filepath.Join(tg.dataDir, backup.RestoredConfigDir, "policies.yaml"): "policy: v1\n",
		filepath.Join(pre[0], "known_hosts"):                                 "old host\n",
		tg.dbPath + ".lock":                                                  "4242\n",
	} {
		if got := readFile(t, file); got != want {
			t.Errorf("%s: %s = %q, want %q", context, file, got, want)
		}
	}
	if left := glob(t, tg.dbPath+"-wal"); len(left) != 0 {
		t.Errorf("%s: a stale -wal sits next to the restored database", context)
	}
	return true
}

func crashWorld(t *testing.T) (*pristine, int) {
	t.Helper()
	_, tg := newWorld(t)
	p := savePristine(t, tg)
	counter := &crasher{}
	if err := backup.RestoreWith(context.Background(), tg.options(), counter.env()); err != nil {
		t.Fatalf("uninterrupted Restore: %v", err)
	}
	if !assertOldOrNew(t, p, "uninterrupted") {
		t.Fatal("an uninterrupted restore changed nothing")
	}
	for _, want := range []string{"before-rename", "renamed", "intent-written", "directories-synced", "journal-temp-synced", "journal-renamed", "journal-dir-synced", "journal-removed", "journal-removal-synced"} {
		if !slices.Contains(counter.points, want) {
			t.Errorf("crash point %q is never reached", want)
		}
	}
	p.reset()
	return p, len(counter.points)
}

func TestCrashBeforeAndAfterEveryRenameAndJournalWriteLeavesOldOrNew(t *testing.T) {
	p, points := crashWorld(t)
	var olds, news int
	for k := 1; k <= points; k++ {
		p.reset()
		crash := &crasher{at: k}
		err := backup.RestoreWith(context.Background(), p.tg.options(), crash.env())
		if !errors.Is(err, errCrash) {
			t.Fatalf("crash point %d: Restore = %v, want the simulated crash", k, err)
		}
		where := crash.points[k-1]

		if err := backup.Recover(p.tg.dataDir); err != nil {
			t.Fatalf("crash %d (%s): Recover: %v", k, where, err)
		}
		if assertOldOrNew(t, p, where) {
			news++
		} else {
			olds++
		}
		if err := backup.Recover(p.tg.dataDir); err != nil {
			t.Fatalf("crash %d (%s): second Recover: %v", k, where, err)
		}
		assertOldOrNew(t, p, where+" (after a second Recover)")
	}
	t.Logf("%d crash points: %d ended in the old state, %d in the new", points, olds, news)
	if olds == 0 || news == 0 {
		t.Errorf("crash points ended %d times old and %d times new; both outcomes must occur", olds, news)
	}
}

func TestRepeatedlyInterruptedRecoveryStillConverges(t *testing.T) {
	p, points := crashWorld(t)
	// Every interruption point of the restore is covered by the test above;
	// here each sampled one is followed by recovery interrupted at every one of
	// recovery's own points, which is quadratic and dominated by fsync.
	stride := max(1, points/10)
	for k := 1; k <= points; k += stride {
		p.reset()
		crash := &crasher{at: k}
		if err := backup.RestoreWith(context.Background(), p.tg.options(), crash.env()); !errors.Is(err, errCrash) {
			t.Fatalf("crash point %d: Restore = %v", k, err)
		}
		crashed := relTreeCopy(t, p)
		for j := 1; ; j++ {
			replaceTree(t, crashed, p.tg.root)
			first := &crasher{at: j}
			err := backup.RecoverWith(p.tg.dataDir, first.env())
			if err == nil {
				assertOldOrNew(t, p, crash.points[k-1]+" then an uninterrupted recovery")
				break // recovery has fewer than j crash points
			}
			if !errors.Is(err, errCrash) {
				t.Fatalf("crash %d, recovery crash %d: %v", k, j, err)
			}
			// Crash again at the first point of the next attempt, then let it finish.
			again := &crasher{at: 1}
			if err := backup.RecoverWith(p.tg.dataDir, again.env()); err != nil && !errors.Is(err, errCrash) {
				t.Fatalf("crash %d, recovery crash %d, second attempt: %v", k, j, err)
			}
			if err := backup.Recover(p.tg.dataDir); err != nil {
				t.Fatalf("crash %d, recovery crash %d: final Recover: %v", k, j, err)
			}
			assertOldOrNew(t, p, crash.points[k-1]+" then recovery interrupted at "+first.points[j-1])
		}
	}
}

// relTreeCopy saves the crashed machine so recovery can be retried from it.
func relTreeCopy(t *testing.T, p *pristine) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "crashed")
	copyTree(t, p.tg.root, dir)
	return dir
}
