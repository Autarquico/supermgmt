//go:build crashpoints

package installer

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"slices"
	"strconv"
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
		"U:staged", "U:prev-linked", "U:prepared:recorded", "U:hold:applied", "U:stopped:applied", "U:stopped:recorded",
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
			if k >= recorded && h.liveArchives() != 1 {
				t.Errorf("%d live archives after a crash past the recorded backup, want exactly 1", h.liveArchives())
			}
			h.noViolations(t)
		})
	}
}

func TestUpgrade_ResumeAfterBackedUpRecordedLeavesOneNewerArchive(t *testing.T) {
	h := newUHost(t)
	crashAfter(t, h, "U:backed_up:recorded")
	if err := h.rerun(); err != nil {
		t.Fatalf("rerun: %v\n%s", err, h.out.String())
	}
	st, _ := h.state()
	if h.liveArchives() != 1 || h.archives != 2 || !strings.Contains(st.Archive, "pre-2") {
		t.Errorf("live %d, taken %d, recorded %q", h.liveArchives(), h.archives, st.Archive)
	}
}

func TestUpgrade_CrashAfterRetakeKeepsOneRecordedArchive(t *testing.T) {
	h := newUHost(t)
	crashAfter(t, h, "U:backed_up:recorded")
	hooks := defaultHooks()
	hooks.crash = func(point string) error {
		if point == "U:backup:retaken" {
			return errCrashed
		}
		return nil
	}
	if err := New(h.deps()).upgrade(context.Background(), h.upgradeOpts(), hooks); !errors.Is(err, errCrashed) {
		t.Fatalf("crash err = %v", err)
	}
	if err := h.rerun(); err != nil {
		t.Fatalf("rerun: %v\n%s", err, h.out.String())
	}
	if h.liveArchives() != 1 {
		t.Errorf("%d live archives, want 1", h.liveArchives())
	}
	h.noViolations(t)
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

func TestUpgrade_CrashAfterTheHoldKeepsItUntilTheServiceStarts(t *testing.T) {
	h := newUHost(t)
	crashAfter(t, h, "U:hold:applied")
	if !h.held || h.enabled {
		t.Errorf("held %t enabled %t after the crash", h.held, h.enabled)
	}
	h.reboot()
	if h.running && h.startedAs != binV1 {
		t.Errorf("a reboot started %q during the upgrade", h.startedAs)
	}
	if err := h.rerun(); err != nil {
		t.Fatalf("rerun: %v\n%s", err, h.out.String())
	}
	if h.held || !h.running || h.startedAs != binV2 {
		t.Errorf("held %t running %t as %q", h.held, h.running, h.startedAs)
	}
}

// ---- SUPERMGMT_CRASH_AT ----

func TestUpgradeCrashPoints_CoverEveryHitLiteral(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "upgrade.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	literals := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		lit, isLit := call.Args[0].(*ast.BasicLit)
		if !isSel || sel.Sel.Name != "hit" || !isLit {
			return true
		}
		literals++
		if point, _ := strconv.Unquote(lit.Value); !slices.Contains(upgradeCrashPoints, point) {
			t.Errorf("hit(%s) in upgrade.go is missing from upgradeCrashPoints", lit.Value)
		}
		return true
	})
	if literals == 0 {
		t.Fatal("found no hit literal; the scan is broken")
	}
}

func TestUpgradeCrashPoints_NameEveryPointOfARun(t *testing.T) {
	for _, point := range upgradePoints(t, func(*uhost) {}) {
		if !slices.Contains(upgradeCrashPoints, point) {
			t.Errorf("a normal run passes %q, which the env hook cannot name", point)
		}
	}
}

// TestUpgradeCrashHelper is the child process of TestUpgradeEnvHookExits86.
func TestUpgradeCrashHelper(t *testing.T) {
	if os.Getenv("SM_CRASH_HELPER") != "1" {
		t.Skip("child process only")
	}
	h := newUHost(t)
	d := h.deps()
	d.Host.Env = map[string]string{crashAtEnv: os.Getenv(crashAtEnv)}
	_ = New(d).upgrade(context.Background(), h.upgradeOpts(), defaultHooks())
}

func TestUpgradeEnvHookExits86(t *testing.T) {
	for _, point := range []string{"U:staged", "U:swap:before", "U:swapped:recorded"} {
		t.Run(point, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestUpgradeCrashHelper$")
			cmd.Env = append(os.Environ(), "SM_CRASH_HELPER=1", crashAtEnv+"="+point)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != crashExitCode {
				t.Fatalf("exit = %v, want code %d", err, crashExitCode)
			}
		})
	}
}

func TestUpgradeEnvHookIgnoresUnknownPoints(t *testing.T) {
	h := newUHost(t)
	d := h.deps()
	d.Host.Env = map[string]string{crashAtEnv: "U:no-such-point"}
	if err := New(d).upgrade(context.Background(), h.upgradeOpts(), defaultHooks()); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
}

func TestUpgrade_CrashBeforeSwapLeavesTheDowngradeRecordOnce(t *testing.T) {
	h := newUHost(t)
	h.oldContent = binV2
	h.put(applianceLayout().Binary, binV2)
	h.put("/usr/local/src/sm-new", binV1)
	o := h.upgradeOpts()
	o.AllowDowngrade = true
	hooks := defaultHooks()
	hooks.crash = func(point string) error {
		if point == "U:swap:before" {
			return errCrashed
		}
		return nil
	}
	if err := New(h.deps()).upgrade(context.Background(), o, hooks); !errors.Is(err, errCrashed) {
		t.Fatalf("crash err = %v", err)
	}
	pending := func() int {
		n := 0
		for p := range h.inodes {
			if strings.HasPrefix(p, applianceLayout().DataDir+"/"+pendingAuditDir+"/") {
				n++
			}
		}
		return n
	}
	if pending() != 1 {
		t.Fatalf("records after the crash = %d, want 1", pending())
	}
	if err := New(h.deps()).upgrade(context.Background(), o, defaultHooks()); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if pending() != 1 || h.live() != binV1 {
		t.Errorf("after the rerun: records %d, live %q; want 1 record (resume must not duplicate) and the new binary", pending(), h.live())
	}
}
