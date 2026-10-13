package installer

import (
	"errors"
	"testing"
)

func TestUpgrade_HoldBeforeStop(t *testing.T) {
	h := newUHost(t)
	if err := h.upgrade(defaultHooks()); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.out.String())
	}
	hold, stop, waited, register, start := h.index("hold "), h.index("stop "), h.index("waitstopped "), h.index("register "), h.index("start ")
	if hold < 0 || hold >= stop || stop >= waited || waited >= register || register >= start {
		t.Errorf("hold %d, stop %d, waitstopped %d, register %d, start %d: %v", hold, stop, waited, register, start, h.events)
	}
	if h.index("disable ") >= 0 {
		t.Errorf("the upgrade used the plain disable: %v", h.events)
	}
}

func TestUpgrade_FailedBackupLiftsTheHoldWhenTheOldServiceReturns(t *testing.T) {
	h := newUHost(t)
	h.backupErr = errors.New("disk full")
	if err := h.upgrade(defaultHooks()); err == nil {
		t.Fatal("upgrade succeeded despite the failed backup")
	}
	if h.held || !h.running || h.startedAs != binV1 {
		t.Errorf("held %t running %t as %q: the old service must come back unheld", h.held, h.running, h.startedAs)
	}
}
