package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

type residencyFixture struct {
	clock *domaintest.FakeClock
	busy  bool
	err   error
	r     *Residency
}

func newResidencyFixture(resident bool) *residencyFixture {
	f := &residencyFixture{clock: domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))}
	f.r = NewResidency(ResidencyConfig{
		Clock: f.clock, IdleExit: 10 * time.Minute, Resident: resident,
		Busy: func(context.Context) (bool, error) { return f.busy, f.err },
	})
	return f
}

func (f *residencyFixture) expiredAfter(d time.Duration) bool {
	f.clock.Advance(d)
	return f.r.Expired(context.Background())
}

func TestAnIdleDaemonExpiresAtIdleExit(t *testing.T) {
	f := newResidencyFixture(false)
	if f.expiredAfter(9 * time.Minute) {
		t.Error("expired before idle_exit")
	}
	if !f.expiredAfter(time.Minute) {
		t.Error("did not expire at idle_exit")
	}
}

func TestActiveWorkKeepsTheDaemonAliveAndTheTimerStartsAfterTheLastJob(t *testing.T) {
	f := newResidencyFixture(false)
	f.busy = true // queued, awaiting_approval, running or interrupted
	if f.expiredAfter(time.Hour) {
		t.Fatal("expired with active work")
	}
	f.busy = false
	if f.expiredAfter(9 * time.Minute) {
		t.Error("the timer counted idle time while a job was active")
	}
	if !f.expiredAfter(time.Minute) {
		t.Error("did not expire 10m after the last job")
	}
}

func TestPresenceAndInFlightRequestsHoldTheTimerAndRestartItWhenTheyEnd(t *testing.T) {
	f := newResidencyFixture(false)
	leave := f.r.Present()
	if f.expiredAfter(time.Hour) {
		t.Fatal("expired with a client present")
	}
	end := f.r.Begin()
	leave()
	if f.expiredAfter(time.Hour) {
		t.Fatal("expired with a request in flight")
	}
	end()
	end() // calling twice must not go negative
	if f.expiredAfter(9 * time.Minute) {
		t.Error("the timer did not restart when the last request ended")
	}
	if !f.expiredAfter(time.Minute) {
		t.Error("did not expire 10m after the last request")
	}
}

func TestAnyChangeResetsTheTimer(t *testing.T) {
	f := newResidencyFixture(false)
	f.clock.Advance(9 * time.Minute)
	f.r.Begin()()
	if f.expiredAfter(9 * time.Minute) {
		t.Error("a request did not reset the timer")
	}
}

func TestAFailingActivityQueryKeepsTheDaemonAlive(t *testing.T) {
	f := newResidencyFixture(false)
	f.err = errors.New("database busy")
	if f.expiredAfter(time.Hour) {
		t.Error("expired although active work could not be ruled out")
	}
}

func TestAResidentDaemonNeverExpires(t *testing.T) {
	f := newResidencyFixture(true)
	if f.expiredAfter(100 * time.Hour) {
		t.Error("a resident daemon expired")
	}
}
