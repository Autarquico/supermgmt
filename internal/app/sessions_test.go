package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (f *fixture) sessions(t *testing.T) *Sessions {
	t.Helper()
	s, err := NewSessions(f.cfg)
	mustf(t, err, "NewSessions")
	return s
}

func (f *fixture) toolCapability(name string, available bool) {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetNodeCapability(ctx, tx, f.node.ID, database.NodeCapability{Capability: name, Available: available, CheckedAt: f.clock.Now()})
	})
}

func TestOpeningASessionIssuesItWithTheAdminConnectInfo(t *testing.T) {
	f := newFixture(t)

	session, info, err := f.sessions(t).Open(context.Background(), f.caller(f.alice), f.node.ID, string(wire.ToolShell))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := session
	if s.State != wire.SessionIssued || s.Tool != wire.ToolShell || s.NodeID != f.node.ID || s.EndedAt != nil || s.EndReason != nil {
		t.Errorf("session = %+v", s)
	}
	if info.User != "admin" || info.HostPublicKey != testHostKey || info.HostKeyAlias != "sm-"+f.node.ID.String() {
		t.Errorf("connect info = %+v", info)
	}
	if got := f.events("node.session.opened"); len(got) != 1 || got[0].Data["tool"] != "shell" {
		t.Errorf("events = %+v", got)
	}
}

func TestOpeningASessionIsIdempotentUnderTheSameKey(t *testing.T) {
	f := newFixture(t)
	first, _ := f.keyed(f.alice, "open-1", "h")
	first.Idempotency.Respond = func(any, error) (int, []byte) { return 201, []byte(`{"data":"opened"}`) }
	again, _ := f.keyed(f.alice, "open-1", "h")
	s := f.sessions(t)

	_, _, err := s.Open(context.Background(), first, f.node.ID, string(wire.ToolShell))
	mustf(t, err, "first Open")
	_, _, err = s.Open(context.Background(), again, f.node.ID, string(wire.ToolShell))

	_ = asReplay(t, err)
	if len(f.events("node.session.opened")) != 1 {
		t.Error("a retried open issued a second session")
	}
}

func TestOpeningRefusesWhatTheNodeCannotDo(t *testing.T) {
	f := newFixture(t)
	s := f.sessions(t)
	ctx, by := context.Background(), f.caller(f.alice)

	_, _, unknown := s.Open(ctx, by, f.node.ID, "vim")
	_, _, missing := s.Open(ctx, by, f.node.ID, string(wire.ToolLazydocker)) // never probed
	f.toolCapability("tool.btop", true)
	_, _, installed := s.Open(ctx, by, f.node.ID, string(wire.ToolBtop))
	_, _, denied := s.Open(ctx, f.caller(f.dave), f.node.ID, string(wire.ToolShell))
	f.toolCapability("node.ssh", false)
	_, _, noSSH := s.Open(ctx, by, f.node.ID, string(wire.ToolShell))

	if smerr.CodeOf(unknown) != smerr.CodeInvalidArgument || smerr.CodeOf(missing) != smerr.CodeCapabilityUnavailable ||
		installed != nil || smerr.CodeOf(denied) != smerr.CodePolicyDenied || smerr.CodeOf(noSSH) != smerr.CodeCapabilityUnavailable {
		t.Errorf("unknown %v, missing %v, installed %v, denied %v, noSSH %v", unknown, missing, installed, denied, noSSH)
	}
}

func TestTheFirstEndWinsAndIsAuditedOnce(t *testing.T) {
	f := newFixture(t)
	s := f.sessions(t)
	ctx, by := context.Background(), f.caller(f.alice)
	opened, _, err := s.Open(ctx, by, f.node.ID, string(wire.ToolShell))
	mustf(t, err, "Open")
	code := 3

	ended, err := s.End(ctx, by, f.node.ID, opened.ID, EndSession{Reason: wire.EndExited, ExitCode: &code})
	if err != nil || ended.State != wire.SessionEnded || ended.ExitCode == nil || *ended.ExitCode != 3 || ended.EndReason == nil || *ended.EndReason != wire.EndExited {
		t.Fatalf("End = %+v, %v", ended, err)
	}
	other := 0
	again, err := s.End(ctx, by, f.node.ID, opened.ID, EndSession{Reason: wire.EndLaunchFailed, ExitCode: &other})

	if err != nil || *again.ExitCode != 3 || *again.EndReason != wire.EndExited {
		t.Errorf("second End = %+v, %v; the first end must stand", again, err)
	}
	if len(f.events("node.session.ended")) != 1 {
		t.Errorf("%d end events, want 1", len(f.events("node.session.ended")))
	}
}

func TestOnlyTheOwnerOfASessionOnItsNodeCanEndIt(t *testing.T) {
	f := newFixture(t)
	s := f.sessions(t)
	ctx := context.Background()
	opened, _, err := s.Open(ctx, f.caller(f.alice), f.node.ID, string(wire.ToolShell))
	mustf(t, err, "Open")

	_, byBob := s.End(ctx, f.caller(f.bob), f.node.ID, opened.ID, EndSession{Reason: wire.EndExited})
	_, wrongNode := s.End(ctx, f.caller(f.alice), "00000000-0000-7000-8000-00000000ffff", opened.ID, EndSession{Reason: wire.EndExited})
	_, badReason := s.End(ctx, f.caller(f.alice), f.node.ID, opened.ID, EndSession{Reason: wire.EndAbandoned})

	if smerr.CodeOf(byBob) != smerr.CodeNotFound || smerr.CodeOf(wrongNode) != smerr.CodeNotFound || smerr.CodeOf(badReason) != smerr.CodeInvalidArgument {
		t.Errorf("bob %v, wrong node %v, bad reason %v", byBob, wrongNode, badReason)
	}
}

func TestSessionsLeftOpenAreAbandonedBySweep(t *testing.T) {
	f := newFixture(t)
	s := f.sessions(t)
	ctx, by := context.Background(), f.caller(f.alice)
	old, _, err := s.Open(ctx, by, f.node.ID, string(wire.ToolShell))
	mustf(t, err, "Open")
	f.clock.Advance(sessionTTL + time.Minute)
	fresh, _, err := s.Open(ctx, by, f.node.ID, string(wire.ToolShell))
	mustf(t, err, "Open")
	sweeper, err := NewSweeper(f.cfg, SweeperOptions{Store: f.store})
	mustf(t, err, "NewSweeper")

	mustf(t, sweeper.Sweep(ctx), "Sweep")

	gotOld, _ := database.GetInteractiveSession(ctx, f.db.Reader(), old.ID)
	gotFresh, _ := database.GetInteractiveSession(ctx, f.db.Reader(), fresh.ID)
	if gotOld.State != database.SessionAbandoned || gotFresh.State != database.SessionIssued {
		t.Errorf("old %s, fresh %s", gotOld.State, gotFresh.State)
	}
	if ev := f.events("node.session.abandoned"); len(ev) != 1 || ev[0].ActorType != domain.ActorSystem {
		t.Errorf("events = %+v", ev)
	}
}
