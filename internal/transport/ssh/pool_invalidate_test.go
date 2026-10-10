package ssh

import (
	"context"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func slowOrFast(release <-chan struct{}) func(*testServer) {
	return func(s *testServer) {
		s.handler = func(cmd string, _ []byte) reply {
			if cmd == "slow" {
				return reply{stdout: "finished", wait: release}
			}
			return reply{stdout: "fast"}
		}
	}
}

func TestChangedTargetDoesNotCutShortACommandRunningOnTheOldConnection(t *testing.T) {
	release := make(chan struct{})
	r := newRig(t, defaultConfig(), slowOrFast(release))
	type outcome struct {
		out string
		err error
	}
	slow := make(chan outcome, 1)
	go func() {
		out, err := r.run("slow")
		slow <- outcome{out, err}
	}()
	eventually(t, "slow command running", func() bool { return r.server.inSessions.Load() == 1 })

	r.server.setHostKey(newSigner(t)) // the node's key rotated: the target changes
	if out, err := r.run("quick"); err != nil || out != "fast" {
		t.Fatalf("command on the new target: %q, %v", out, err)
	}
	close(release)
	if got := <-slow; got.err != nil || got.out != "finished" {
		t.Fatalf("the running command was cut short: %q, %v", got.out, got.err)
	}
	eventually(t, "old connection retired", func() bool {
		r.pool.mu.Lock()
		defer r.pool.mu.Unlock()
		return len(r.pool.retiring) == 0
	})
}

func TestInvalidateForcesAFreshConnectionOnIdleNodes(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	r.pool.Invalidate(r.nodeID, "supermgmt")
	if st := r.pool.State(r.nodeID).Status; st != ConnUnknown {
		t.Fatalf("state after Invalidate = %v", st)
	}
	if _, err := r.run("x"); err != nil {
		t.Fatal(err)
	}
	if n := r.server.connections.Load(); n != 2 {
		t.Errorf("%d connections, want 2", n)
	}
}

func TestInvalidateIsDrainSafeAndNewCommandsDoNotWait(t *testing.T) {
	release := make(chan struct{})
	r := newRig(t, defaultConfig(), slowOrFast(release))
	done := make(chan error, 1)
	go func() { _, err := r.run("slow"); done <- err }()
	eventually(t, "slow command running", func() bool { return r.server.inSessions.Load() == 1 })

	r.pool.Invalidate(r.nodeID, "supermgmt")
	if out, err := r.run("quick"); err != nil || out != "fast" {
		t.Fatalf("%q, %v", out, err)
	}
	if n := r.server.connections.Load(); n != 2 {
		t.Errorf("%d connections, want a fresh second one", n)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the in-flight command was cut short: %v", err)
	}
}

func TestInvalidateDuringADialDiscardsTheStaleConnection(t *testing.T) {
	r := newRig(t, defaultConfig(), func(s *testServer) { s.handshakeDelay = 150 * time.Millisecond })
	errc := make(chan error, 1)
	go func() { _, err := r.run("x"); errc <- err }()
	eventually(t, "handshake started", func() bool { return r.server.inHandshake.Load() == 1 })

	r.pool.Invalidate(r.nodeID, "supermgmt")
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if n := r.server.connections.Load(); n != 2 {
		t.Errorf("%d connections, want the pre-Invalidate dial discarded and one more made", n)
	}
}

// TestTwoTargetsForOneNodeAndUserDoNotReplaceEachOtherForever: a dial whose
// slot was taken over by a different Target fails once instead of re-dialing
// and taking the slot back.
func TestTwoTargetsForOneNodeAndUserDoNotReplaceEachOtherForever(t *testing.T) {
	gate := make(chan struct{})
	r := newRig(t, defaultConfig(), func(s *testServer) { s.handshakeGate = gate })
	first := r.target()
	second := r.target()
	second.CredentialRef = "secret://ssh/default@2" // same node and user, different Target

	errA, errB := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := r.pool.For(first).Run(context.Background(), templatesRead("x"))
		errA <- err
	}()
	eventually(t, "first handshake started", func() bool { return r.server.inHandshake.Load() == 1 })
	go func() {
		_, err := r.pool.For(second).Run(context.Background(), templatesRead("x"))
		errB <- err
	}()
	eventually(t, "second target took the slot", func() bool {
		r.pool.mu.Lock()
		defer r.pool.mu.Unlock()
		return r.pool.peers[connKey{r.nodeID, "supermgmt"}].target == second
	})
	close(gate)

	select {
	case err := <-errA:
		requireCode(t, err, smerr.CodeNodeUnreachable)
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced caller is still looping")
	}
	if err := <-errB; err != nil {
		t.Fatalf("the newer target: %v", err)
	}
}

func TestInvalidateOfAnUnknownNodeIsANoOp(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	r.pool.Invalidate("nobody", "supermgmt")
}
