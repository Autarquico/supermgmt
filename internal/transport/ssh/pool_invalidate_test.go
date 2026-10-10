package ssh

import (
	"testing"
	"time"
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

func TestInvalidateOfAnUnknownNodeIsANoOp(t *testing.T) {
	r := newRig(t, defaultConfig(), nil)
	r.pool.Invalidate("nobody", "supermgmt")
}
