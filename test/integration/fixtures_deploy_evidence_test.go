//go:build fixtures

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// What the deployment evidence source (internal/app/deploy_evidence.go) and
// the reconciler rely on, observed on a real node: the pull marker and its
// .done, the project flock, and the state a killed `compose up` leaves behind.

const lockProbeConflict = templates.LockConflictExit

// slowComposeYAML brings a service up behind a dependency that turns healthy
// only after a while, so `compose up --detach` keeps running (and holding the
// project lock) for about twenty seconds.
const slowComposeYAML = `services:
  db:
    image: ` + busyboxImage + `
    command: ["sh", "-c", "sleep 12; touch /tmp/ready; sleep 600"]
    healthcheck:
      test: ["CMD-SHELL", "test -f /tmp/ready"]
      interval: 2s
      timeout: 2s
      retries: 30
  web:
    image: ` + busyboxImage + `
    command: ["sleep", "600"]
    depends_on:
      db:
        condition: service_healthy
`

// lockHeld reports whether a compose command of the project still holds the lock.
func (n *deployNode) lockHeld(t *testing.T, project string) bool {
	t.Helper()
	res := n.readTemplate(t, "compose.lock_probe", map[string]string{"project": project})
	switch res.ExitStatus {
	case 0:
		return false
	case lockProbeConflict:
		return true
	}
	t.Fatalf("compose.lock_probe exit %d: %s", res.ExitStatus, stderrOf(res))
	return false
}

// waitLockHeldBy waits for the lock of the run's project to be taken, failing
// with the run's own outcome if the command ended without ever holding it.
// It does not probe before the run's marker exists: lock_probe takes the lock
// for a moment itself, and a probe that lands between the command's start and
// its flock makes the command refuse with the conflict status.
func (n *deployNode) waitLockHeldBy(t *testing.T, run backgroundRun, project string, within time.Duration) {
	t.Helper()
	const poll = 250 * time.Millisecond
	for range int(within / poll) {
		select {
		case out := <-run.done:
			t.Fatalf("the command ended before the lock was seen held: err=%v exit %d\nstdout: %s\nstderr: %s",
				out.err, out.res.ExitStatus, out.res.Stdout, out.res.Stderr)
		default:
		}
		if n.markerOf(t, run.marker).Kind != templates.MarkerAbsent && n.lockHeld(t, project) {
			return
		}
		time.Sleep(poll)
	}
	t.Fatalf("project lock of %s was not taken within %s", project, within)
}

func (n *deployNode) waitLock(t *testing.T, project string, held bool, within time.Duration) {
	t.Helper()
	const poll = 500 * time.Millisecond
	for range int(within / poll) {
		if n.lockHeld(t, project) == held {
			return
		}
		time.Sleep(poll)
	}
	t.Fatalf("project lock of %s did not become held=%v within %s", project, held, within)
}

// stageSlowProject pulls busybox and materializes slowComposeYAML as a new deployment.
func (n *deployNode) stageSlowProject(t *testing.T, project, deployment string) {
	t.Helper()
	n.adoptProject(t, project)
	if res := n.materialize(t, deployDirArgs(project, deployment), composeOnly(slowComposeYAML)); res.ExitStatus != 0 {
		t.Fatalf("materialize: %s", stderrOf(res))
	}
}

type backgroundRun struct {
	marker string
	done   chan runOutcome
}

type runOutcome struct {
	res transport.Result
	err error
}

// startComposeUp runs the Locked compose.up template in the background, the
// way the worker does, and returns once the command has been sent.
func (n *deployNode) startComposeUp(t *testing.T, project, deployment string) backgroundRun {
	t.Helper()
	marker := deployMarker()
	cmd, err := templates.RenderMutatingInput("compose.up", marker, deployDirArgs(project, deployment), nil, project)
	if err != nil {
		t.Fatalf("render compose.up: %v", err)
	}
	run := backgroundRun{marker: marker, done: make(chan runOutcome, 1)}
	go func() {
		res, err := n.super.Run(t.Context(), cmd)
		run.done <- runOutcome{res, err}
	}()
	return run
}

func TestFixtures_PullGoesThroughTLSAndLeavesAMarker(t *testing.T) {
	n := startDeployNode(t)
	reg := n.startRegistry(t)
	const deployment = "018f0000-0000-7000-8000-0000000000a1"
	pullMarker := deployment + "-0"

	t.Run("a registry whose certificate the node does not trust cannot be pulled from", func(t *testing.T) {
		reg.distrust(t)
		defer reg.trust(t)
		res := n.mutateMarked(t, pullMarker+"x", "compose.pull", map[string]string{"image": reg.ref()}, nil, "")
		if res.ExitStatus == 0 {
			t.Fatalf("pull from an untrusted registry succeeded: %s", res.Stdout)
		}
		if out := string(res.Stderr); !strings.Contains(out, "x509") && !strings.Contains(out, "certificate") {
			t.Errorf("pull failed, but not on the certificate: %q", out)
		}
		state := n.markerOf(t, pullMarker+"x")
		if state.Kind != templates.MarkerDone || state.CompletionProof() {
			t.Errorf("marker after a failed pull = %+v; want done with a nonzero status and no completion proof", state)
		}
	})

	t.Run("with the test CA trusted the pull succeeds and .done holds exit 0 under the intent's marker name", func(t *testing.T) {
		res := n.mutateMarked(t, pullMarker, "compose.pull", map[string]string{"image": reg.ref()}, nil, "")
		if res.ExitStatus != 0 {
			t.Fatalf("pull exit %d: %s", res.ExitStatus, stderrOf(res))
		}
		if state := n.markerOf(t, pullMarker); !state.CompletionProof() {
			t.Errorf("marker %s = %+v; want done with exit 0", pullMarker, state)
		}
		if res := n.readTemplate(t, "compose.image_inspect", map[string]string{"image": reg.ref()}); res.ExitStatus != 0 {
			t.Errorf("the pulled image is not on the node: %s", stderrOf(res))
		}
	})

	t.Run("a marker nobody wrote reads as absent", func(t *testing.T) {
		if state := n.markerOf(t, deployment+"-9"); state.Kind != templates.MarkerAbsent {
			t.Errorf("marker = %+v; want absent", state)
		}
	})
}

func TestFixtures_ComposeLockQuiescence(t *testing.T) {
	n := startDeployNode(t)
	n.shell(t, "docker pull -q "+busyboxImage)
	const (
		project = "t17b-lock"
		first   = "018f0000-0000-7000-8000-0000000000b1"
		second  = "018f0000-0000-7000-8000-0000000000b2"
	)
	n.stageSlowProject(t, project, first)
	n.stageSlowProject(t, project, second)

	if n.lockHeld(t, project) {
		t.Fatal("the lock of an idle project reads as held")
	}
	run := n.startComposeUp(t, project, first)
	n.waitLockHeldBy(t, run, project, 20*time.Second)

	t.Run("a second compose command of the same project is refused without waiting and never starts", func(t *testing.T) {
		res, marker := n.mutate(t, "compose.up", deployDirArgs(project, second), nil, project)
		if res.ExitStatus != templates.LockConflictExit {
			t.Errorf("exit %d; want the lock conflict %d: %s", res.ExitStatus, templates.LockConflictExit, stderrOf(res))
		}
		if state := n.markerOf(t, marker); state.Kind != templates.MarkerAbsent {
			t.Errorf("marker of the refused command = %+v; want absent, i.e. it never began", state)
		}
	})

	t.Run("another project's lock is independent", func(t *testing.T) {
		if n.lockHeld(t, "t17b-other") {
			t.Error("an unrelated project reads as locked")
		}
	})

	out := <-run.done
	if out.err != nil || out.res.ExitStatus != 0 {
		t.Fatalf("the first compose up: err=%v exit %d: %s", out.err, out.res.ExitStatus, stderrOf(out.res))
	}

	t.Run("the lock is released when the command ends and its marker holds exit 0", func(t *testing.T) {
		if n.lockHeld(t, project) {
			t.Error("the lock is still held after compose up returned")
		}
		if state := n.markerOf(t, run.marker); !state.CompletionProof() {
			t.Errorf("marker = %+v; want done with exit 0", state)
		}
	})
}

// A killed CLI leaves containers that look settled and no .done: the evidence
// source must not read that as a completed deployment (spec §20.4).
func TestFixtures_KilledComposeUpHasNoProof(t *testing.T) {
	n := startDeployNode(t)
	n.shell(t, "docker pull -q "+busyboxImage)
	const (
		project = "t17b-killed"
		id      = "018f0000-0000-7000-8000-0000000000c1"
	)
	n.stageSlowProject(t, project, id)
	run := n.startComposeUp(t, project, id)
	n.waitLockHeldBy(t, run, project, 20*time.Second)

	if state := n.markerOf(t, run.marker); state.Kind != templates.MarkerStarted {
		t.Fatalf("marker while compose up runs = %+v; want started", state)
	}

	// Kill the wrapper (flock and the shell that would write .done); the
	// timeout/compose children survive, exactly as when the worker is killed.
	pattern := fmt.Sprintf("[%c]%s", run.marker[0], run.marker[1:])
	n.shell(t, "pkill -KILL -f '"+pattern+"'")

	t.Run("the project lock stays held while the orphaned compose still runs", func(t *testing.T) {
		if !n.lockHeld(t, project) {
			t.Error("the lock was released although compose up is still running")
		}
	})

	n.waitLock(t, project, false, 90*time.Second)
	select {
	case <-run.done:
	case <-time.After(30 * time.Second):
		t.Error("the killed command's session never ended")
	}

	t.Run("the containers settle and two samples agree", func(t *testing.T) {
		sample := func() string {
			var parts []string
			for _, c := range n.projectContainers(t, project) {
				parts = append(parts, c.ID+"|"+c.Config.Image+"|"+c.State.Status)
			}
			return strings.Join(parts, "\n")
		}
		first := sample()
		time.Sleep(2 * time.Second)
		if second := sample(); second != first {
			t.Errorf("samples differ:\n%s\n--\n%s", first, second)
		}
		containers := n.projectContainers(t, project)
		if len(containers) != 2 {
			t.Fatalf("project has %d containers; want 2", len(containers))
		}
		for _, c := range containers {
			if c.State.Status != "running" {
				t.Errorf("%s is %s; want running", c.Name, c.State.Status)
			}
		}
	})

	t.Run("the marker still reads started and offers no completion proof", func(t *testing.T) {
		for range 2 {
			state := n.markerOf(t, run.marker)
			if state.Kind != templates.MarkerStarted || state.CompletionProof() {
				t.Fatalf("marker after the kill = %+v; want started without proof", state)
			}
			time.Sleep(time.Second)
		}
		if got := n.shell(t, "ls /var/lib/supermgmt/markers | grep -c '^"+run.marker+"'"); got != "1" {
			t.Errorf("%s files for the marker; want exactly the marker itself (no .done)", got)
		}
	})
}
