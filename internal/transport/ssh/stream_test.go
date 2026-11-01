package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func exportCmd() templates.Command {
	return templates.Command{Template: "docker.volume_export", Line: "export-line", Stream: templates.StreamExport}
}

func importCmd() templates.Command {
	return templates.Command{Template: "docker.volume_import", Line: "import-line", Stream: templates.StreamImport, Mutating: true}
}

var streamOpts = transport.StreamOptions{Total: 10 * time.Second, Idle: 5 * time.Second, Ceiling: 64 << 20}

func exitStatus(ch cryptossh.Channel, status uint32) {
	_, _ = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{status}))
}

func (r relayRig) openStream(t *testing.T, c templates.Command, o transport.StreamOptions) transport.Stream {
	t.Helper()
	st, err := r.pool.OpenStream(context.Background(), r.target(), c, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Abort(); _, _, _ = st.Wait() })
	return st
}

func oneSession() PoolConfig {
	cfg := defaultConfig()
	cfg.MaxSessionsPerConnection = 1
	return cfg
}

// freeSlot proves the only session slot is free by opening a stream on it.
func (r relayRig) freeSlot(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := r.pool.OpenStream(ctx, r.target(), exportCmd(), streamOpts)
	if err != nil {
		t.Fatalf("the session slot was not released: %v", err)
	}
	st.Abort()
	_, _, _ = st.Wait()
}

func allBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

func TestExportStreamsBinaryBytesAndReportsExit(t *testing.T) {
	payload := allBytes(3<<20 + 17)
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) {
		_, _ = ch.Write(payload)
		exitStatus(ch, 0)
	})
	st := r.openStream(t, exportCmd(), streamOpts)
	got, err := io.ReadAll(st)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes, %v; want %d identical bytes", len(got), err, len(payload))
	}
	if exit, tail, err := st.Wait(); exit != 0 || tail != "" || err != nil {
		t.Errorf("Wait = %d %q %v", exit, tail, err)
	}
	if cmds := r.server.seen(); len(cmds) != 1 || cmds[0] != "export-line" {
		t.Errorf("commands = %q", cmds)
	}
	r.freeSlot(t)
}

func TestANonZeroExitIsAResultWithASanitisedBoundedTail(t *testing.T) {
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) {
		_, _ = ch.Stderr().Write([]byte("Error: no such container\x1b[31m red\nTOKEN=" + string(bytes.Repeat([]byte("x"), 50000))))
		exitStatus(ch, 3)
	})
	st := r.openStream(t, exportCmd(), streamOpts)
	_, _ = io.Copy(io.Discard, st)
	exit, tail, err := st.Wait()
	if exit != 3 || err != nil {
		t.Fatalf("Wait = %d %v, want exit 3 and no error", exit, err)
	}
	if len([]rune(tail)) > diagnosticRunes+3 || bytes.ContainsAny([]byte(tail), "\x1b\n") {
		t.Errorf("tail is not bounded and sanitised: %q", tail)
	}
}

func TestAMissingExitStatusIsAnError(t *testing.T) {
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) { _, _ = ch.Write([]byte("partial")) })
	st := r.openStream(t, exportCmd(), streamOpts)
	_, _ = io.Copy(io.Discard, st)
	if _, _, err := st.Wait(); smerr.CodeOf(err) != smerr.CodeNodeUnreachable {
		t.Fatalf("Wait err = %v, want NODE_UNREACHABLE", err)
	}
	r.freeSlot(t)
}

func TestImportDeliversEveryByteAndCloseGivesTheNodeEOF(t *testing.T) {
	payload := allBytes(2<<20 + 3)
	received := make(chan []byte, 1)
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) {
		b, _ := io.ReadAll(ch)
		received <- b
		exitStatus(ch, 0)
	})
	st := r.openStream(t, importCmd(), streamOpts)
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	_ = st.Close() // idempotent
	if exit, _, err := st.Wait(); exit != 0 || err != nil {
		t.Fatalf("Wait = %d %v", exit, err)
	}
	if got := <-received; !bytes.Equal(got, payload) {
		t.Errorf("node received %d bytes, want %d identical", len(got), len(payload))
	}
	r.freeSlot(t)
}

func TestABlockedPeerEndsAtTheIdleDeadlineAndFreesTheSlot(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) { <-release })
	st := r.openStream(t, importCmd(), transport.StreamOptions{Total: 30 * time.Second, Idle: 300 * time.Millisecond, Ceiling: 1 << 30})

	writeErr := make(chan error, 1)
	go func() {
		_, err := st.Write(make([]byte, 16<<20)) // far beyond the channel window
		writeErr <- err
	}()
	select {
	case err := <-writeErr:
		if !errors.Is(err, transport.ErrStreamIdle) {
			t.Errorf("Write err = %v, want the idle deadline", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the blocked write never ended")
	}
	if _, _, err := st.Wait(); !errors.Is(err, transport.ErrStreamIdle) || smerr.CodeOf(err) != smerr.CodeTimeout {
		t.Errorf("Wait err = %v, want a TIMEOUT for the idle deadline", err)
	}
}

func TestTheTotalDeadlineEndsAStreamThatNeverFinishes(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) { <-release })
	st := r.openStream(t, exportCmd(), transport.StreamOptions{Total: 250 * time.Millisecond, Idle: 250 * time.Millisecond, Ceiling: 1 << 20})
	if _, _, err := st.Wait(); !errors.Is(err, transport.ErrStreamTotal) {
		t.Fatalf("Wait err = %v, want the total deadline", err)
	}
	r.freeSlot(t)
}

func TestTheIdleDeadlineIsSuspendedOnceTheInputIsClosed(t *testing.T) {
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) {
		_, _ = io.ReadAll(ch)
		time.Sleep(600 * time.Millisecond) // extracting takes longer than the idle deadline
		exitStatus(ch, 0)
	})
	st := r.openStream(t, importCmd(), transport.StreamOptions{Total: 10 * time.Second, Idle: 200 * time.Millisecond, Ceiling: 1 << 20})
	_, _ = st.Write([]byte("tar"))
	_ = st.Close()
	if exit, _, err := st.Wait(); exit != 0 || err != nil {
		t.Fatalf("Wait = %d %v", exit, err)
	}
}

func TestExceedingTheCeilingAbortsInBothDirections(t *testing.T) {
	t.Run("export", func(t *testing.T) {
		r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) {
			_, _ = ch.Write(make([]byte, 100<<10))
			exitStatus(ch, 0)
		})
		st := r.openStream(t, exportCmd(), transport.StreamOptions{Total: 10 * time.Second, Idle: 5 * time.Second, Ceiling: 1 << 10})
		_, err := io.Copy(io.Discard, st)
		if !errors.Is(err, transport.ErrStreamCeiling) {
			t.Errorf("read err = %v", err)
		}
		if _, _, err := st.Wait(); !errors.Is(err, transport.ErrStreamCeiling) {
			t.Errorf("Wait err = %v", err)
		}
		r.freeSlot(t)
	})
	t.Run("import", func(t *testing.T) {
		r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) {
			_, _ = io.Copy(io.Discard, ch)
			exitStatus(ch, 0)
		})
		st := r.openStream(t, importCmd(), transport.StreamOptions{Total: 10 * time.Second, Idle: 5 * time.Second, Ceiling: 1 << 10})
		if _, err := st.Write(make([]byte, 2<<10)); !errors.Is(err, transport.ErrStreamCeiling) {
			t.Errorf("write err = %v", err)
		}
		if _, _, err := st.Wait(); !errors.Is(err, transport.ErrStreamCeiling) {
			t.Errorf("Wait err = %v", err)
		}
		r.freeSlot(t)
	})
}

func TestAbortIsIdempotentAndAnAbortedExportNeverEndsCleanly(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) {
		_, _ = ch.Write([]byte("some"))
		<-release
	})
	st := r.openStream(t, exportCmd(), streamOpts)
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); st.Abort() }()
	}
	wg.Wait()
	if _, err := st.Read(buf); !errors.Is(err, transport.ErrStreamAborted) {
		t.Errorf("read after abort = %v, want the abort, never EOF", err)
	}
	if _, _, err := st.Wait(); !errors.Is(err, transport.ErrStreamAborted) {
		t.Errorf("Wait err = %v", err)
	}
	st.Abort()
	r.freeSlot(t)
}

func TestCancellingTheContextAbortsARunningStream(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) { <-release })
	ctx, cancel := context.WithCancel(context.Background())
	st, err := r.pool.OpenStream(ctx, r.target(), exportCmd(), streamOpts)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, _, err := st.Wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait err = %v, want context.Canceled", err)
	}
	r.freeSlot(t)
}

func TestCancellingWhileTheSessionOpensFreesTheSlot(t *testing.T) {
	gate := make(chan struct{})
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) { exitStatus(ch, 0) })
	r.server.execGate = gate
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := r.pool.OpenStream(ctx, r.target(), exportCmd(), streamOpts)
	requireCode(t, err, smerr.CodeTimeout)
	close(gate)
	r.freeSlot(t)
}

func TestAStreamCountsAgainstTheSessionLimitUntilItEnds(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) { <-release })
	first := r.openStream(t, exportCmd(), streamOpts)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := r.pool.OpenStream(ctx, r.target(), exportCmd(), streamOpts)
	requireCode(t, err, smerr.CodeTimeout)

	first.Abort()
	_, _, _ = first.Wait()
	r.freeSlot(t)
}

func TestWrongDirectionAndBadOptionsAreRefused(t *testing.T) {
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) { exitStatus(ch, 0) })
	exp := r.openStream(t, exportCmd(), streamOpts)
	if _, err := exp.Write([]byte("x")); !errors.Is(err, transport.ErrStreamDirection) {
		t.Errorf("write on an export = %v", err)
	}
	_, _, _ = exp.Wait()
	imp := r.openStream(t, importCmd(), streamOpts)
	if _, err := imp.Read(make([]byte, 1)); !errors.Is(err, transport.ErrStreamDirection) {
		t.Errorf("read on an import = %v", err)
	}
	_ = imp.Close()
	_, _, _ = imp.Wait()

	for name, o := range map[string]transport.StreamOptions{
		"no total":   {Idle: time.Second, Ceiling: 1},
		"no idle":    {Total: time.Second, Ceiling: 1},
		"no ceiling": {Total: time.Second, Idle: time.Second},
		"idle>total": {Total: time.Second, Idle: time.Minute, Ceiling: 1},
	} {
		if _, err := r.pool.OpenStream(context.Background(), r.target(), exportCmd(), o); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := r.pool.OpenStream(context.Background(), r.target(), templates.Command{Line: "ls"}, streamOpts); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("a plain command was opened as a stream: %v", err)
	}
	if n := len(r.server.seen()); n != 2 {
		t.Errorf("%d commands reached the node, want the 2 valid streams", n)
	}
}

func TestManyStreamsLeaveNoGoroutinesBehind(t *testing.T) {
	r := newRelayRig(t, oneSession(), func(_ string, ch cryptossh.Channel) {
		_, _ = ch.Write([]byte("x"))
		exitStatus(ch, 0)
	})
	r.freeSlot(t) // connects, so the baseline holds the pool's goroutines
	baseline := runtime.NumGoroutine()
	for range 20 {
		st, err := r.pool.OpenStream(context.Background(), r.target(), exportCmd(), streamOpts)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, st)
		if _, _, err := st.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "the stream goroutines to end", func() bool { return runtime.NumGoroutine() <= baseline+2 })
}
