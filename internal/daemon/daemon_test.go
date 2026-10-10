package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

// instance is a data dir with a loaded configuration and a short socket path.
type instance struct {
	t      *testing.T
	root   string
	cfg    *config.Config
	socket string
}

func newInstance(t *testing.T, extra string) *instance {
	t.Helper()
	root, err := os.MkdirTemp("", "smd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	file := filepath.Join(root, "config.yaml")
	yaml := "version: 1\ninstance:\n  mode: local\n  data_dir: " + filepath.Join(root, "data") + "\n" + extra
	if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := config.Load(file, []string{"HOME=" + root})
	if err != nil {
		t.Fatal(err)
	}
	return &instance{t: t, root: root, cfg: res.Config, socket: filepath.Join(root, "run", "s")}
}

// running is a daemon started in this process.
type running struct {
	stop context.CancelFunc
	done chan error
}

func (i *instance) start(opts ...func(*Options)) *running {
	i.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{})
	o := Options{Config: i.cfg, Socket: i.socket, OnListening: func(string) { close(listening) }, IdleCheck: 10 * time.Millisecond}
	for _, f := range opts {
		f(&o)
	}
	r := &running{stop: cancel, done: make(chan error, 1)}
	go func() { r.done <- Run(ctx, o) }()
	select {
	case <-listening:
	case err := <-r.done:
		cancel()
		r.done <- err
		return r
	case <-time.After(waitLimit):
		failWithGoroutines(i.t, "the daemon did not start")
	}
	i.t.Cleanup(func() {
		cancel()
		_ = r.wait(i.t)
	})
	return r
}

func (r *running) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(waitLimit):
		failWithGoroutines(t, "the daemon did not exit")
		return nil
	}
}

// waitLimit bounds every wait on a daemon; past it the test fails with the
// stacks of all goroutines, which is what a hang needs to be diagnosed.
const waitLimit = 30 * time.Second

func failWithGoroutines(t *testing.T, what string) {
	t.Helper()
	var dump strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&dump, 1)
	t.Fatalf("%s within %s\n%s", what, waitLimit, dump.String())
}

func (i *instance) client() *client.Client { return client.New(client.Options{Socket: i.socket}) }

func TestTheDaemonServesTheLocalUserAsAdminAndCleansUpOnShutdown(t *testing.T) {
	i := newInstance(t, "")
	r := i.start()
	me, err := i.client().Me(context.Background())
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if want := "local:" + strconv.Itoa(os.Getuid()); me.DisplayName != want || len(me.Roles) != 1 || me.Roles[0] != "admin" || me.Credential != domain.CredentialLocalSocket {
		t.Errorf("me = %+v, want %s as admin over local_socket", me, want)
	}
	key, err := i.client().SSHKey(context.Background())
	if err != nil || !strings.HasPrefix(key.AuthorizedKey, "ssh-ed25519 ") {
		t.Errorf("ssh key = %+v, %v", key, err)
	}
	info, err := os.Stat(i.socket)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("socket: %v, %v; want mode 0600", info, err)
	}
	r.stop()
	if err := r.wait(t); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	if _, err := os.Lstat(i.socket); !os.IsNotExist(err) {
		t.Errorf("the socket survived shutdown: %v", err)
	}
}

func TestTheLocalIdentityIsCreatedOnceAcrossRestarts(t *testing.T) {
	i := newInstance(t, "")
	first := i.start()
	first.stop()
	_ = first.wait(t)
	second := i.start()
	defer second.stop()
	if _, err := i.client().Me(context.Background()); err != nil {
		t.Fatalf("Me after restart: %v", err)
	}
}

func TestASecondDaemonOnTheSameDatabaseExitsNamingThePID(t *testing.T) {
	i := newInstance(t, "")
	i.start()
	second := *i
	second.socket = filepath.Join(i.root, "other", "s")
	err := runOnce(&second)
	var held *database.LockHeldError
	if !errors.As(err, &held) || held.PID != os.Getpid() {
		t.Fatalf("err = %v, want the database lock held by PID %d", err, os.Getpid())
	}
}

func TestASymlinkedAliasOfTheDatabaseDirectoryIsTheSameDatabase(t *testing.T) {
	i := newInstance(t, "")
	i.start()
	alias := filepath.Join(i.root, "alias")
	if err := os.Symlink(filepath.Join(i.root, "data"), alias); err != nil {
		t.Fatal(err)
	}
	second := *i
	cfg := *i.cfg
	cfg.Storage.SQLite.Path = filepath.Join(alias, "supermgmt.db")
	second.cfg = &cfg
	second.socket = filepath.Join(i.root, "other", "s")
	var held *database.LockHeldError
	if err := runOnce(&second); !errors.As(err, &held) {
		t.Fatalf("err = %v, want the database lock held", err)
	}
}

func TestTwoDatabasesOnOneSocketAreRefusedAsSocketInUse(t *testing.T) {
	i := newInstance(t, "")
	i.start()
	second := *i
	cfg := *i.cfg
	cfg.Storage.SQLite.Path = filepath.Join(i.root, "elsewhere", "supermgmt.db")
	second.cfg = &cfg
	err := runOnce(&second)
	var inUse *SocketInUseError
	if !errors.As(err, &inUse) || inUse.PID != os.Getpid() {
		t.Fatalf("err = %v, want socket in use by PID %d", err, os.Getpid())
	}
	if _, err := i.client().Me(context.Background()); err != nil {
		t.Errorf("the first daemon stopped answering: %v", err)
	}
}

// runOnce runs a daemon that is expected to fail at startup.
func runOnce(i *instance) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return Run(ctx, Options{Config: i.cfg, Socket: i.socket})
}

func TestAStaleSocketIsUnlinkedUnderTheLock(t *testing.T) {
	i := newInstance(t, "")
	if err := os.MkdirAll(filepath.Dir(i.socket), 0o700); err != nil {
		t.Fatal(err)
	}
	stale, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", i.socket)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close() // leaves the file behind, as a killed daemon does
	i.start()
	if _, err := i.client().Me(context.Background()); err != nil {
		t.Fatalf("Me over a replaced stale socket: %v", err)
	}
}

func TestANonSocketAtTheSocketPathIsNeverRemoved(t *testing.T) {
	i := newInstance(t, "")
	if err := os.MkdirAll(filepath.Dir(i.socket), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(i.socket, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runOnce(i); err == nil {
		t.Fatal("the daemon started over a regular file")
	}
	if data, _ := os.ReadFile(i.socket); string(data) != "precious" {
		t.Error("the file at the socket path was touched")
	}
}

func TestUnsafeSocketDirectoriesAreRefused(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"mode 0755": func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, dir string) {
			target := t.TempDir()
			if err := os.Chmod(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			i := newInstance(t, "")
			setup(t, filepath.Dir(i.socket))
			var unsafe *UnsafeSocketDirError
			if err := runOnce(i); !errors.As(err, &unsafe) {
				t.Fatalf("err = %v, want an unsafe socket directory", err)
			}
		})
	}
}

func TestADirectoryOwnedBySomeoneElseIsRefused(t *testing.T) {
	dir := t.TempDir()
	_, err := PrepareSocketDir(filepath.Join(dir, "x", "s"), os.Getuid()+1)
	var unsafe *UnsafeSocketDirError
	if !errors.As(err, &unsafe) {
		t.Fatalf("err = %v, want an unsafe socket directory", err)
	}
}

func TestASocketPathOverTheSunPathLimitIsAnExplicitError(t *testing.T) {
	i := newInstance(t, "")
	i.socket = filepath.Join(i.root, strings.Repeat("d", 120), "s")
	err := runOnce(i)
	if err == nil || !strings.Contains(err.Error(), "daemon.socket") {
		t.Fatalf("err = %v, want an explicit sun_path error", err)
	}
}

func TestBothLockFilesRecordThePID(t *testing.T) {
	i := newInstance(t, "")
	i.start()
	for _, lock := range []string{i.cfg.Storage.SQLite.Path + ".lock", i.socket + ".lock"} {
		data, err := os.ReadFile(lock)
		if err != nil || strings.TrimSpace(string(data)) != strconv.Itoa(os.Getpid()) {
			t.Errorf("%s = %q, %v; want the PID", lock, data, err)
		}
	}
}

func TestAFailedPeerLookupRefusesTheClient(t *testing.T) {
	i := newInstance(t, "")
	i.start(func(o *Options) {
		o.Peer = func(*net.UnixConn) (uint32, error) { return 0, errors.New("injected") }
	})
	if _, err := i.client().Me(context.Background()); err == nil {
		t.Fatal("the daemon served a connection whose peer it could not identify")
	}
}

func TestAnIdleDaemonExitsAfterIdleExit(t *testing.T) {
	i := newInstance(t, "daemon:\n  idle_exit: 150ms\n")
	r := i.start()
	if err := r.wait(t); err != nil {
		t.Errorf("idle exit: %v", err)
	}
}

func TestAPresentClientKeepsTheDaemonAlive(t *testing.T) {
	i := newInstance(t, "daemon:\n  idle_exit: 150ms\n")
	r := i.start()
	ctx, cancel := context.WithCancel(context.Background())
	held := make(chan struct{})
	go func() { defer close(held); _ = i.client().HoldPresence(ctx) }()
	select {
	case err := <-r.done:
		t.Fatalf("the daemon exited with a client present: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	cancel()
	<-held
	if err := r.wait(t); err != nil {
		t.Errorf("exit after the client left: %v", err)
	}
}

func TestStartingAndImmediatelyStoppingNeverHangs(t *testing.T) {
	i := newInstance(t, "")
	for n := range 50 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, Options{Config: i.cfg, Socket: i.socket, OnListening: func(string) { cancel() }})
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("round %d: %v", n, err)
			}
		case <-time.After(waitLimit):
			failWithGoroutines(t, "a daemon stopped right after it started did not exit")
		}
		cancel()
	}
}

func shortTemp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "smd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestASocketDirectoryUnderAWorldWritableParentIsRefusedUnlessSticky(t *testing.T) {
	root := shortTemp(t)
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	var unsafe *UnsafeSocketDirError
	if _, err := PrepareSocketDir(filepath.Join(root, "run", "s"), os.Getuid()); !errors.As(err, &unsafe) {
		t.Fatalf("err = %v, want an unsafe parent", err)
	}
	if err := os.Chmod(root, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	dir, err := PrepareSocketDir(filepath.Join(root, "run", "s"), os.Getuid())
	if err != nil {
		t.Fatalf("a sticky parent (like /tmp) must be accepted: %v", err)
	}
	_ = dir.Close()
}

func TestAGroupWritableParentIsRefused(t *testing.T) {
	root := shortTemp(t)
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	var unsafe *UnsafeSocketDirError
	if _, err := PrepareSocketDir(filepath.Join(root, "run", "s"), os.Getuid()); !errors.As(err, &unsafe) {
		t.Fatalf("err = %v, want an unsafe parent", err)
	}
}

func TestASocketDirectoryReplacedAfterTheCheckIsDetected(t *testing.T) {
	root := shortTemp(t)
	socket := filepath.Join(root, "run", "s")
	dir, err := PrepareSocketDir(socket, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Recheck(); err != nil {
		t.Fatalf("unchanged directory: %v", err)
	}
	if err := os.Rename(filepath.Dir(socket), filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Dir(socket), 0o700); err != nil {
		t.Fatal(err)
	}
	var unsafe *UnsafeSocketDirError
	if err := dir.Recheck(); !errors.As(err, &unsafe) {
		t.Fatalf("err = %v, want the replacement detected", err)
	}
}
