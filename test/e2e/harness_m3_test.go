//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// The M3 upgrade tests install the previous release (the M2 merge commit, built as a real
// semantic version because the installer orders versions and refuses unorderable ones) and
// upgrade it to the tree under test.
const (
	prevCommit  = "e6d5577"
	prevVersion = "v0.2.0"
	nextVersion = "v0.3.0"

	versionPackage = "github.com/autarquico/supermgmt/internal/version"
	nextBinary     = "/opt/sm-next"
	wrapperBinary  = "/opt/sm-wrap"
	faultDir       = "/opt/sm-fault"
	// serverMarker is where a service started by the wrapper can write (the unit is read-only elsewhere).
	serverMarker = harness.ServerData + "/fault-at-server"
	prevBinary   = "/opt/sm-prev"
)

var (
	m3Mu     sync.Mutex
	m3Builds = map[string]*m3Build{}
)

type m3Build struct {
	once sync.Once
	path string
	err  error
}

func m3Once(key string, build func() (string, error)) (string, error) {
	m3Mu.Lock()
	b, ok := m3Builds[key]
	if !ok {
		b = &m3Build{}
		m3Builds[key] = b
	}
	m3Mu.Unlock()
	b.once.Do(func() { b.path, b.err = build() })
	return b.path, b.err
}

func buildVersioned(srcDir, out, goarch, version string) (string, error) {
	env := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	res, err := harness.Run(context.Background(), srcDir, env, "", "go", "build", "-trimpath",
		"-ldflags", "-X "+versionPackage+".Version="+version, "-o", out, "./cmd/sm")
	if e := commandFailure("go build "+out, res, err); e != nil {
		return "", e
	}
	return out, nil
}

func commandFailure(what string, res harness.Result, err error) error {
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w\n%s", what, err, res.Output())
	case res.Code != 0:
		return fmt.Errorf("%s: exit %d\n%s", what, res.Code, res.Output())
	}
	return nil
}

// previousSM is the `sm` of M2 (commit prevCommit, exported with git archive so the working tree
// is untouched) built as prevVersion for the containers.
func previousSM(t testing.TB) string {
	t.Helper()
	arch := harness.DockerArch(t)
	path, err := m3Once("prev", func() (string, error) {
		src := filepath.Join(harness.WorkDir(), "prev-src")
		if err := os.MkdirAll(src, 0o755); err != nil {
			return "", err
		}
		tarball := filepath.Join(harness.WorkDir(), "prev-src.tar")
		ctx := context.Background()
		res, err := harness.Run(ctx, harness.RepoRoot(), nil, "", "git", "archive", "--format=tar", "--output", tarball, prevCommit)
		if e := commandFailure("git archive "+prevCommit+" (CI needs fetch-depth: 0)", res, err); e != nil {
			return "", e
		}
		res, err = harness.Run(ctx, "", nil, "", "tar", "-xf", tarball, "-C", src)
		if e := commandFailure("extract "+prevCommit, res, err); e != nil {
			return "", e
		}
		return buildVersioned(src, filepath.Join(harness.WorkDir(), "sm-prev-"+arch), arch, prevVersion)
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// nextSM is the tree under test, built as nextVersion for the containers.
func nextSM(t testing.TB) string {
	t.Helper()
	arch := harness.DockerArch(t)
	path, err := m3Once("next", func() (string, error) {
		return buildVersioned(harness.RepoRoot(), filepath.Join(harness.WorkDir(), "sm-next-"+arch), arch, nextVersion)
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// faultWrapper is a stand-in for the new release: a script that hands every command to the real
// build in nextBinary, except where the test asks for a fault by writing its name to faultDir/mode.
// It is what the installer stages, hashes, runs for the backup and starts as the service, so each
// failure boundary of the upgrade is reached through the same code paths a broken release would hit.
// (The crashpoints hooks of the installer are not reachable from a process: PLAN note in the report.)
const faultWrapper = `#!/bin/sh
real=` + nextBinary + `
mode=$(cat ` + faultDir + `/mode 2>/dev/null)
if [ "$1" = "${mode%%:*}" ]; then case "$mode" in
backup:fail)
	echo "injected: the backup cannot be written" >&2
	exit 1
	;;
backup:hold)
	touch ` + faultDir + `/at-backup
	while [ -f ` + faultDir + `/hold ]; do sleep 1; done
	;;
server:never-ready)
	exit 1
	;;
server:hang)
	touch ` + serverMarker + `
	exec sleep 100000
	;;
server:migrate-then-unreachable)
	# the real server migrates the schema, but listens where the readiness probe does not look
	sed 's#0\.0\.0\.0:8443#127.0.0.1:9999#' /etc/supermgmt/config.yaml > /var/lib/supermgmt/fault-config.yaml
	exec "$real" server --config /var/lib/supermgmt/fault-config.yaml
	;;
esac; fi
exec "$real" "$@"
`

// upgradeHost is a clean Debian systemd host running the previous release as a server, with data.
type upgradeHost struct {
	t      *testing.T
	srv    *harness.Server
	admin  *harness.Client
	token  string // the administrator's session
	issued string // an API token created before the upgrade
	sshFP  string // the instance SSH key fingerprint
}

func newPreviousServer(t *testing.T) *upgradeHost {
	t.Helper()
	ctx := context.Background()
	srv := harness.NewServerHost(t, harness.NewNetwork(t), harness.NewCA(t), harness.ServerOptions{Mode: harness.Direct})
	c := srv.C
	c.CopyRoot(ctx, previousSM(t), prevBinary)
	c.MustExec(ctx, "chmod", "0755", prevBinary)
	res := c.Env(ctx, "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, prevBinary, "install", "server",
		"--tls", "direct", "--tls-cert", "/opt/tls/server.crt", "--tls-key", "/opt/tls/server.key",
		"--public-url", srv.URL, "--listen", "0.0.0.0:8443", "--yes")
	if res.Code != 0 {
		t.Fatalf("%s install server exited %d\n%s", prevVersion, res.Code, res.Output())
	}
	srv.WaitReady(ctx)

	h := &upgradeHost{t: t, srv: srv, admin: harness.NewClient(t)}
	h.admin.AddProfile(ctx, "ops", srv.URL, srv.CAFile)
	h.token = srv.BootstrapAdmin(ctx, h.admin, "admin before the upgrade")
	api := srv.Typed(h.token)
	issued, err := api.CreateToken(ctx, wire.CreateTokenRequest{Name: "automation", ExpiresAt: harness.Now().Add(30 * 24 * time.Hour)})
	if err != nil {
		t.Fatalf("create an API token on %s: %v", prevVersion, err)
	}
	h.issued = issued.Value
	key, err := api.SSHKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h.sshFP = key.FingerprintSHA256
	if got := h.installedVersion(ctx); got != prevVersion {
		t.Fatalf("the installed server reports %q, want %s", got, prevVersion)
	}
	return h
}

func (h *upgradeHost) ctx() context.Context { return context.Background() }

// stageNext puts the real new build on the host: at nextBinary, and the fault wrapper at wrapperBinary.
func (h *upgradeHost) stageNext() {
	h.t.Helper()
	c := h.srv.C
	c.CopyRoot(h.ctx(), nextSM(h.t), nextBinary)
	c.MustExec(h.ctx(), "chmod", "0755", nextBinary)
	c.MustExec(h.ctx(), "install", "-d", "-m", "0777", faultDir)
	c.WriteFile(h.ctx(), wrapperBinary, []byte(faultWrapper), "0755")
}

// setFault selects the wrapper's behaviour ("" = none) and clears the markers it leaves.
func (h *upgradeHost) setFault(mode string) {
	h.t.Helper()
	h.srv.C.MustExec(h.ctx(), "sh", "-c", fmt.Sprintf("rm -f %[1]s/at-backup %[3]s; printf %%s '%[2]s' > %[1]s/mode; chmod 0666 %[1]s/mode", faultDir, mode, serverMarker))
}

// setHold keeps the wrapper's backup:hold fault waiting (true) or lets it go on (false).
func (h *upgradeHost) setHold(on bool) {
	h.t.Helper()
	cmd := "rm -f " + faultDir + "/hold"
	if on {
		cmd = "touch " + faultDir + "/hold && chmod 0666 " + faultDir + "/hold"
	}
	h.srv.C.MustExec(h.ctx(), "sh", "-c", cmd)
}

// startUpgrade runs the upgrade in the background; the result arrives when the installer ends.
func (h *upgradeHost) startUpgrade(binary string) <-chan harness.Result {
	h.t.Helper()
	args := append([]string{"exec", "--env", "SUPERMGMT_NONINTERACTIVE=1", h.srv.C.Name}, upgradeArgs(binary)...)
	done := make(chan harness.Result, 1)
	go func() {
		res, _ := harness.Docker(context.Background(), "", args...)
		done <- res
	}()
	return done
}

// killInstaller ends the running `sm install upgrade` (and anything it spawned) the way a power cut would.
func (h *upgradeHost) killInstaller(done <-chan harness.Result) {
	h.t.Helper()
	h.srv.C.Exec(h.ctx(), "", "pkill", "-9", "-f", "install upgrade")
	h.srv.C.Exec(h.ctx(), "", "pkill", "-9", "-f", harness.ServerBinary+".new") // the staged build the backup runs
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		h.t.Fatal("the killed installer did not exit")
	}
}

// upgradeArgs is `sm install upgrade`, run by the real new build, installing binary.
func upgradeArgs(binary string) []string {
	return []string{nextBinary, "install", "upgrade", "--binary", binary, "--yes"}
}

func (h *upgradeHost) upgrade(binary string) harness.Result {
	h.t.Helper()
	return h.srv.C.Env(h.ctx(), "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"}, upgradeArgs(binary)...)
}

func (h *upgradeHost) installedVersion(ctx context.Context) string {
	h.t.Helper()
	out := h.srv.C.MustExec(ctx, harness.ServerBinary, "version", "--json")
	var v struct{ Version string }
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		h.t.Fatalf("decode sm version: %v\n%s", err, out)
	}
	return v.Version
}

var schemaDetail = regexp.MustCompile(`(?:^version |schema version )(\d+)`)

// schema is the schema version of the database as the offline doctor of bin reports it. The
// offline doctor needs the database lock, so a running service is stopped for the reading and
// started again afterwards.
func (h *upgradeHost) schema(bin string) int {
	h.t.Helper()
	if h.serviceActive() {
		h.srv.C.MustExec(h.ctx(), "systemctl", "stop", "supermgmt")
		defer func() {
			h.srv.C.MustExec(h.ctx(), "systemctl", "start", "supermgmt")
			h.srv.WaitReady(h.ctx())
		}()
	}
	res := h.srv.C.Exec(h.ctx(), "", "runuser", "-u", "supermgmt", "--", bin, "doctor", "--offline", "--json", "--config", harness.ServerConfig)
	var report struct {
		Checks []struct{ Name, Status, Detail string } `json:"checks"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &report); err != nil {
		h.t.Fatalf("%s doctor --offline gave no report: %v\n%s", bin, err, res.Output())
	}
	for _, c := range report.Checks {
		if c.Name != "schema" {
			continue
		}
		m := schemaDetail.FindStringSubmatch(c.Detail)
		if m == nil {
			h.t.Fatalf("schema check says %q", c.Detail)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	h.t.Fatalf("%s doctor reports no schema check:\n%s", bin, res.Stdout)
	return 0
}

// assertDataIntact checks the sessions, the API token and the instance identity made before the upgrade.
func (h *upgradeHost) assertDataIntact(t *testing.T) {
	t.Helper()
	for name, token := range map[string]string{"the administrator's session": h.token, "the API token": h.issued} {
		if _, err := h.srv.Typed(token).Me(h.ctx()); err != nil {
			t.Errorf("%s no longer works: %v", name, err)
		}
	}
	key, err := h.srv.Typed(h.token).SSHKey(h.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if key.FingerprintSHA256 != h.sshFP {
		t.Errorf("the instance SSH key changed: %s -> %s", h.sshFP, key.FingerprintSHA256)
	}
}

func (h *upgradeHost) serviceActive() bool {
	return h.srv.C.Exec(h.ctx(), "", "systemctl", "is-active", "--quiet", "supermgmt").Code == 0
}

func (h *upgradeHost) fileExists(path string) bool {
	return h.srv.C.Exec(h.ctx(), "", "test", "-e", path).Code == 0
}

func (h *upgradeHost) sha(path string) string {
	h.t.Helper()
	return strings.Fields(h.srv.C.MustExec(h.ctx(), "sha256sum", path))[0]
}

var archiveLine = regexp.MustCompile(`pre-upgrade backup: (\S+) \(schema (\d+)\)`)

// preUpgradeArchive reads the archive path and its schema from the installer's output.
func preUpgradeArchive(t *testing.T, output string) (path string, schema int) {
	t.Helper()
	m := archiveLine.FindStringSubmatch(output)
	if m == nil {
		t.Fatalf("the installer did not report a pre-upgrade backup:\n%s", output)
	}
	schema, _ = strconv.Atoi(m[2])
	return m[1], schema
}

// waitFor polls cond until it holds or the timeout passes.
func (h *upgradeHost) waitFor(what string, timeout time.Duration, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %s\n%s", what, h.srv.C.Exec(h.ctx(), "", "journalctl", "-u", "supermgmt", "--no-pager", "-n", "20").Output())
}

// upgradePhase is the phase in upgrade.json ("" when there is no state file).
func (h *upgradeHost) upgradePhase() string {
	res := h.srv.C.Exec(h.ctx(), "", "cat", harness.ServerData+"/upgrade.json")
	if res.Code != 0 {
		return ""
	}
	var st struct{ Phase string }
	_ = json.Unmarshal([]byte(res.Stdout), &st)
	return st.Phase
}
