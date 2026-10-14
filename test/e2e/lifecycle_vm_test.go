//go:build e2e && hostlifecycle

package e2e_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Spec docs/specs/m6-hardening.md and ADR-0036 "Host-mutating tests": the install lifecycle on a real
// runner. These tests mutate the machine they run on, so they compile only with the hostlifecycle
// tag and start with the T18 guard (SM_E2E_VM=1, a disposable runner or the systemd e2e container,
// no installation present). One lifecycle per fresh runner:
//
//	server:       N-1 `install.sh server` from a local signed mirror -> seed -> upgrade -> backup ->
//	              restore -> uninstall (data kept) -> --purge-data      (Linux, root)
//	local-client: N-1 `install local --resident` -> seed -> upgrade -> backup -> restore -> uninstall ->
//	              --purge-data, plus `install client` and a login against a server (Linux user unit;
//	              the macOS twin is lifecycle_macos_test.go)
//
// The upgrade is first ended by the crash hook right after the hold was applied: a manual start must
// be refused then. Every step asserts health, the doctor JSON where the service allows it, and that
// the data made before survived. N-1 is the newest milestone merged on main (lifecyclePrevious).

const (
	lifeReadyTimeout = time.Minute
	lifeHoldCrashAt  = "U:stopped:applied"
	lifeDoctorFormat = 1
)

// ---- running commands on this machine ----

func lifeEnv(extra ...string) []string {
	return append(append(os.Environ(), "SUPERMGMT_NONINTERACTIVE=1", "SUPERMGMT_NO_AUTOSTART=1", "NO_COLOR=1"), extra...)
}

func lifeRun(t testing.TB, env []string, stdin, name string, args ...string) harness.Result {
	t.Helper()
	res, err := harness.Run(context.Background(), "", env, stdin, name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return res
}

func lifeMust(t testing.TB, env []string, stdin, name string, args ...string) harness.Result {
	t.Helper()
	res := lifeRun(t, env, stdin, name, args...)
	if res.Code != 0 {
		t.Fatalf("%s %s exited %d\n%s", name, strings.Join(args, " "), res.Code, res.Output())
	}
	return res
}

func lifeDecode[T any](t testing.TB, what string, res harness.Result) T {
	t.Helper()
	var out T
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("decode %s: %v\n%s", what, err, res.Output())
	}
	return out
}

func lifeExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// lifeStep runs one step of a lifecycle and stops the lifecycle at the first failed step.
func lifeStep(t *testing.T, name string, step func(t *testing.T)) {
	t.Helper()
	if !t.Run(name, step) {
		t.FailNow()
	}
}

// ---- builds: N-1 from its merge commit, N from the tree with the crash hook ----

// lifeBuild builds ./cmd/sm of srcDir for this machine as version.
func lifeBuild(t testing.TB, key, srcDir, version, tags string) string {
	t.Helper()
	return harness.BuildSM(t, "life-"+key, srcDir, runtime.GOOS, runtime.GOARCH, version, tags)
}

// lifePreviousSM is the sm of the newest merged milestone, exported with git archive.
func lifePreviousSM(t testing.TB) (string, milestone) {
	t.Helper()
	prev := lifecyclePrevious(t)
	src := harness.MilestoneSource(t, prev.name, prev.commit)
	return lifeBuild(t, "prev-"+prev.name, src, prev.version, ""), prev
}

// lifeNextSM is the tree under test as the version after every milestone, with the crash hook.
func lifeNextSM(t testing.TB) string {
	t.Helper()
	return lifeBuild(t, "next", harness.RepoRoot(), lifecycleNextVersion(), "crashpoints")
}

// ---- a local signed release mirror (no docker) ----

type lifeRelease struct {
	baseURL string
	script  string // install.sh with the throwaway trust root
	caFile  string // what curl must trust to reach the mirror
	version string
}

func lifePackSM(t testing.TB, binary string) []byte {
	t.Helper()
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "sm", Mode: 0o755, Size: int64(len(body)), ModTime: time.Unix(0, 0)}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// lifeServeRelease signs a release holding binary as version with a throwaway key (the repository's
// own testkey.sh and finalize.sh) and serves it over HTTPS on loopback.
func lifeServeRelease(t *testing.T, ca *harness.CA, binary, version string) lifeRelease {
	t.Helper()
	root := lifeScratchDir(t, "", "sm-life-release-")
	stage := filepath.Join(root, "served", version)
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	archive := lifePackSM(t, binary)
	for _, target := range []string{"linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"} {
		name := fmt.Sprintf("sm_%s_%s.tar.gz", strings.TrimPrefix(version, "v"), target)
		sbom := fmt.Sprintf(`{"spdxVersion":"SPDX-2.3","name":%q}`+"\n", target)
		for file, content := range map[string][]byte{name: archive, name + ".spdx.json": []byte(sbom)} {
			if err := os.WriteFile(filepath.Join(stage, file), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	trust := filepath.Join(root, "trust")
	repo := harness.RepoRoot()
	lifeMust(t, nil, "", filepath.Join(repo, "packaging/release/testkey.sh"), trust)
	signing := append(os.Environ(), "SM_SIGNING_KEY_FILE="+filepath.Join(trust, "key"))
	lifeMust(t, signing, "", filepath.Join(repo, "packaging/release/finalize.sh"), stage, version)

	script := filepath.Join(root, "install.sh")
	rendered := harness.RenderScript(t, filepath.Join(repo, "install.sh"), filepath.Join(trust, "allowed_signers"), "")
	if err := os.WriteFile(script, rendered, 0o755); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(caFile, ca.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return lifeRelease{baseURL: lifeServeFiles(t, ca, filepath.Join(root, "served")), script: script, caFile: caFile, version: version}
}

func lifeServeFiles(t *testing.T, ca *harness.CA, dir string) string {
	t.Helper()
	pair := ca.Issue(t, []string{"localhost"}, []string{"127.0.0.1"})
	cert, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.FileServer(http.Dir(dir)),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + listener.Addr().String()
}

// lifeScratchDir is a world-readable directory in parent ("" = the temp directory).
func lifeScratchDir(t testing.TB, parent, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func lifeFreePort(t testing.TB) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// ---- what the doctor and the API say ----

type lifeDoctorReport struct {
	FormatVersion         int  `json:"format_version"`
	OK                    bool `json:"ok"`
	DatabaseSchemaVersion *int `json:"database_schema_version"`
	Checks                []struct {
		Name, Status, Detail string
	} `json:"checks"`
}

func (r lifeDoctorReport) status(name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return ""
}

// lifeDoctor runs `<prefix...> doctor <args> --json` and returns the report; a failing doctor is a failure.
func lifeDoctor(t testing.TB, prefix []string, args ...string) lifeDoctorReport {
	t.Helper()
	argv := append(append(append([]string{}, prefix[1:]...), "doctor"), args...)
	res := lifeRun(t, lifeEnv(), "", prefix[0], append(argv, "--json")...)
	report := lifeDecode[lifeDoctorReport](t, "doctor --json", res)
	if res.Code != 0 || !report.OK {
		t.Fatalf("doctor is not healthy (exit %d)\n%s", res.Code, res.Stdout)
	}
	return report
}

// assertCurrentDoctor is the contract of the new build's offline doctor (ADR-0035).
func assertCurrentDoctor(t *testing.T, report lifeDoctorReport) {
	t.Helper()
	if report.FormatVersion != lifeDoctorFormat {
		t.Errorf("doctor format_version %d, want %d", report.FormatVersion, lifeDoctorFormat)
	}
	if report.DatabaseSchemaVersion == nil || *report.DatabaseSchemaVersion != latestSchema(t) {
		t.Errorf("doctor database_schema_version %v, want %d", report.DatabaseSchemaVersion, latestSchema(t))
	}
}

func lifeInstalledVersion(t testing.TB, binary string) string {
	t.Helper()
	v := lifeDecode[struct{ Version string }](t, "sm version --json", lifeMust(t, lifeEnv(), "", binary, "version", "--json"))
	return v.Version
}

func lifeRemoteAPI(t testing.TB, url, caFile, token string) *client.Client {
	t.Helper()
	c, err := client.NewRemote(client.Remote{URL: url, CAFile: caFile, Token: token}, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// lifeWaitHTTPS waits for the readiness endpoint of a TLS server.
func lifeWaitHTTPS(t testing.TB, ca *harness.CA, url string, why func() string) {
	t.Helper()
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12}}}
	defer hc.CloseIdleConnections()
	deadline := harness.Now().Add(lifeReadyTimeout)
	for harness.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url+"/health/ready", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := hc.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s did not become ready\n%s", url, why())
}

// lifeSeed is what an administrator made on N-1 and must find again after every later step.
type lifeSeed struct {
	session string
	issued  string
	sshFP   string
}

func lifeMakeSeed(t testing.TB, url, caFile, session string) lifeSeed {
	t.Helper()
	ctx := context.Background()
	api := lifeRemoteAPI(t, url, caFile, session)
	issued, err := api.CreateToken(ctx, wire.CreateTokenRequest{Name: "automation", ExpiresAt: harness.Now().Add(30 * 24 * time.Hour)})
	if err != nil {
		t.Fatalf("create an API token on N-1: %v", err)
	}
	key, err := api.SSHKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return lifeSeed{session: session, issued: issued.Value, sshFP: key.FingerprintSHA256}
}

func (s lifeSeed) assertIntact(t *testing.T, url, caFile string) {
	t.Helper()
	ctx := context.Background()
	for name, token := range map[string]string{"the administrator's session": s.session, "the API token": s.issued} {
		if _, err := lifeRemoteAPI(t, url, caFile, token).Me(ctx); err != nil {
			t.Errorf("%s no longer works: %v", name, err)
		}
	}
	s.assertIdentity(t, lifeRemoteAPI(t, url, caFile, s.session))
}

// assertIdentity checks the instance SSH key: the one datum a restore keeps while it kills credentials.
func (s lifeSeed) assertIdentity(t *testing.T, api *client.Client) {
	t.Helper()
	key, err := api.SSHKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if key.FingerprintSHA256 != s.sshFP {
		t.Errorf("the instance SSH key changed: %s -> %s", s.sshFP, key.FingerprintSHA256)
	}
}

// ---- mode server (Linux, root) ----

const (
	// lifeServiceReadableDir holds the certificate: the unit has a private /tmp.
	lifeServiceReadableDir = "/opt"
	lifeServerUnit         = "supermgmt"
	lifeServerUser         = "supermgmt"
)

func lifeRequireLinuxRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("the server lifecycle installs a system service: run it as root on the disposable runner")
	}
}

func lifeServerActive() bool {
	return exec.CommandContext(context.Background(), "systemctl", "is-active", "--quiet", lifeServerUnit).Run() == nil
}

func lifeServerJournal() string {
	out, _ := exec.CommandContext(context.Background(), "journalctl", "-u", lifeServerUnit, "--no-pager", "-n", "30").CombinedOutput()
	return string(out)
}

// lifeAsServiceUser runs sm as the service account, which owns the data directory.
func lifeAsServiceUser(t testing.TB, binary string, stdin string, args ...string) harness.Result {
	t.Helper()
	return lifeRun(t, lifeEnv(), stdin, "runuser", append([]string{"-u", lifeServerUser, "--", binary}, args...)...)
}

// TestLifecycleVM_Server
//
// Given a host with no installation, N-1 installed by install.sh from a signed mirror.
// Then: the upgrade holds the service while unfinished, converges to the new build with the data
// intact; an offline backup restores into a service that starts in restore hold and keeps the
// instance identity; the uninstall removes the software and keeps configuration, data and backups;
// --purge-data then removes them.
func TestLifecycleVM_Server(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the server lifecycle runs on Linux")
	}
	harness.RequireHostLifecycle(t)
	lifeRequireLinuxRoot(t)
	ctx := context.Background()

	prevBin, prev := lifePreviousSM(t)
	nextBin := lifeNextSM(t)
	ca := harness.NewCA(t)
	release := lifeServeRelease(t, ca, prevBin, prev.version)
	certDir := lifeScratchDir(t, lifeServiceReadableDir, "sm-life-tls-")
	crt, key := ca.Issue(t, []string{"localhost"}, []string{"127.0.0.1"}).WriteTo(t, certDir, "server")
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(certDir, "ca.pem")
	if err := os.WriteFile(caFile, ca.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	port := lifeFreePort(t)
	url := "https://localhost:" + port
	sm := []string{harness.ServerBinary}
	serverArgs := []string{"--config", harness.ServerConfig}
	var seed lifeSeed
	var archive string

	lifeStep(t, "install.sh installs N-1 from the signed mirror and the service becomes healthy", func(t *testing.T) {
		env := lifeEnv("SUPERMGMT_RELEASE_BASE_URL="+release.baseURL, "SUPERMGMT_VERSION="+release.version, "CURL_CA_BUNDLE="+release.caFile)
		res := lifeRun(t, env, "", "bash", release.script, "server", "--tls", "direct", "--tls-cert", crt, "--tls-key", key,
			"--public-url", url, "--listen", "127.0.0.1:"+port, "--yes")
		if res.Code != 0 {
			t.Fatalf("install.sh server exited %d\n%s", res.Code, res.Output())
		}
		lifeWaitHTTPS(t, ca, url, lifeServerJournal)
		lifeDoctor(t, sm, serverArgs...)
		if got := lifeInstalledVersion(t, harness.ServerBinary); got != prev.version {
			t.Fatalf("installed sm reports %q, want %s", got, prev.version)
		}
		code, ok := harness.BootstrapCode(res.Output())
		if !ok {
			t.Fatalf("the installer printed no bootstrap code\n%s", res.Output())
		}
		admin := harness.NewClient(t)
		admin.AddProfile(ctx, "ops", url, caFile)
		admin.Must(ctx, code+"\n", "login", "--bootstrap", "--display-name", "admin on N-1")
		seed = lifeMakeSeed(t, url, caFile, admin.StoredToken("ops"))
	})

	lifeStep(t, "a manual start is refused while the upgrade is unfinished", func(t *testing.T) {
		res := lifeRun(t, lifeEnv(crashPointEnv+"="+lifeHoldCrashAt), "", nextBin, "install", "upgrade", "--binary", nextBin, "--yes")
		if res.Code != crashExitCode {
			t.Fatalf("upgrade crashed at %s: exit %d, want %d\n%s", lifeHoldCrashAt, res.Code, crashExitCode, res.Output())
		}
		if exec.CommandContext(ctx, "systemctl", "start", lifeServerUnit).Run() == nil {
			t.Error("a manual start succeeded in the middle of the upgrade: the hold is not in place")
		}
		if lifeServerActive() {
			t.Error("the service runs in the middle of the upgrade")
		}
		time.Sleep(crashRerunDelay)
	})

	lifeStep(t, "the upgrade resumes and converges to the new build with the data intact", func(t *testing.T) {
		res := lifeRun(t, lifeEnv(), "", nextBin, "install", "upgrade", "--binary", nextBin, "--yes")
		if res.Code != 0 {
			t.Fatalf("rerun of the upgrade exited %d\n%s", res.Code, res.Output())
		}
		lifeWaitHTTPS(t, ca, url, lifeServerJournal)
		if got := lifeInstalledVersion(t, harness.ServerBinary); got != lifecycleNextVersion() {
			t.Errorf("installed sm reports %q, want %s", got, lifecycleNextVersion())
		}
		report := lifeDoctor(t, sm, serverArgs...)
		if report.FormatVersion != lifeDoctorFormat {
			t.Errorf("doctor format_version %d, want %d", report.FormatVersion, lifeDoctorFormat)
		}
		seed.assertIntact(t, url, caFile)
	})

	lifeStep(t, "an offline backup carries the latest schema", func(t *testing.T) {
		lifeMust(t, lifeEnv(), "", "systemctl", "stop", lifeServerUnit)
		assertCurrentDoctor(t, lifeDoctor(t, []string{"runuser", "-u", lifeServerUser, "--", harness.ServerBinary}, append([]string{"--offline"}, serverArgs...)...))
		res := lifeAsServiceUser(t, harness.ServerBinary, "", append([]string{"backup", "create", "--offline", "--json"}, serverArgs...)...)
		if res.Code != 0 {
			t.Fatalf("backup create --offline exited %d\n%s", res.Code, res.Output())
		}
		report := lifeDecode[struct {
			Path          string `json:"path"`
			SchemaVersion int    `json:"schema_version"`
		}](t, "backup create --offline --json", res)
		if report.SchemaVersion != latestSchema(t) {
			t.Errorf("the backup has schema %d, want %d", report.SchemaVersion, latestSchema(t))
		}
		archive = report.Path
	})

	lifeStep(t, "the restore starts in restore hold, keeps the identity and restore-complete lifts the hold", func(t *testing.T) {
		res := lifeAsServiceUser(t, harness.ServerBinary, "", append([]string{"backup", "restore", "--offline", archive, "--json"}, serverArgs...)...)
		if res.Code != 0 {
			t.Fatalf("backup restore --offline exited %d\n%s", res.Code, res.Output())
		}
		lifeMust(t, lifeEnv(), "", "systemctl", "start", lifeServerUnit)
		lifeWaitHTTPS(t, ca, url, lifeServerJournal)
		if got := lifeDoctor(t, sm, serverArgs...).status("restore_hold"); got != "warn" {
			t.Errorf("restore_hold is %q after the restore, want warn", got)
		}
		code := strings.TrimSpace(lifeMust(t, lifeEnv(), "", harness.ServerBinary, append([]string{"admin", "bootstrap-code"}, serverArgs...)...).Stdout)
		admin := harness.NewClient(t)
		admin.AddProfile(ctx, "ops", url, caFile)
		admin.Must(ctx, code+"\n", "login", "--bootstrap", "--display-name", "admin after the restore")
		seed.assertIdentity(t, lifeRemoteAPI(t, url, caFile, admin.StoredToken("ops")))
		lifeMust(t, lifeEnv(), "", harness.ServerBinary, append([]string{"admin", "restore-complete"}, serverArgs...)...)
		if got := lifeDoctor(t, sm, serverArgs...).status("restore_hold"); got != "ok" {
			t.Errorf("restore_hold is %q after restore-complete, want ok", got)
		}
	})

	lifeStep(t, "uninstall removes the software and keeps configuration, data and backups", func(t *testing.T) {
		res := lifeRun(t, lifeEnv(), "", harness.ServerBinary, "install", "uninstall", "--yes")
		if res.Code != 0 {
			t.Fatalf("uninstall exited %d\n%s", res.Code, res.Output())
		}
		for _, gone := range []string{harness.ServerBinary, "/etc/systemd/system/supermgmt.service"} {
			if lifeExists(gone) {
				t.Errorf("%s is still there after the uninstall", gone)
			}
		}
		if lifeServerActive() {
			t.Error("the service still runs after the uninstall")
		}
		for _, kept := range []string{harness.ServerConfig, harness.ServerData + "/supermgmt.db", archive} {
			if !lifeExists(kept) {
				t.Errorf("%s was removed by an uninstall that did not ask to purge data", kept)
			}
		}
		if !strings.Contains(res.Output(), "--purge-data") {
			t.Errorf("the uninstall does not tell how to delete the data:\n%s", res.Output())
		}
	})

	lifeStep(t, "--purge-data removes what the uninstall kept", func(t *testing.T) {
		res := lifeRun(t, lifeEnv(), "", nextBin, "install", "uninstall", "--purge-data", "--yes")
		if res.Code != 0 {
			t.Fatalf("uninstall --purge-data exited %d\n%s", res.Code, res.Output())
		}
		for _, path := range []string{harness.ServerData, filepath.Dir(harness.ServerConfig)} {
			if lifeExists(path) {
				t.Errorf("%s survived --purge-data", path)
			}
		}
	})
}

// ---- mode local-client ----

// lifeUserService drives the resident daemon's unit with the service manager of the OS.
type lifeUserService struct {
	t    testing.TB
	home string
}

func (s lifeUserService) darwinTarget() string {
	return "gui/" + strconv.Itoa(os.Getuid()) + "/dev.supermgmt.daemon"
}

func (s lifeUserService) plist() string {
	return filepath.Join(s.home, "Library", "LaunchAgents", "dev.supermgmt.daemon.plist")
}

func (s lifeUserService) unitFile() string {
	if runtime.GOOS == "darwin" {
		return s.plist()
	}
	return filepath.Join(s.home, ".config", "systemd", "user", "supermgmt.service")
}

func (s lifeUserService) command(action string) []string {
	if runtime.GOOS == "darwin" {
		switch action {
		case "stop":
			return []string{"launchctl", "bootout", s.darwinTarget()}
		case "start":
			return []string{"launchctl", "bootstrap", "gui/" + strconv.Itoa(os.Getuid()), s.plist()}
		default:
			return []string{"launchctl", "print", s.darwinTarget()}
		}
	}
	switch action {
	case "stop", "start":
		return []string{"systemctl", "--user", action, "supermgmt.service"}
	default:
		return []string{"systemctl", "--user", "is-active", "--quiet", "supermgmt.service"}
	}
}

func (s lifeUserService) try(action string) bool {
	argv := s.command(action)
	return exec.CommandContext(context.Background(), argv[0], argv[1:]...).Run() == nil
}

func (s lifeUserService) active() bool { return s.try("active") }

func (s lifeUserService) stop() {
	s.t.Helper()
	if !s.try("stop") {
		s.t.Fatalf("%v failed", s.command("stop"))
	}
}

func (s lifeUserService) start() {
	s.t.Helper()
	if !s.try("start") {
		s.t.Fatalf("%v failed", s.command("start"))
	}
}

// lifeHostServer is a real `sm server` of the tree under test, run unprivileged on loopback with
// direct TLS: the server a local-client user logs in to. It stands in for the e2e container
// because the macOS runners have no docker.
type lifeHostServer struct {
	url    string
	caFile string
	code   string
}

func lifeStartHostServer(t *testing.T, ca *harness.CA, nextBin string) lifeHostServer {
	t.Helper()
	dir := lifeScratchDir(t, "", "sml-")
	crt, key := ca.Issue(t, []string{"localhost"}, []string{"127.0.0.1"}).WriteTo(t, dir, "server")
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	port := lifeFreePort(t)
	url := "https://localhost:" + port
	cfg := filepath.Join(dir, "config.yaml")
	doc := fmt.Sprintf(`version: 1
instance:
    name: lifecycle-server
    mode: server
    data_dir: %s
server:
    listen: 127.0.0.1:%s
    public_url: %s
    admin_socket: %s
    tls:
        mode: direct
        cert_file: %s
        key_file: %s
`, filepath.Join(dir, "data"), port, url, filepath.Join(dir, "admin.sock"), crt, key)
	if err := os.WriteFile(cfg, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	lifeMust(t, lifeEnv(), "", nextBin, "server", "init", "--config", cfg)

	logFile := filepath.Join(dir, "server.log")
	logs, err := os.Create(logFile)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), nextBin, "server", "--config", cfg)
	cmd.Env, cmd.Stdout, cmd.Stderr = lifeEnv(), logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logs.Close()
	})
	lifeWaitHTTPS(t, ca, url, func() string { raw, _ := os.ReadFile(logFile); return string(raw) })
	code := strings.TrimSpace(lifeMust(t, lifeEnv(), "", nextBin, "admin", "bootstrap-code", "--config", cfg).Stdout)
	return lifeHostServer{url: url, caFile: caFile, code: code}
}

// lifeClientLogin installs client mode into a private home and logs in to the server with the
// installed sm: the profile it wrote is the one the login uses.
func lifeClientLogin(t *testing.T, nextBin string, srv lifeHostServer) {
	t.Helper()
	home := lifeScratchDir(t, "", "sm-life-client-")
	empty := filepath.Join(home, "empty-path") // no keychain, no browser opener
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "XDG_DATA_HOME=" + filepath.Join(home, "data"),
		"XDG_STATE_HOME=" + filepath.Join(home, "state"), "XDG_RUNTIME_DIR=" + home, "PATH=" + empty,
		"SUPERMGMT_NONINTERACTIVE=1", "SUPERMGMT_NO_AUTOSTART=1", "NO_COLOR=1",
	}
	lifeMust(t, env, "", nextBin, "install", "client", "--yes")
	installed := filepath.Join(home, ".local", "bin", "sm")
	if !lifeExists(installed) {
		t.Fatalf("install client left no sm at %s", installed)
	}
	lifeMust(t, env, "", installed, "profile", "add", "lifecycle", "--url", srv.url, "--ca-file", srv.caFile)
	lifeMust(t, env, "", installed, "profile", "use", "lifecycle")
	lifeMust(t, env, srv.code+"\n", installed, "login", "--bootstrap", "--display-name", "lifecycle client")
	key := lifeDecode[struct {
		Fingerprint string `json:"fingerprint_sha256"`
	}](t, "ssh-key show --json", lifeMust(t, env, "", installed, "--json", "ssh-key", "show"))
	if key.Fingerprint == "" {
		t.Error("the logged-in client sees no instance SSH key")
	}
}

// lifeResidentLifecycle is the local-client lifecycle on the current OS: N-1 `install local
// --resident` -> upgrade -> backup -> restore -> uninstall -> purge, then `client` against a server.
func lifeResidentLifecycle(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "linux" && os.Getenv("XDG_RUNTIME_DIR") == "" {
		t.Fatal("the resident daemon needs a systemd user session (XDG_RUNTIME_DIR is not set)")
	}
	prevBin, prev := lifePreviousSM(t)
	nextBin := lifeNextSM(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	envMap := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			envMap[k] = v
		}
	}
	paths := config.Resolve(runtime.GOOS, envMap, home)
	installed := filepath.Join(home, ".local", "bin", "sm")
	service := lifeUserService{t: t, home: home}
	env := lifeEnv()
	var seedFP, archive string

	fingerprint := func(t *testing.T) string {
		t.Helper()
		key := lifeDecode[struct {
			Fingerprint string `json:"fingerprint_sha256"`
		}](t, "ssh-key show --json", lifeMust(t, env, "", installed, "--json", "ssh-key", "show"))
		return key.Fingerprint
	}
	waitDaemon := func(t *testing.T) {
		t.Helper()
		deadline := harness.Now().Add(lifeReadyTimeout)
		for harness.Now().Before(deadline) {
			if lifeRun(t, env, "", installed, "--json", "status").Code == 0 {
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("the resident daemon does not answer\n%s", lifeRun(t, env, "", installed, "status").Output())
	}

	lifeStep(t, "N-1 installs as a resident daemon and answers", func(t *testing.T) {
		lifeMust(t, env, "", prevBin, "install", "local", "--resident", "--yes")
		if !service.active() {
			t.Fatal("the resident unit is not running after the install")
		}
		waitDaemon(t)
		if got := lifeInstalledVersion(t, installed); got != prev.version {
			t.Fatalf("installed sm reports %q, want %s", got, prev.version)
		}
		if seedFP = fingerprint(t); seedFP == "" {
			t.Fatal("the daemon reports no instance SSH key")
		}
	})

	lifeStep(t, "a manual start is refused while the upgrade is unfinished", func(t *testing.T) {
		res := lifeRun(t, lifeEnv(crashPointEnv+"="+lifeHoldCrashAt), "", nextBin, "install", "upgrade", "--binary", nextBin, "--yes")
		if res.Code != crashExitCode {
			t.Fatalf("upgrade crashed at %s: exit %d, want %d\n%s", lifeHoldCrashAt, res.Code, crashExitCode, res.Output())
		}
		if service.try("start") {
			t.Error("a manual start succeeded in the middle of the upgrade: the hold is not in place")
		}
		if service.active() {
			t.Error("the resident daemon runs in the middle of the upgrade")
		}
		time.Sleep(crashRerunDelay)
	})

	lifeStep(t, "the upgrade resumes and the daemon runs the new build with its identity", func(t *testing.T) {
		res := lifeRun(t, env, "", nextBin, "install", "upgrade", "--binary", nextBin, "--yes")
		if res.Code != 0 {
			t.Fatalf("rerun of the upgrade exited %d\n%s", res.Code, res.Output())
		}
		waitDaemon(t)
		if got := lifeInstalledVersion(t, installed); got != lifecycleNextVersion() {
			t.Errorf("installed sm reports %q, want %s", got, lifecycleNextVersion())
		}
		if got := fingerprint(t); got != seedFP {
			t.Errorf("the instance SSH key changed: %s -> %s", seedFP, got)
		}
	})

	lifeStep(t, "an offline backup carries the latest schema", func(t *testing.T) {
		service.stop()
		assertCurrentDoctor(t, lifeDoctor(t, []string{installed}, "--offline"))
		res := lifeMust(t, env, "", installed, "backup", "create", "--offline", "--json")
		report := lifeDecode[struct {
			Path          string `json:"path"`
			SchemaVersion int    `json:"schema_version"`
		}](t, "backup create --offline --json", res)
		if report.SchemaVersion != latestSchema(t) {
			t.Errorf("the backup has schema %d, want %d", report.SchemaVersion, latestSchema(t))
		}
		archive = report.Path
	})

	lifeStep(t, "the restore brings the daemon back with its identity", func(t *testing.T) {
		lifeMust(t, env, "", installed, "backup", "restore", "--offline", archive, "--json")
		service.start()
		waitDaemon(t)
		if got := fingerprint(t); got != seedFP {
			t.Errorf("the instance SSH key changed by the restore: %s -> %s", seedFP, got)
		}
	})

	lifeStep(t, "a client logs in to a server", func(t *testing.T) {
		lifeClientLogin(t, nextBin, lifeStartHostServer(t, harness.NewCA(t), nextBin))
	})

	lifeStep(t, "uninstall removes the software and keeps configuration, data and backups", func(t *testing.T) {
		res := lifeRun(t, env, "", installed, "install", "uninstall", "--yes")
		if res.Code != 0 {
			t.Fatalf("uninstall exited %d\n%s", res.Code, res.Output())
		}
		for _, gone := range []string{installed, service.unitFile()} {
			if lifeExists(gone) {
				t.Errorf("%s is still there after the uninstall", gone)
			}
		}
		if service.active() {
			t.Error("the resident daemon still runs after the uninstall")
		}
		for _, kept := range []string{paths.Config, paths.DB, archive} {
			if !lifeExists(kept) {
				t.Errorf("%s was removed by an uninstall that did not ask to purge data", kept)
			}
		}
	})

	lifeStep(t, "--purge-data removes what the uninstall kept", func(t *testing.T) {
		res := lifeRun(t, env, "", nextBin, "install", "uninstall", "--purge-data", "--yes")
		if res.Code != 0 {
			t.Fatalf("uninstall --purge-data exited %d\n%s", res.Code, res.Output())
		}
		for _, path := range []string{paths.Config, paths.DB, archive} {
			if lifeExists(path) {
				t.Errorf("%s survived --purge-data", path)
			}
		}
	})
}

// TestLifecycleVM_LocalClient
//
// Given a Linux host with a systemd user session and no installation.
// Then: the resident daemon (systemd user unit) goes through install, held upgrade, backup, restore,
// uninstall and purge with its identity intact, and a client installed beside it logs in to a server.
func TestLifecycleVM_LocalClient(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the macOS twin is TestLifecycleMacOS_LocalClient")
	}
	harness.RequireHostLifecycle(t)
	lifeResidentLifecycle(t)
}
