package cli

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
)

// realServerBox is a real server (no OIDC) behind a TLS front, and a user
// whose profile points at it.
type realServerBox struct {
	*remoteBox
	serverEnv  []string
	serverFile string
}

func newRealServerBox(t *testing.T) *realServerBox {
	t.Helper()
	file, root := serverConfig(t)
	serverEnv := []string{"HOME=" + root}
	loaded, err := config.Load(file, serverEnv)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serving := make(chan daemon.Endpoints, 1)
	done := make(chan error, 1)
	go func() {
		done <- daemon.RunServer(ctx, daemon.Options{Config: loaded.Config, ConfigFile: file, OnServing: func(ep daemon.Endpoints) { serving <- ep }})
	}()
	t.Cleanup(func() {
		cancel()
		t.Logf("daemon stopped: %v", <-done)
	})
	var endpoints daemon.Endpoints
	select {
	case endpoints = <-serving:
	case err := <-done:
		t.Fatalf("the server stopped: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not start")
	}

	front := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: endpoints.HTTP.String()}))
	t.Cleanup(front.Close)

	dir := t.TempDir()
	box := &remoteBox{
		t: t, dir: dir, srv: front, caFile: filepath.Join(dir, "ca.pem"),
		env: []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "xdg"), envNoAutostart + "=1", "USER=tester"},
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}
	if err := os.WriteFile(box.caFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	box.useProfile()
	return &realServerBox{remoteBox: box, serverEnv: serverEnv, serverFile: file}
}

func (b *realServerBox) bootstrapCode() string {
	b.t.Helper()
	r := runServerCmds(b.serverEnv, "admin", "bootstrap-code", "--config", b.serverFile)
	if r.code != 0 {
		b.t.Fatalf("bootstrap-code: exit %d, stderr %q", r.code, r.stderr)
	}
	return strings.TrimSpace(r.stdout)
}

func TestLoginBootstrapCreatesTheAdministratorOnARealServerWithoutOIDC(t *testing.T) {
	b := newRealServerBox(t)

	r := b.runLogin(loginDeps{sleep: sleepContext}, b.bootstrapCode()+"\n", "--bootstrap", "--display-name", "Root")

	if r.code != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	if b.storedToken() == "" {
		t.Error("no credential was stored")
	}
}

func TestLoginBootstrapWithoutOIDCNeedsADisplayNameWhenNotInteractive(t *testing.T) {
	b := newRealServerBox(t)

	r := b.runLogin(loginDeps{sleep: sleepContext}, b.bootstrapCode()+"\n", "--bootstrap")

	if r.code != exitUsage || !strings.Contains(r.stderr, "--display-name") {
		t.Errorf("exit %d, stderr %q; want a usage error naming --display-name", r.code, r.stderr)
	}
	if b.storedToken() != "" {
		t.Error("a credential was stored without a name")
	}
}

func TestWithAnAdminOnlyARecoveryCodeIsIssuedAndItLogsIn(t *testing.T) {
	b := newRealServerBox(t)
	if r := b.runLogin(loginDeps{sleep: sleepContext}, b.bootstrapCode()+"\n", "--bootstrap", "--display-name", "Root"); r.code != 0 {
		t.Fatalf("first login: exit %d, stderr %q", r.code, r.stderr)
	}

	refused := runServerCmds(b.serverEnv, "admin", "bootstrap-code", "--config", b.serverFile)
	recovery := runServerCmds(b.serverEnv, "admin", "bootstrap-code", "--recover", "--config", b.serverFile)

	if refused.code == 0 {
		t.Errorf("a plain code was issued with an admin present: %q", refused.stdout)
	}
	code := strings.TrimSpace(recovery.stdout)
	if recovery.code != 0 || !strings.HasPrefix(code, "smr_") {
		t.Fatalf("--recover: exit %d, stdout %q, stderr %q", recovery.code, recovery.stdout, recovery.stderr)
	}
	if r := b.runLogin(loginDeps{sleep: sleepContext}, code+"\n", "--bootstrap", "--display-name", "Recovered"); r.code != 0 {
		t.Errorf("login with the recovery code: exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestLoginBootstrapWithoutOIDCKeepsTheAPITokenNotTheShortSession(t *testing.T) {
	b := newRealServerBox(t)

	r := b.runLogin(loginDeps{sleep: sleepContext}, b.bootstrapCode()+"\n", "--bootstrap", "--display-name", "Root", "--json")

	if r.code != 0 {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	if stored := b.storedToken(); !strings.HasPrefix(stored, "smt_") {
		t.Errorf("stored a %.4q credential; want the API token (smt_), which outlives the session", stored)
	}
	var out loginOutcome
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil || out.ExpiresAt == nil {
		t.Fatalf("login output %q: %v", r.stdout, err)
	}
	if left := time.Until(*out.ExpiresAt); left < 30*24*time.Hour {
		t.Errorf("the stored credential expires in %s; want the API token's lifetime", left)
	}
}

func TestLoginBootstrapIgnoresAStoredCredentialTheServerNoLongerAccepts(t *testing.T) {
	b := newRealServerBox(t)
	b.signIn("sms_" + strings.Repeat("A", 43))

	r := b.runLogin(loginDeps{sleep: sleepContext}, b.bootstrapCode()+"\n", "--bootstrap", "--display-name", "Root")

	if r.code != 0 {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	if stored := b.storedToken(); !strings.HasPrefix(stored, "smt_") {
		t.Errorf("stored %.4q; want the new API token in place of the refused credential", stored)
	}
}
