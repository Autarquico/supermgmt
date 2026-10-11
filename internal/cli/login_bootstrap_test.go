package cli

import (
	"context"
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
		<-done
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
