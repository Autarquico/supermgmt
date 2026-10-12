//go:build e2e

package e2e_test

import (
	"context"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Spec docs/specs/m3-proxmox-installer.md (uninstall), ADR-0027, PLAN §9 row "Uninstall preserves
// data unless separately confirmed". The server is the tree under test, installed with its own
// `sm install server --tls direct`.

const unitFile = "/etc/systemd/system/supermgmt.service"

// installedServer is a running server of the tree under test with an administrator.
type installedServer struct {
	srv   *harness.Server
	token string
}

func startInstalledServer(t *testing.T) *installedServer {
	t.Helper()
	ctx := context.Background()
	srv := harness.StartServer(t, harness.NewNetwork(t), harness.NewCA(t), harness.ServerOptions{Mode: harness.Direct})
	srv.WaitReady(ctx)
	admin := harness.NewClient(t)
	admin.AddProfile(ctx, "ops", srv.URL, srv.CAFile)
	return &installedServer{srv: srv, token: srv.BootstrapAdmin(ctx, admin, "admin")}
}

func (s *installedServer) uninstall(args ...string) harness.Result {
	return s.srv.C.Env(context.Background(), "", map[string]string{"SUPERMGMT_NONINTERACTIVE": "1"},
		append([]string{"/root/sm", "install", "uninstall"}, args...)...)
}

func (s *installedServer) exists(path string) bool {
	return s.srv.C.Exec(context.Background(), "", "test", "-e", path).Code == 0
}

func (s *installedServer) assertSoftwareGone(t *testing.T) {
	t.Helper()
	for _, path := range []string{harness.ServerBinary, unitFile} {
		if s.exists(path) {
			t.Errorf("%s is still there after the uninstall", path)
		}
	}
	if s.srv.C.Exec(context.Background(), "", "systemctl", "is-active", "--quiet", "supermgmt").Code == 0 {
		t.Error("the service still runs after the uninstall")
	}
}

// TestM3_UninstallKeepsData
//
// Then: the default uninstall removes the software and the unit and keeps the configuration, the
// database and the backups; a later --purge-data (no software left to start from) removes them.
func TestM3_UninstallKeepsData(t *testing.T) {
	s := startInstalledServer(t)

	res := s.uninstall("--yes")
	if res.Code != 0 {
		t.Fatalf("sm install uninstall exited %d\n%s", res.Code, res.Output())
	}
	s.assertSoftwareGone(t)
	for _, path := range []string{harness.ServerConfig, harness.ServerData + "/supermgmt.db", harness.ServerData + "/secrets"} {
		if !s.exists(path) {
			t.Errorf("%s was removed by an uninstall that did not ask to purge data", path)
		}
	}
	if !strings.Contains(res.Output(), "--purge-data") {
		t.Errorf("the uninstall does not tell how to delete the data:\n%s", res.Output())
	}

	t.Run("a later --purge-data removes what the uninstall kept", func(t *testing.T) {
		purged := s.uninstall("--purge-data", "--yes")
		if purged.Code != 0 {
			t.Fatalf("sm install uninstall --purge-data exited %d\n%s", purged.Code, purged.Output())
		}
		for _, path := range []string{harness.ServerData, "/etc/supermgmt"} {
			if s.exists(path) {
				t.Errorf("%s survived --purge-data", path)
			}
		}
	})
}

// TestM3_UninstallPurgeDataRemovesIt
//
// Then: without a terminal the data is deleted only when --purge-data is accompanied by --yes
// (refused with exit 2 otherwise, nothing removed), and with it the software, the data and the
// configuration are gone.
func TestM3_UninstallPurgeDataRemovesIt(t *testing.T) {
	s := startInstalledServer(t)

	refused := s.uninstall("--purge-data")
	if refused.Code != exitInvalid {
		t.Fatalf("--purge-data without confirmation: exit %d, want %d\n%s", refused.Code, exitInvalid, refused.Output())
	}
	for _, path := range []string{harness.ServerBinary, harness.ServerData + "/supermgmt.db", harness.ServerConfig} {
		if !s.exists(path) {
			t.Fatalf("%s was removed although the purge was not confirmed", path)
		}
	}

	res := s.uninstall("--purge-data", "--yes")
	if res.Code != 0 {
		t.Fatalf("sm install uninstall --purge-data --yes exited %d\n%s", res.Code, res.Output())
	}
	s.assertSoftwareGone(t)
	for _, path := range []string{harness.ServerData, "/etc/supermgmt"} {
		if s.exists(path) {
			t.Errorf("%s survived --purge-data", path)
		}
	}
}
