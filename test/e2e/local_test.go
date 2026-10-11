//go:build e2e

package e2e_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// TestM2_LocalModeWithoutIdP
//
// Criterion S1, second half ("el modo local sigue funcionando sin IdP"; PLAN §9 row 3): a local
// daemon with no server, no TLS and no identity provider keeps working as in M1, and the Unix
// socket still refuses a bearer token (peer credentials are its only authentication).
func TestM2_LocalModeWithoutIdP(t *testing.T) {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "sm-local-") // short: Unix socket paths are limited to ~100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "d.sock")
	config := fmt.Sprintf("version: 1\ninstance:\n    mode: local\n    data_dir: %s\ndaemon:\n    socket: %s\n", filepath.Join(dir, "data"), socket)
	configFile := harness.WriteHostFile(t, dir, "config.yaml", []byte(config), 0o600)

	laptop := harness.NewClient(t)
	laptop.Start(ctx, "", "daemon", "--config", configFile)
	waitForLocalDaemon(t, ctx, laptop, configFile)

	t.Run("commands run against the local daemon", func(t *testing.T) {
		laptop.Must(ctx, "", "nodes", "list", "--config", configFile)
		laptop.Must(ctx, "", "jobs", "--config", configFile)
	})

	t.Run("the socket refuses a bearer token", func(t *testing.T) {
		hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://daemon/api/v1/me", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer smt_notatoken")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET /me with a bearer on the socket = %d, want 401", resp.StatusCode)
		}
	})
}

func waitForLocalDaemon(t *testing.T, ctx context.Context, c *harness.Client, configFile string) {
	t.Helper()
	deadline := harness.Now().Add(30 * time.Second)
	for harness.Now().Before(deadline) {
		if c.Run(ctx, "", "status", "--config", configFile).Code == 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("the local daemon did not answer within 30s")
}
