package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
)

// recoveryServer is a real server-mode daemon without OIDC: its admin socket
// and its HTTP API, each reached the way `sm` reaches them.
type recoveryServer struct {
	t     *testing.T
	admin *http.Client
	api   string
}

func newRecoveryServer(t *testing.T) *recoveryServer {
	t.Helper()
	root, err := os.MkdirTemp("", "smr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	file := filepath.Join(root, "config.yaml")
	body := "version: 1\ninstance:\n  mode: server\n  data_dir: " + filepath.Join(root, "data") + "\n" +
		"server:\n  listen: 127.0.0.1:0\n  admin_socket: " + filepath.Join(root, "run", "admin.sock") + "\n  trusted_proxies: [10.0.0.0/8]\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(file, []string{"HOME=" + root})
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
	var ep daemon.Endpoints
	select {
	case ep = <-serving:
	case err := <-done:
		t.Fatalf("the server stopped: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not start")
	}

	admin := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", ep.Admin)
		},
	}}
	t.Cleanup(admin.CloseIdleConnections)
	return &recoveryServer{t: t, admin: admin, api: "http://" + ep.HTTP.String()}
}

func (s *recoveryServer) do(client *http.Client, method, url, token, body string) (int, []byte) {
	s.t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(s.t.Context(), method, url, reader)
	if err != nil {
		s.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set(wire.HeaderAuthorization, "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	return resp.StatusCode, payload
}

// issue asks the admin socket for a code; body is the request body ("" for a plain code).
func (s *recoveryServer) issue(body string) (int, string) {
	s.t.Helper()
	status, payload := s.do(s.admin, http.MethodPost, "http://admin"+wire.AdminPathBootstrapCode, "", body)
	var reply struct{ Data wire.BootstrapCodeIssued }
	if status == http.StatusOK {
		if err := json.Unmarshal(payload, &reply); err != nil {
			s.t.Fatalf("decode %s: %v", payload, err)
		}
	}
	return status, reply.Data.Code
}

func (s *recoveryServer) mustIssue(body string) string {
	s.t.Helper()
	status, code := s.issue(body)
	if status != http.StatusOK || code == "" {
		s.t.Fatalf("issue %q: status %d", body, status)
	}
	return code
}

// exchange trades a code for an identity; it returns the status and, on
// success, the identity id and API token.
func (s *recoveryServer) exchange(code, name string) (status int, identity, token string) {
	s.t.Helper()
	req, err := json.Marshal(wire.BootstrapRequest{Code: code, DisplayName: name})
	if err != nil {
		s.t.Fatal(err)
	}
	status, payload := s.do(http.DefaultClient, http.MethodPost, s.api+wire.PathBootstrap, "", string(req))
	if status != http.StatusOK {
		return status, "", ""
	}
	var reply struct{ Data wire.Bootstrapped }
	if err := json.Unmarshal(payload, &reply); err != nil || reply.Data.APIToken == nil {
		s.t.Fatalf("decode %s: %v", payload, err)
	}
	return status, reply.Data.IdentityID.String(), reply.Data.APIToken.Value
}

func (s *recoveryServer) listNodes(token string) int {
	s.t.Helper()
	status, _ := s.do(http.DefaultClient, http.MethodGet, s.api+wire.PathNodes, token, "")
	return status
}

// newServerWithAdmin is a server whose first admin, A, took the bootstrap code.
// Each scenario gets its own, since the exchange route is rate limited per
// address (burst 5).
func newServerWithAdmin(t *testing.T) (s *recoveryServer, identityA, tokenA string) {
	t.Helper()
	s = newRecoveryServer(t)
	identityA, tokenA = mustExchange(t, s, s.mustIssue(""), "Admin A")
	return s, identityA, tokenA
}

const recoverBody = `{"recover":true}`

func TestAdminRecoveryCodeOnARealServerWithoutOIDC(t *testing.T) {
	t.Run("a plain bootstrap code is refused once an admin exists", func(t *testing.T) {
		s, _, _ := newServerWithAdmin(t)
		if status, _ := s.issue(""); status != http.StatusConflict {
			t.Errorf("plain code with an admin: status %d, want %d", status, http.StatusConflict)
		}
	})

	t.Run("a recovery code creates a second admin that can list nodes and leaves the first one bound", func(t *testing.T) {
		s, identityA, tokenA := newServerWithAdmin(t)
		code := s.mustIssue(recoverBody)
		if !strings.HasPrefix(code, "smr_") {
			t.Fatalf("recovery code %q lacks the smr_ prefix", code)
		}
		identityB, tokenB := mustExchange(t, s, code, "Admin B")
		if identityB == identityA {
			t.Errorf("the recovery created no new identity: %s", identityB)
		}
		if got := s.listNodes(tokenB); got != http.StatusOK {
			t.Errorf("nodes list with the recovered admin's token: status %d", got)
		}
		if got := s.listNodes(tokenA); got != http.StatusOK {
			t.Errorf("nodes list with the first admin's token: status %d", got)
		}
	})

	t.Run("a recovery code cannot be exchanged twice", func(t *testing.T) {
		s, _, _ := newServerWithAdmin(t)
		code := s.mustIssue(recoverBody)
		mustExchange(t, s, code, "Admin B")
		if status, _, _ := s.exchange(code, "Admin C"); status == http.StatusOK {
			t.Error("a used recovery code was exchanged again")
		}
	})

	t.Run("issuing a new recovery code invalidates a pending one", func(t *testing.T) {
		s, _, _ := newServerWithAdmin(t)
		first := s.mustIssue(recoverBody)
		second := s.mustIssue(recoverBody)
		if status, _, _ := s.exchange(first, "Superseded"); status == http.StatusOK {
			t.Error("a superseded recovery code was exchanged")
		}
		if status, _, _ := s.exchange(second, "Latest"); status != http.StatusOK {
			t.Errorf("the latest recovery code: status %d", status)
		}
	})

	t.Run("a refused plain code does not invalidate a pending recovery code", func(t *testing.T) {
		s, _, _ := newServerWithAdmin(t)
		pending := s.mustIssue(recoverBody)
		if status, _ := s.issue(""); status != http.StatusConflict {
			t.Fatalf("plain code with an admin: status %d", status)
		}
		if status, _, _ := s.exchange(pending, "Still valid"); status != http.StatusOK {
			t.Errorf("recovery code after a refused plain code: status %d", status)
		}
	})
}

func TestAdminRecoveryCodeAndPlainCodeInvalidateEachOther(t *testing.T) {
	t.Run("a recovery code invalidates a pending plain code", func(t *testing.T) {
		s := newRecoveryServer(t)
		plain := s.mustIssue("")
		recovery := s.mustIssue(recoverBody)
		if status, _, _ := s.exchange(plain, "Plain"); status == http.StatusOK {
			t.Error("a plain code superseded by a recovery code was exchanged")
		}
		if status, _, _ := s.exchange(recovery, "Recovery"); status != http.StatusOK {
			t.Errorf("the recovery code: status %d", status)
		}
	})

	t.Run("a plain code invalidates a pending recovery code", func(t *testing.T) {
		s := newRecoveryServer(t)
		recovery := s.mustIssue(recoverBody)
		plain := s.mustIssue("")
		if status, _, _ := s.exchange(recovery, "Recovery"); status == http.StatusOK {
			t.Error("a recovery code superseded by a plain code was exchanged")
		}
		if status, _, _ := s.exchange(plain, "Plain"); status != http.StatusOK {
			t.Errorf("the plain code: status %d", status)
		}
	})
}

func mustExchange(t *testing.T, s *recoveryServer, code, name string) (identity, token string) {
	t.Helper()
	status, identity, token := s.exchange(code, name)
	if status != http.StatusOK || token == "" {
		t.Fatalf("exchange for %q: status %d", name, status)
	}
	return identity, token
}
