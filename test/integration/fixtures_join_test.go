//go:build fixtures

package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const joinToken = "smj_fixture-token"

// enrollStub is the server side of /enroll: it records what the node presented
// and answers with the instance key, the way the Enrollments service does.
type enrollStub struct {
	mu       sync.Mutex
	requests []wire.EnrollRequest
	key      identity
}

func (s *enrollStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req wire.EnrollRequest
	if r.Method != http.MethodPost || r.URL.Path != wire.PathEnroll || json.NewDecoder(r.Body).Decode(&req) != nil || req.Token != joinToken {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(wire.ErrorEnvelope{Error: wire.Error{Code: "UNAUTHENTICATED", Message: "invalid join token"}})
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(wire.Envelope[wire.Enrolled]{Data: wire.Enrolled{
		NodeID: "node-joined", InstanceID: instanceID, SSHUser: dedicatedUser,
		AuthorizedKey: s.key.public, KeyVersion: 1, FingerprintSHA256: "SHA256:fixture",
	}})
}

// serveEnroll starts an HTTPS server the container can reach on every
// interface, with a certificate for the names the container uses for its host.
func serveEnroll(t *testing.T, names []string, stub *enrollStub) (port string, caPEM []byte) {
	t.Helper()
	cert, caPEM := selfSignedFor(t, names)
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: stub, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.ServeTLS(l, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port, caPEM
}

func selfSignedFor(t *testing.T, names []string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sm-join-fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), //nolint:forbidigo // x509 validity is judged against the wall clock
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pemBytes
}

// buildSM compiles sm for the architecture of the container.
func buildLinuxSM(t *testing.T, n *fixtureNode) string {
	t.Helper()
	arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[n.shell(t, "uname -m")]
	if arch == "" {
		t.Skipf("unsupported fixture architecture %q", n.shell(t, "uname -m"))
	}
	out := filepath.Join(t.TempDir(), "sm")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", out, "./cmd/sm")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build sm for linux/%s: %v\n%s", arch, err, combined)
	}
	return out
}

func (n *fixtureNode) put(t *testing.T, path, mode string, content []byte) {
	t.Helper()
	script := "umask 077 && cat > " + path + " && chmod " + mode + " " + path
	cmd := exec.CommandContext(t.Context(), "docker", "exec", "-i", n.Name, "sh", "-c", script)
	cmd.Stdin = bytes.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("put %s: %v\n%s", path, err, out)
	}
}

func (n *fixtureNode) copyIn(t *testing.T, local, remote string) {
	t.Helper()
	if out, err := exec.CommandContext(t.Context(), "docker", "cp", local, n.Name+":"+remote).CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v\n%s", err, out)
	}
}

// hostAddresses are the names under which the container can reach the docker
// host: Docker Desktop's alias, and the default gateway on a Linux daemon.
func hostAddresses(t *testing.T, n *fixtureNode) []string {
	t.Helper()
	names := []string{"host.docker.internal"}
	if gw, err := n.tryShell(t, "ip route | awk '/^default/ {print $3; exit}'"); err == nil && gw != "" {
		names = append(names, gw)
	}
	return names
}

func (n *fixtureNode) runJoin(t *testing.T, server string) (string, error) {
	t.Helper()
	return n.tryShell(t, "/usr/local/bin/sm join --server "+server+" --token-file /root/join-token --ca-file /root/join-ca.pem 2>&1")
}

// Join (ADR-0022) on the M1 fixture: the node enrolls over HTTPS, then the
// instance key opens the node as the dedicated user, with no extra privilege.
func TestFixturesM2_JoinEnrollsFixtureNode(t *testing.T) {
	n := startNode(t, fixture.Options{})
	id := newIdentity(t)
	stub := &enrollStub{key: id}
	names := hostAddresses(t, n)
	port, caPEM := serveEnroll(t, names, stub)
	n.copyIn(t, buildLinuxSM(t, n), "/usr/local/bin/sm")
	n.put(t, "/root/join-token", "0600", []byte(joinToken+"\n"))
	n.put(t, "/root/join-ca.pem", "0644", caPEM)

	var out string
	var err error
	for _, name := range names { // the first name the container can reach wins
		out, err = n.runJoin(t, "https://"+net.JoinHostPort(name, port))
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("sm join: %v\n%s", err, out)
	}

	t.Run("the node presented its pinned host key", func(t *testing.T) {
		if len(stub.requests) != 1 {
			t.Fatalf("requests = %d, want 1", len(stub.requests))
		}
		got := stub.requests[0]
		if got.HostPublicKey != n.hostKeyPin || got.Token != joinToken || got.Hostname == "" {
			t.Errorf("request = %+v, want host key %q", got, n.hostKeyPin)
		}
	})

	t.Run("the node is reachable as supermgmt with the instance key", func(t *testing.T) {
		h := newHarness(t, defaultPoolConfig(), id)
		res := run(t, h.pool.For(n.superTarget()), "setup.verify_id", nil)
		if got := strings.TrimSpace(string(res.Stdout)); got != dedicatedUser {
			t.Errorf("id -un = %q, want %s", got, dedicatedUser)
		}
	})

	t.Run("the account and its key line are exactly the minimal join", func(t *testing.T) {
		if got := n.shell(t, "cat /var/lib/supermgmt/.ssh/authorized_keys"); got != "restrict "+id.public+" supermgmt@"+instanceID {
			t.Errorf("authorized_keys = %q", got)
		}
		if got := n.shell(t, "stat -c '%U:%G %a' /var/lib/supermgmt /var/lib/supermgmt/markers /var/lib/supermgmt/.ssh /var/lib/supermgmt/.ssh/authorized_keys"); got !=
			"supermgmt:supermgmt 750\nsupermgmt:supermgmt 700\nsupermgmt:supermgmt 700\nsupermgmt:supermgmt 600" {
			t.Errorf("modes = %q", got)
		}
		if got := n.shell(t, "id -nG supermgmt"); got != "supermgmt" {
			t.Errorf("groups = %q, want only the primary group (no docker, no journal)", got)
		}
		if _, err := n.tryShell(t, "test -e /etc/sudoers.d/supermgmt"); err == nil {
			t.Error("join wrote a sudoers drop-in")
		}
		if got := n.shell(t, "getent shadow supermgmt | cut -d: -f2"); got != "*" {
			t.Errorf("password field = %q, want *", got)
		}
	})

	t.Run("running join again converges", func(t *testing.T) {
		before := n.shell(t, "getent passwd supermgmt; sha256sum /var/lib/supermgmt/.ssh/authorized_keys")
		var again string
		var err error
		for _, name := range names {
			if again, err = n.runJoin(t, "https://"+net.JoinHostPort(name, port)); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("second sm join: %v\n%s", err, again)
		}
		if after := n.shell(t, "getent passwd supermgmt; sha256sum /var/lib/supermgmt/.ssh/authorized_keys"); after != before {
			t.Errorf("state changed on the second run:\n%s\n%s", before, after)
		}
	})

	t.Run("a foreign supermgmt account is never adopted", func(t *testing.T) {
		n.shell(t, "pkill -u supermgmt; userdel -r supermgmt; useradd --create-home --shell /bin/bash supermgmt")
		var refusal string
		var err error
		for _, name := range names {
			if refusal, err = n.runJoin(t, "https://"+net.JoinHostPort(name, port)); err != nil && strings.Contains(refusal, "not the SuperMgmt service account") {
				break
			}
		}
		if err == nil || !strings.Contains(refusal, "not the SuperMgmt service account") {
			t.Fatalf("sm join over a foreign account: err = %v, output %q; want a CONFLICT refusal", err, refusal)
		}
	})
}
