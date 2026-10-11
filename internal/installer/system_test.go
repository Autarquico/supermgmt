package installer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOSFilesWriteAtomicWithMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.yaml")
	var f osFiles
	if err := f.MkdirAll(filepath.Dir(path), 0o700, Owner{}); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteFile(path, []byte("one"), 0o640, Owner{}); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteFile(path, []byte("two"), 0o640, Owner{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, err = %v", info.Mode(), err)
	}
	if got, _ := f.ReadFile(path); string(got) != "two" {
		t.Fatalf("content = %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestOSFilesCopyFile(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (osFiles{}).CopyFile(src, dst, 0o755, Owner{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dst)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, err = %v", info.Mode(), err)
	}
}

func TestHealthWaitsUntilReady(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	if err := (httpHealth{}).WaitReady(context.Background(), Probe{URL: srv.URL}, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2 {
		t.Error("returned before the service was ready")
	}
}

func TestHealthTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if err := (httpHealth{}).WaitReady(context.Background(), Probe{URL: srv.URL}, 700*time.Millisecond); err == nil {
		t.Fatal("want a timeout")
	}
}

func TestHealthTrustsOnlyTheConfiguredCertificate(t *testing.T) {
	certPEM, keyPEM := testCert(t, "mgmt.example.com", testNow.Add(24*time.Hour))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	good := Probe{URL: srv.URL, ServerName: "mgmt.example.com", RootPEM: certPEM}
	if err := (httpHealth{}).WaitReady(context.Background(), good, 5*time.Second); err != nil {
		t.Fatalf("configured certificate rejected: %v", err)
	}
	other, _ := testCert(t, "mgmt.example.com", testNow.Add(24*time.Hour))
	bad := Probe{URL: srv.URL, ServerName: "mgmt.example.com", RootPEM: other}
	if err := (httpHealth{}).WaitReady(context.Background(), bad, 700*time.Millisecond); err == nil {
		t.Fatal("a different certificate must not be trusted")
	}
}

func TestLinePrompterConfirm(t *testing.T) {
	for answer, want := range map[string]bool{"y\n": true, "YES\n": true, "n\n": false, "\n": false, "maybe\n": false} {
		var out bytes.Buffer
		p := linePrompter{in: bufio.NewReader(strings.NewReader(answer)), out: &out}
		got, err := p.Confirm("Proceed?")
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v", answer, got, err)
		}
	}
}

func TestDialAddress(t *testing.T) {
	cases := map[string]string{"127.0.0.1:8787": "127.0.0.1:8787", "0.0.0.0:8443": "127.0.0.1:8443", ":8443": "127.0.0.1:8443", "[::]:8443": "127.0.0.1:8443", "10.0.0.5:443": "10.0.0.5:443"}
	for in, want := range cases {
		got, err := dialAddress(in)
		if err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := dialAddress("unix:/run/sm.sock"); err == nil {
		t.Error("unix listen cannot be probed")
	}
}
