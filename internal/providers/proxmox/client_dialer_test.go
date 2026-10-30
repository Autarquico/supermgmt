package proxmox_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
)

const dialerToken = "root@pam!sm=00000000-0000-0000-0000-000000000000"

// authority is a throwaway CA and the certificate it signed for pve.test and
// 127.0.0.1.
type authority struct {
	caPEM []byte
	leaf  tls.Certificate
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "pve"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames: []string{"pve.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return authority{
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leaf:  tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

// relayedServer is a TLS server reached only through the dialer; dials counts
// the connections the client opened and open the ones still open.
type relayedServer struct {
	dial  func(context.Context) (net.Conn, error)
	dials atomic.Int32
	open  atomic.Int32
	host  atomic.Value // Host header of the last request
	auth  atomic.Value // Authorization header of the last request
}

type trackedConn struct {
	net.Conn
	open *atomic.Int32
	done atomic.Bool
}

func (c *trackedConn) Close() error {
	if c.done.CompareAndSwap(false, true) {
		c.open.Add(-1)
	}
	return c.Conn.Close()
}

func startRelayedServer(t *testing.T, a authority, handler http.HandlerFunc) *relayedServer {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{a.leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	rs := &relayedServer{}
	rs.dial = func(ctx context.Context) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		rs.dials.Add(1)
		rs.open.Add(1)
		return &trackedConn{Conn: c, open: &rs.open}, nil
	}
	return rs
}

func versionHandler(rs **relayedServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		(*rs).host.Store(r.Host)
		(*rs).auth.Store(r.Header.Get("Authorization"))
		if r.URL.Path != "/api2/json/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"version":"9.0.3","release":"9.0"}}`))
	}
}

func relayedClient(t *testing.T, rs *relayedServer, ca []byte, name string) proxmox.Client {
	t.Helper()
	c, err := proxmox.New("", ca, audit.Secret(dialerToken),
		proxmox.WithDialer(rs.dial), proxmox.WithServerName(name), proxmox.WithHTTPTimeout(testTimeout))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDialerClientReachesPVEWithAFixedBase(t *testing.T) {
	a := newAuthority(t)
	var rs *relayedServer
	rs = startRelayedServer(t, a, versionHandler(&rs))
	v, err := relayedClient(t, rs, a.caPEM, "pve.test").Version(context.Background())
	if err != nil || v.Version != "9.0.3" {
		t.Fatalf("version = %+v, err = %v", v, err)
	}
	if got := rs.host.Load(); got != "pve.test:8006" {
		t.Errorf("Host = %v, want pve.test:8006", got)
	}
	if got := rs.auth.Load(); got != "PVEAPIToken="+dialerToken {
		t.Errorf("Authorization = %v", got)
	}
}

func TestDialerClientAcceptsAnIPLiteralServerName(t *testing.T) {
	a := newAuthority(t)
	var rs *relayedServer
	rs = startRelayedServer(t, a, versionHandler(&rs))
	if _, err := relayedClient(t, rs, a.caPEM, "127.0.0.1").Version(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := rs.host.Load(); got != "127.0.0.1:8006" {
		t.Errorf("Host = %v", got)
	}
}

func TestDialerClientRefusesACertificateOfAnotherCA(t *testing.T) {
	a, other := newAuthority(t), newAuthority(t)
	var rs *relayedServer
	rs = startRelayedServer(t, a, versionHandler(&rs))
	if _, err := relayedClient(t, rs, other.caPEM, "pve.test").Version(context.Background()); err == nil {
		t.Fatal("a certificate from another CA was accepted")
	}
	if rs.auth.Load() != nil {
		t.Error("a request carrying the token was sent over an unverified channel")
	}
}

func TestDialerClientRefusesAnotherServerName(t *testing.T) {
	a := newAuthority(t)
	var rs *relayedServer
	rs = startRelayedServer(t, a, versionHandler(&rs))
	if _, err := relayedClient(t, rs, a.caPEM, "other.test").Version(context.Background()); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
	if rs.auth.Load() != nil {
		t.Error("a request carrying the token was sent over an unverified channel")
	}
}

func TestDialerClientDoesNotFollowRedirects(t *testing.T) {
	a := newAuthority(t)
	rs := startRelayedServer(t, a, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.test/api2/json/version", http.StatusFound)
	})
	if _, err := relayedClient(t, rs, a.caPEM, "pve.test").Version(context.Background()); err == nil {
		t.Fatal("a redirect was followed")
	}
	if rs.dials.Load() != 1 {
		t.Errorf("dials = %d, want 1", rs.dials.Load())
	}
}

func TestDialerClientReusesAndCloseIdleEndsTheRelay(t *testing.T) {
	a := newAuthority(t)
	var rs *relayedServer
	rs = startRelayedServer(t, a, versionHandler(&rs))
	c := relayedClient(t, rs, a.caPEM, "pve.test")
	for range 3 {
		if _, err := c.Version(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if rs.dials.Load() != 1 || rs.open.Load() != 1 {
		t.Fatalf("dials = %d, open = %d; want one reused connection", rs.dials.Load(), rs.open.Load())
	}
	c.(proxmox.IdleCloser).CloseIdle()
	deadline := time.Now().Add(testTimeout)                  //nolint:forbidigo // test polling against real goroutines
	for rs.open.Load() != 0 && time.Now().Before(deadline) { //nolint:forbidigo // see above
		time.Sleep(10 * time.Millisecond)
	}
	if rs.open.Load() != 0 {
		t.Error("CloseIdle left the relay connection open")
	}
}

func TestDialerNeedsACAAndAServerName(t *testing.T) {
	a := newAuthority(t)
	dial := func(context.Context) (net.Conn, error) { return nil, net.ErrClosed }
	for name, tc := range map[string]struct {
		ca   []byte
		opts []proxmox.Option
	}{
		"no CA":            {nil, []proxmox.Option{proxmox.WithDialer(dial), proxmox.WithServerName("pve.test")}},
		"CA without PEM":   {[]byte("nope"), []proxmox.Option{proxmox.WithDialer(dial), proxmox.WithServerName("pve.test")}},
		"no server name":   {a.caPEM, []proxmox.Option{proxmox.WithDialer(dial)}},
		"name with a path": {a.caPEM, []proxmox.Option{proxmox.WithDialer(dial), proxmox.WithServerName("pve.test/x")}},
	} {
		if _, err := proxmox.New("", tc.ca, audit.Secret(dialerToken), tc.opts...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
