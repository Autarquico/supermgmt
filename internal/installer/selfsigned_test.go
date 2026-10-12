package installer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
)

const tlsDir = "/etc/supermgmt/tls/"

func selfSignedOpts(publicURL string, noStart bool) Options {
	o := serverOpts()
	o.PublicURL = publicURL
	o.TLS, o.SelfSigned, o.NoStart = config.TLSDirect, true, noStart
	return o
}

func installSelfSigned(t *testing.T, o Options) (*world, string) {
	t.Helper()
	w := newWorld()
	d, out := w.deps("linux", 0, false)
	if err := New(d).Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	return w, out.String()
}

// handshake runs a TLS handshake between the installed server certificate and
// a client that trusts only the CA file, verifying serverName.
func handshake(t *testing.T, w *world, serverName string) error {
	t.Helper()
	ctx := context.Background()
	pair, err := tls.X509KeyPair(w.files[tlsDir+"server.pem"], w.files[tlsDir+"server.key"])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(w.files[tlsDir+"ca.pem"]) {
		t.Fatal("CA file holds no certificate")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pair}}).HandshakeContext(ctx)
	}()
	clientConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	client := tls.Client(clientConn, &tls.Config{RootCAs: roots, ServerName: serverName, Time: fixedClock{}.Now})
	return client.HandshakeContext(ctx)
}

func TestSelfSignedLeafIsTrustedThroughTheCAForEveryName(t *testing.T) {
	cases := map[string]struct{ publicURL, serverName string }{
		"public dns name": {"https://mgmt.example.com", "mgmt.example.com"},
		"loopback ip":     {"https://mgmt.example.com", "127.0.0.1"},
		"localhost":       {"https://mgmt.example.com", "localhost"},
		"public ip":       {"https://192.0.2.10:8443", "192.0.2.10"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, _ := installSelfSigned(t, selfSignedOpts(tc.publicURL, false))
			if err := handshake(t, w, tc.serverName); err != nil {
				t.Fatalf("client trusting the CA must connect: %v", err)
			}
		})
	}
}

func TestSelfSignedLeafIsNotTrustedForOtherNames(t *testing.T) {
	w, _ := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", false))
	if err := handshake(t, w, "evil.example.com"); err == nil {
		t.Fatal("a name outside the SANs must fail verification")
	}
}

func TestSelfSignedKeysArePrivate(t *testing.T) {
	w, _ := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", false))
	svc, root := Owner{ServiceUser, ServiceUser}, Owner{"root", "root"}
	cases := map[string]struct {
		mode  uint32
		owner Owner
	}{
		tlsDir + "ca.key":     {0o600, root},
		tlsDir + "server.key": {0o600, svc},
		tlsDir + "ca.pem":     {0o644, root},
		tlsDir + "server.pem": {0o644, root},
	}
	for path, want := range cases {
		if uint32(w.modes[path]) != want.mode || w.owners[path] != want.owner {
			t.Errorf("%s = %v %v, want %o %v", path, w.modes[path], w.owners[path], want.mode, want.owner)
		}
	}
}

func TestSelfSignedConfigUsesDirectTLSWithTheLeaf(t *testing.T) {
	w, _ := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", false))
	cfg := string(w.files["/etc/supermgmt/config.yaml"])
	for _, want := range []string{"mode: direct", "cert_file: " + tlsDir + "server.pem", "key_file: " + tlsDir + "server.key", "listen: 0.0.0.0:8443"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config lacks %q:\n%s", want, cfg)
		}
	}
}

func TestNoStartLoadsTheUnitAndNeverEnablesOrStartsIt(t *testing.T) {
	w, out := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", true))
	if w.index("load "+UnitName) < 0 {
		t.Fatalf("unit not loaded: %v", w.events)
	}
	for _, forbidden := range []string{"register ", "start ", "health ", "run "} {
		if w.index(forbidden) >= 0 {
			t.Errorf("--no-start must not %q: %v", forbidden, w.events)
		}
	}
	if strings.Contains(out, "Bootstrap code") {
		t.Errorf("no bootstrap code before the server is initialized:\n%s", out)
	}
}

func TestSelfSignedInstallPrintsTheCAForLogin(t *testing.T) {
	w, out := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", true))
	fp, err := fingerprint(w.files[tlsDir+"ca.pem"])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{tlsDir + "ca.pem", fp, strings.TrimSpace(string(w.files[tlsDir+"ca.pem"])), "sm login --ca-file"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Error("a private key must never be printed")
	}
}

func TestSelfSignedStartedServerIsProbedThroughTheCAAndPrintsBootstrapAndCA(t *testing.T) {
	w, out := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", false))
	if w.index("register "+UnitName) < 0 || w.index("start "+UnitName) < 0 {
		t.Fatalf("unit not registered and started: %v", w.events)
	}
	if string(w.probe.RootPEM) != string(w.files[tlsDir+"ca.pem"]) || w.probe.ServerName != "mgmt.example.com" {
		t.Errorf("probe = %+v, want trust anchored at the CA", w.probe)
	}
	if !strings.Contains(out, "CODE-1234") || !strings.Contains(out, "SHA-256 fingerprint") {
		t.Errorf("output lacks the bootstrap code or the CA:\n%s", out)
	}
}

func TestSelfSignedNeverRegeneratesExistingCertificates(t *testing.T) {
	w := newWorld()
	w.files[tlsDir+"server.pem"], w.files[tlsDir+"ca.pem"] = []byte("old-leaf"), []byte("old-ca")
	d, _ := w.deps("linux", 0, false)
	err := New(d).Run(context.Background(), selfSignedOpts("https://mgmt.example.com", true))
	if exitCodeOf(t, err) != ExitConfiguration {
		t.Fatalf("an unreadable existing CA should fail the fingerprint step, got %v", err)
	}
	if string(w.files[tlsDir+"server.pem"]) != "old-leaf" || string(w.files[tlsDir+"ca.pem"]) != "old-ca" {
		t.Error("existing certificate material must never be regenerated")
	}
}

func TestSelfSignedRejectsConflictingFlags(t *testing.T) {
	cases := map[string]func(*Options){
		"cert file":     func(o *Options) { o.CertFile = "/c.pem" },
		"key file":      func(o *Options) { o.KeyFile = "/k.pem" },
		"trusted proxy": func(o *Options) { o.TrustedProxies = []string{"10.0.0.1"} },
		"non-https url": func(o *Options) { o.PublicURL = "http://mgmt.example.com" },
		"missing url":   func(o *Options) { o.PublicURL = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld()
			d, _ := w.deps("linux", 0, false)
			o := selfSignedOpts("https://mgmt.example.com", false)
			mutate(&o)
			if got := exitCodeOf(t, New(d).Run(context.Background(), o)); got != ExitInvalid {
				t.Errorf("exit = %d, want %d", got, ExitInvalid)
			}
			if len(w.events) != 0 {
				t.Errorf("a rejected install must change nothing: %v", w.events)
			}
		})
	}
}

func TestNoStartIsRejectedForRestore(t *testing.T) {
	w := newWorld()
	w.files["/a.tar"], w.files["/k.key"] = []byte("a"), []byte("k")
	d, _ := w.deps("linux", 0, false)
	o := serverOpts()
	o.Mode, o.Archive, o.KeyExport, o.NoStart = ModeRestore, "/a.tar", "/k.key", true
	if got := exitCodeOf(t, New(d).Run(context.Background(), o)); got != ExitInvalid {
		t.Errorf("exit = %d, want %d", got, ExitInvalid)
	}
}
