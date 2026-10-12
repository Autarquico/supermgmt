package installer

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
)

func serverOpts() Options {
	return Options{Mode: ModeServer, Binary: "/tmp/sm", PublicURL: "https://mgmt.example.com"}
}

func TestServerUnitMatchesTheReferenceUnit(t *testing.T) {
	want, err := os.ReadFile("../../packaging/systemd/supermgmt.service")
	if err != nil {
		t.Fatal(err)
	}
	got := renderServerUnit(Options{Mode: ModeServer}.layout(Host{}))
	if string(got) != string(want) {
		t.Fatalf("rendered unit differs from packaging/systemd/supermgmt.service:\n%s", got)
	}
}

func TestServerInstallProxyByDefault(t *testing.T) {
	w := newWorld()
	d, out := w.deps("linux", 0, false)
	if err := New(d).Run(context.Background(), serverOpts()); err != nil {
		t.Fatal(err)
	}
	cfg := string(w.files["/etc/supermgmt/config.yaml"])
	for _, want := range []string{"mode: proxy", "listen: 127.0.0.1:8787", "127.0.0.1/32", "public_url: https://mgmt.example.com"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config lacks %q:\n%s", want, cfg)
		}
	}
	if _, err := config.LoadBytes(w.files["/etc/supermgmt/config.yaml"], nil); err != nil {
		t.Errorf("written config does not load: %v", err)
	}
	if w.probe.URL != "http://127.0.0.1:8787/health/ready" || w.probe.RootPEM != nil {
		t.Errorf("probe = %+v", w.probe)
	}
	if !strings.Contains(out.String(), "CODE-1234") {
		t.Errorf("bootstrap code not printed:\n%s", out)
	}
}

func TestServerInstallLaysOutPermissions(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 0, false)
	if err := New(d).Run(context.Background(), serverOpts()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mode  fs.FileMode
		owner Owner
	}{
		"/etc/supermgmt":                  {0o750, Owner{"root", ServiceUser}},
		"/etc/supermgmt/config.yaml":      {0o640, Owner{"root", ServiceUser}},
		"/var/lib/supermgmt":              {0o750, Owner{ServiceUser, ServiceUser}},
		"/var/lib/supermgmt/secrets/keys": {0o700, Owner{ServiceUser, ServiceUser}},
		"/usr/local/bin/sm":               {0o755, Owner{}},
		"/etc/systemd/system/" + UnitName: {0o644, Owner{}},
	}
	for path, want := range cases {
		if w.modes[path] != want.mode || w.owners[path] != want.owner {
			t.Errorf("%s = %v %v, want %v %v", path, w.modes[path], w.owners[path], want.mode, want.owner)
		}
	}
}

func TestServerInstallOrdersSteps(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 0, false)
	if err := New(d).Run(context.Background(), serverOpts()); err != nil {
		t.Fatal(err)
	}
	order := []string{"useradd", "copy /usr/local/bin/sm", "write /etc/supermgmt/config.yaml", "register", "start", "health", "run /usr/local/bin/sm admin bootstrap-code"}
	last := -1
	for _, prefix := range order {
		i := w.index(prefix)
		if i <= last {
			t.Fatalf("%q at %d, want after %d; events: %v", prefix, i, last, w.events)
		}
		last = i
	}
}

func TestServerInstallExitCodes(t *testing.T) {
	cases := []struct {
		name  string
		goos  string
		uid   int
		setup func(*world)
		want  int
	}{
		{"not root", "linux", 1000, nil, ExitPrerequisite},
		{"not linux", "darwin", 0, nil, ExitUnsupported},
		{"health never ready", "linux", 0, func(w *world) { w.healthErr = context.DeadlineExceeded }, ExitConnectivity},
		{"service fails to start", "linux", 0, func(w *world) { w.startErr = context.Canceled }, ExitConfiguration},
		{"bootstrap code fails", "linux", 0, func(w *world) {
			w.runErr["/usr/local/bin/sm admin bootstrap-code"] = &ExitStatus{Command: "sm", Code: 1}
		}, ExitConfiguration},
		{"empty bootstrap code", "linux", 0, func(w *world) { w.bootstrap = "\n" }, ExitConfiguration},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld()
			if tc.setup != nil {
				tc.setup(w)
			}
			d, _ := w.deps(tc.goos, tc.uid, false)
			err := New(d).Run(context.Background(), serverOpts())
			if got := exitCodeOf(t, err); got != tc.want {
				t.Fatalf("exit %d (%v), want %d", got, err, tc.want)
			}
		})
	}
}

func TestPublicURLIsRequiredWithoutATerminal(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 0, false)
	o := serverOpts()
	o.PublicURL = ""
	if got := exitCodeOf(t, New(d).Run(context.Background(), o)); got != ExitInvalid {
		t.Fatalf("exit %d, want %d", got, ExitInvalid)
	}
}

func TestPublicURLIsAskedWithATerminal(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 0, true)
	o := serverOpts()
	o.PublicURL, o.Yes = "", true
	if err := New(d).Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(w.asked) != 1 || !strings.Contains(w.asked[0], "Public https URL") {
		t.Fatalf("asked %v", w.asked)
	}
}

func TestTLSValidation(t *testing.T) {
	goodCert, goodKey := testCert(t, "mgmt.example.com", testNow.Add(time.Hour))
	_, otherKey := testCert(t, "mgmt.example.com", testNow.Add(time.Hour))
	expiredCert, expiredKey := testCert(t, "mgmt.example.com", testNow.Add(-time.Minute))
	wrongHostCert, wrongHostKey := testCert(t, "other.example.com", testNow.Add(time.Hour))

	direct := func(cert, key string) Options {
		o := serverOpts()
		o.TLS, o.CertFile, o.KeyFile = config.TLSDirect, cert, key
		return o
	}
	cases := []struct {
		name  string
		opts  Options
		files map[string][]byte
		want  int
	}{
		{"direct valid", direct("/c.pem", "/k.pem"), map[string][]byte{"/c.pem": goodCert, "/k.pem": goodKey}, 0},
		{"direct without cert and key", direct("", ""), nil, ExitInvalid},
		{"direct missing cert file", direct("/c.pem", "/k.pem"), map[string][]byte{"/k.pem": goodKey}, ExitInvalid},
		{"direct missing key file", direct("/c.pem", "/k.pem"), map[string][]byte{"/c.pem": goodCert}, ExitInvalid},
		{"direct mismatched key", direct("/c.pem", "/k.pem"), map[string][]byte{"/c.pem": goodCert, "/k.pem": otherKey}, ExitInvalid},
		{"direct garbage cert", direct("/c.pem", "/k.pem"), map[string][]byte{"/c.pem": []byte("nope"), "/k.pem": goodKey}, ExitInvalid},
		{"direct expired", direct("/c.pem", "/k.pem"), map[string][]byte{"/c.pem": expiredCert, "/k.pem": expiredKey}, ExitInvalid},
		{"direct wrong host", direct("/c.pem", "/k.pem"), map[string][]byte{"/c.pem": wrongHostCert, "/k.pem": wrongHostKey}, ExitInvalid},
		{"proxy with cert flags", func() Options { o := serverOpts(); o.CertFile = "/c.pem"; return o }(), nil, ExitInvalid},
		{
			"direct with trusted proxies", func() Options { o := direct("/c.pem", "/k.pem"); o.TrustedProxies = []string{"10.0.0.1"}; return o }(),
			map[string][]byte{"/c.pem": goodCert, "/k.pem": goodKey},
			ExitInvalid,
		},
		{"public url over http", func() Options { o := serverOpts(); o.PublicURL = "http://mgmt.example.com"; return o }(), nil, ExitInvalid},
		{"public url without host", func() Options { o := serverOpts(); o.PublicURL = "https://"; return o }(), nil, ExitInvalid},
		{"unknown tls mode", func() Options { o := serverOpts(); o.TLS = "acme"; return o }(), nil, ExitInvalid},
		{"proxy listening on a public address", func() Options { o := serverOpts(); o.Listen = "0.0.0.0:8787"; return o }(), nil, ExitInvalid},
		{"proxy with a malformed trusted proxy", func() Options { o := serverOpts(); o.TrustedProxies = []string{"not-an-ip"}; return o }(), nil, ExitInvalid},
		{"proxy with explicit CIDRs", func() Options { o := serverOpts(); o.TrustedProxies = []string{"10.0.0.0/8", "::1"}; return o }(), nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld()
			for p, b := range tc.files {
				w.files[p] = b
			}
			d, _ := w.deps("linux", 0, false)
			d.Clock = fixedClock{}
			err := New(d).Run(context.Background(), tc.opts)
			if tc.want == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if got := exitCodeOf(t, err); got != tc.want {
				t.Fatalf("exit %d (%v), want %d", got, err, tc.want)
			}
			if w.index("write /etc") >= 0 || w.index("useradd") >= 0 {
				t.Errorf("a rejected TLS arrangement must change nothing: %v", w.events)
			}
		})
	}
}

func TestDirectTLSProbeTrustsTheConfiguredCertificate(t *testing.T) {
	cert, key := testCert(t, "mgmt.example.com", testNow.Add(time.Hour))
	w := newWorld()
	w.files["/c.pem"], w.files["/k.pem"] = cert, key
	d, _ := w.deps("linux", 0, false)
	o := serverOpts()
	o.TLS, o.CertFile, o.KeyFile = config.TLSDirect, "/c.pem", "/k.pem"
	if err := New(d).Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if w.probe.URL != "https://127.0.0.1:8443/health/ready" || w.probe.ServerName != "mgmt.example.com" || string(w.probe.RootPEM) != string(cert) {
		t.Fatalf("probe = %+v", w.probe)
	}
	if !strings.Contains(string(w.files["/etc/supermgmt/config.yaml"]), "cert_file: /c.pem") {
		t.Errorf("config lacks the cert path:\n%s", w.files["/etc/supermgmt/config.yaml"])
	}
}

func TestExistingInstallFailsWithoutATerminal(t *testing.T) {
	cases := map[string]string{
		"binary":   "/usr/local/bin/sm",
		"unit":     "/etc/systemd/system/" + UnitName,
		"config":   "/etc/supermgmt/config.yaml",
		"database": "/var/lib/supermgmt/supermgmt.db",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld()
			w.files[path] = []byte("x")
			d, _ := w.deps("linux", 0, false)
			err := New(d).Run(context.Background(), serverOpts())
			if got := exitCodeOf(t, err); got != ExitPrerequisite {
				t.Fatalf("exit %d (%v), want %d", got, err, ExitPrerequisite)
			}
			if w.index("useradd") >= 0 || w.index("copy") >= 0 {
				t.Errorf("nothing may change: %v", w.events)
			}
		})
	}
}

func TestMultipleCandidateConfigsAreAmbiguous(t *testing.T) {
	w := newWorld()
	w.files["/etc/supermgmt/config.yaml"] = []byte("a")
	w.files["/home/alex/.config/supermgmt/config.yaml"] = []byte("b")
	d, _ := w.deps("linux", 0, false)
	err := New(d).Run(context.Background(), serverOpts())
	if got := exitCodeOf(t, err); got != ExitPrerequisite || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("exit %d (%v)", got, err)
	}
}

func TestExistingInstallAsksWithATerminalAndKeepsConfig(t *testing.T) {
	w := newWorld()
	w.files["/etc/supermgmt/config.yaml"] = []byte("version: 1\ninstance:\n  mode: server\nserver:\n  public_url: https://old.example.com\n  tls: {mode: proxy}\n  trusted_proxies: [127.0.0.1/32]\n")
	d, _ := w.deps("linux", 0, true)
	o := serverOpts()
	o.Yes = true
	if err := New(d).Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(w.files["/etc/supermgmt/config.yaml"]), "old.example.com") {
		t.Error("existing configuration was overwritten")
	}
	if len(w.asked) != 1 {
		t.Errorf("asked %v", w.asked)
	}
}

func TestDecliningTheExistingInstallPromptCancels(t *testing.T) {
	w := newWorld()
	w.files["/usr/local/bin/sm"] = []byte("old")
	w.confirmYes = false
	d, _ := w.deps("linux", 0, true)
	err := New(d).Run(context.Background(), serverOpts())
	if got := exitCodeOf(t, err); got != ExitCancelled {
		t.Fatalf("exit %d (%v), want %d", got, err, ExitCancelled)
	}
	if string(w.files["/usr/local/bin/sm"]) != "old" {
		t.Error("binary replaced after cancel")
	}
}

func TestDecliningThePlanCancels(t *testing.T) {
	w := newWorld()
	w.confirmYes = false
	d, _ := w.deps("linux", 0, true)
	err := New(d).Run(context.Background(), serverOpts())
	if got := exitCodeOf(t, err); got != ExitCancelled {
		t.Fatalf("exit %d, want %d", got, ExitCancelled)
	}
}

func TestExistingServiceUserIsReused(t *testing.T) {
	w := newWorld()
	w.users[ServiceUser] = true
	d, _ := w.deps("linux", 0, false)
	if err := New(d).Run(context.Background(), serverOpts()); err != nil {
		t.Fatal(err)
	}
	if w.index("useradd") >= 0 {
		t.Error("user created twice")
	}
}

func TestUnknownModeIsInvalid(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 0, false)
	if got := exitCodeOf(t, New(d).Run(context.Background(), Options{Mode: "bogus"})); got != ExitInvalid {
		t.Fatalf("exit %d", got)
	}
}

// The M3 modes are frozen in W0 and exit 3 until their tasks fill them.
func TestM3ModesAreUnsupportedUntilImplemented(t *testing.T) {
	for _, mode := range []Mode{ModeProxmoxLXC, ModeUpgrade, ModeUninstall} {
		w := newWorld()
		d, _ := w.deps("linux", 0, false)
		if got := exitCodeOf(t, New(d).Run(context.Background(), Options{Mode: mode})); got != ExitUnsupported {
			t.Errorf("%s: exit %d", mode, got)
		}
	}
}

func TestExitCode(t *testing.T) {
	if ExitCode(nil) != 0 || ExitCode(context.Canceled) != 1 || ExitCode(fail(ExitRestore, "x")) != ExitRestore {
		t.Fatal("ExitCode mapping broken")
	}
}

func TestProxyModeProbeStatesThatTLSEndedAtTheProxy(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 0, false)
	o := serverOpts()
	o.TLS = config.TLSProxy
	if err := New(d).Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if w.probe.URL != "http://127.0.0.1:8787/health/ready" || w.probe.ForwardedProto != "https" {
		t.Fatalf("probe = %+v, want plain HTTP on loopback with X-Forwarded-Proto https", w.probe)
	}
}
