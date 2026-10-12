package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/providers/proxmox/pvefake"
)

// ---- a TLS server with a certificate chain of the test's choosing ----------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: domain.SystemClock{}.Now().Add(-time.Hour), NotAfter: domain.SystemClock{}.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// serve starts a TLS server whose leaf, signed by ca, covers names and
// returns its port and the leaf's DER.
func (ca testCA) serve(t *testing.T, serial int64, dns []string, ips ...net.IP) (port string, leaf []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "pve"},
		NotBefore: domain.SystemClock{}.Now().Add(-time.Hour), NotAfter: domain.SystemClock{}.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: dns, IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := tls.NewListener(plain, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).HandshakeContext(context.Background())
				_ = conn.Close()
			}()
		}
	}()
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port, der
}

func writeCA(t *testing.T, ca testCA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, path, string(ca.pem))
	return path
}

func providersCheck(env []string, args ...string) result {
	return execRoot(env, "", args, newProvidersCmd(env))
}

func tlsOnly(args ...string) result {
	return providersCheck([]string{"HOME=" + os.TempDir()}, append([]string{"providers", "check", "--offline", "--tls-only", "--json"}, args...)...)
}

type checkJSON struct {
	Provider          string `json:"provider"`
	Endpoint          string `json:"endpoint"`
	OK                bool   `json:"ok"`
	Problem           string `json:"problem"`
	Version           string `json:"version"`
	Nodes             int    `json:"nodes"`
	Guests            int    `json:"guests"`
	Storages          int    `json:"storages"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

func decodeCheck(t *testing.T, r result) checkJSON {
	t.Helper()
	var out checkJSON
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("not a check report: %q (stderr %q): %v", r.stdout, r.stderr, err)
	}
	return out
}

func TestTLSOnlyCheckAcceptsTheChainTheEndpointServesForItsHost(t *testing.T) {
	ca := newTestCA(t, "pve-root")
	port, leaf := ca.serve(t, 2, []string{"pve.test"}, net.ParseIP("127.0.0.1"))

	r := tlsOnly("--endpoint", "https://127.0.0.1:"+port, "--ca-file", writeCA(t, ca))

	report := decodeCheck(t, r)
	sum := sha256.Sum256(leaf)
	if r.code != 0 || !report.OK || report.CertificateSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("exit %d, report %+v, stderr %q", r.code, report, r.stderr)
	}
}

func TestTLSOnlyCheckRefusesACertificateThatDoesNotCoverTheChosenHostName(t *testing.T) {
	ca := newTestCA(t, "pve-root")
	port, _ := ca.serve(t, 2, []string{"pve.test"}, net.ParseIP("127.0.0.1"))

	r := tlsOnly("--endpoint", "https://localhost:"+port, "--ca-file", writeCA(t, ca))

	report := decodeCheck(t, r)
	if r.code != 8 || report.OK || !strings.Contains(report.Problem, "localhost") || !strings.Contains(report.Problem, "not trusted") {
		t.Errorf("exit %d, report %+v", r.code, report)
	}
}

func TestTLSOnlyCheckRefusesARotatedCertificateTheCADidNotSign(t *testing.T) {
	trusted, rotated := newTestCA(t, "pve-root"), newTestCA(t, "pve-root-2")
	port, _ := rotated.serve(t, 3, nil, net.ParseIP("127.0.0.1"))

	r := tlsOnly("--endpoint", "https://127.0.0.1:"+port, "--ca-file", writeCA(t, trusted))

	report := decodeCheck(t, r)
	if r.code != 8 || report.OK || !strings.Contains(report.Problem, "unknown authority") {
		t.Errorf("exit %d, report %+v", r.code, report)
	}
}

func TestTLSOnlyCheckFailsOnAnEndpointNobodyListensOn(t *testing.T) {
	ca := newTestCA(t, "pve-root")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()

	r := tlsOnly("--endpoint", "https://127.0.0.1:"+port, "--ca-file", writeCA(t, ca))

	if r.code != 8 || decodeCheck(t, r).OK {
		t.Errorf("exit %d, stdout %q", r.code, r.stdout)
	}
}

func TestProvidersCheckRefusesWhatItCannotRun(t *testing.T) {
	ca := newTestCA(t, "pve-root")
	caFile := writeCA(t, ca)
	env := []string{"HOME=" + t.TempDir()}
	cases := map[string][]string{
		"without --offline":              {"providers", "check", "pve"},
		"--tls-only without an endpoint": {"providers", "check", "--offline", "--tls-only", "--ca-file", caFile},
		"--tls-only without a CA":        {"providers", "check", "--offline", "--tls-only", "--endpoint", "https://pve.lan:8006"},
		"--tls-only with a name":         {"providers", "check", "--offline", "--tls-only", "--endpoint", "https://a:1", "--ca-file", caFile, "pve"},
		"no name":                        {"providers", "check", "--offline"},
		"endpoint flags with a name":     {"providers", "check", "--offline", "pve", "--endpoint", "https://a:1"},
		"an endpoint that is not https":  {"providers", "check", "--offline", "--tls-only", "--endpoint", "http://pve.lan:8006", "--ca-file", caFile, "--json"},
	}
	for name, args := range cases {
		r := providersCheck(env, args...)
		want := exitUsage
		if name == "an endpoint that is not https" {
			want = 8 // a check failure with its reason, not a usage error
		}
		if r.code != want {
			t.Errorf("%s: exit %d (stdout %q, stderr %q), want %d", name, r.code, r.stdout, r.stderr, want)
		}
	}
}

// ---- a named provider, from the configuration file and the secret store -----------

const pveTokenName = "providers/pve/token"

type pveBox struct {
	sandbox
	fake    *pvefake.Fake
	token   string
	options []proxmox.Option
}

func newPVEBox(t *testing.T) *pveBox {
	t.Helper()
	s, _ := keyedSandbox(t)
	fake := pvefake.New(t)
	fake.AddNode("pve1")
	fake.AddNode("pve2")
	fake.AddGuest(pvefake.Guest{Node: "pve1", Type: "qemu", VMID: 100, Name: "web", Status: "running"})
	fake.AddStorage(pvefake.Storage{ID: "local", Node: "pve1", Plugin: "dir", Total: 100, Used: 10})
	fake.SetRole("Discovery", "VM.Audit", "Sys.Audit", "Datastore.Audit")
	token := fake.AddToken("sm@pve", "sm", false)
	fake.Grant("sm@pve", "/", "Discovery", true)

	caFile := filepath.Join(s.dir, "pve-root-ca.pem")
	writeFile(t, caFile, string(fake.CAPEM()))
	base, err := os.ReadFile(s.configFile)
	if err != nil {
		t.Fatal(err)
	}
	s.writeConfig(t, string(base)+"providers:\n  - type: proxmox\n    name: pve\n    endpoint: "+fake.Endpoint()+"\n"+
		"    credential_ref: secret://"+pveTokenName+"\n    ca_file: "+caFile+"\n")
	return &pveBox{
		sandbox: s, fake: fake, token: token,
		options: []proxmox.Option{proxmox.WithHTTPTimeout(2 * time.Second), proxmox.WithNetguardOptions(netguard.WithTestDialer(fake.Dial))},
	}
}

func (b *pveBox) importToken(t *testing.T, value string) {
	t.Helper()
	if r := b.runIn(value+"\n", "secrets", "import", "--offline", "--name", pveTokenName); r.code != 0 {
		t.Fatalf("import: exit %d: %s", r.code, r.stderr)
	}
}

func (b *pveBox) check(args ...string) result {
	args = append([]string{"providers", "check", "--offline"}, args...)
	args = append(args, "--config", b.configFile, "--json")
	r := execRoot(b.env, "", args, newProvidersCmdWith(b.env, b.options))
	r.stdout, r.stderr = b.normalize(r.stdout), b.normalize(r.stderr)
	return r
}

func TestProvidersCheckReadsTheClusterWithTheStoredTokenAndNeverPrintsIt(t *testing.T) {
	b := newPVEBox(t)
	b.importToken(t, b.token)

	r := b.check("pve")

	report := decodeCheck(t, r)
	if r.code != 0 || !report.OK || report.Provider != "pve" || report.Version != "9.0.3" ||
		report.Nodes != 2 || report.Guests != 1 || report.Storages != 1 {
		t.Errorf("exit %d, report %+v, stderr %q", r.code, report, r.stderr)
	}
	secret := strings.SplitN(b.token, "=", 2)[1]
	assertNoSecret(t, secret, r)
	if b.fake.Count("GET", "/cluster/resources") != 1 || b.fake.Count("POST", "") != 0 {
		t.Error("the check must read the cluster once and change nothing")
	}
}

func TestProvidersCheckFailsWithExit8WhenTheTokenIsRejectedAndKeepsItOutOfTheOutput(t *testing.T) {
	b := newPVEBox(t)
	wrong := "sm@pve!sm=0123456789abcdef0123456789abcdef"
	b.importToken(t, wrong)

	r := b.check("pve")

	report := decodeCheck(t, r)
	if r.code != 8 || report.OK || !strings.Contains(report.Problem, "401") {
		t.Errorf("exit %d, report %+v", r.code, report)
	}
	assertNoSecret(t, "0123456789abcdef0123456789abcdef", r)
}

func TestProvidersCheckFailsWithExit8WhenNoTokenWasImported(t *testing.T) {
	b := newPVEBox(t)

	r := b.check("pve")

	report := decodeCheck(t, r)
	if r.code != 8 || report.OK || !strings.Contains(report.Problem, "API token cannot be read") {
		t.Errorf("exit %d, report %+v", r.code, report)
	}
	if b.fake.Count("GET", "/version") != 0 {
		t.Error("the cluster was contacted without a token")
	}
}

func TestProvidersCheckFailsWhenThePVEFirewallBlocksTheCaller(t *testing.T) {
	b := newPVEBox(t)
	b.importToken(t, b.token)
	b.fake.Inject(pvefake.Rule{Method: "GET", PathSuffix: "/version", Fault: pvefake.DropBefore()})

	r := b.check("pve")

	report := decodeCheck(t, r)
	if r.code != 8 || report.OK || !strings.Contains(report.Problem, "Proxmox firewall") {
		t.Errorf("exit %d, report %+v", r.code, report)
	}
}

func TestProvidersCheckFailsWhenTheTokenSeesNoClusterNode(t *testing.T) {
	b := newPVEBox(t)
	b.importToken(t, b.token)
	b.fake.Revoke("sm@pve", "/", "Discovery")

	r := b.check("pve")

	report := decodeCheck(t, r)
	if r.code != 8 || report.OK || !strings.Contains(report.Problem, "Sys.Audit") {
		t.Errorf("exit %d, report %+v", r.code, report)
	}
}

func TestProvidersCheckIsAUsageErrorForAProviderTheFileDoesNotDeclare(t *testing.T) {
	b := newPVEBox(t)

	r := b.check("ghost")

	if r.code != exitUsage || !strings.Contains(r.stderr, "no Proxmox provider named") || !strings.Contains(r.stderr, "ghost") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestProvidersCheckRefusesWhileTheServiceHoldsTheDatabase(t *testing.T) {
	b := newPVEBox(t)
	b.importToken(t, b.token)
	lock, err := database.AcquireDatabaseLock(b.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()

	r := b.check("pve")

	if r.code != exitPrerequisite || !strings.Contains(r.stderr, "stop the service") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestProvidersCommandIsNoLongerHidden(t *testing.T) {
	r := execRoot([]string{"HOME=" + t.TempDir()}, "", []string{"--help"}, newProvidersCmd(nil))

	if !strings.Contains(r.stdout, "providers") {
		t.Errorf("sm --help does not list providers:\n%s", r.stdout)
	}
}
