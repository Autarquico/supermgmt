package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const pveTestSecret = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"

// pveCA is a certificate authority that issues the API certificate of a test host.
type pveCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newPVECA(t *testing.T) pveCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustf(t, err, "ca key")
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Proxmox Virtual Environment"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	mustf(t, err, "ca cert")
	cert, err := x509.ParseCertificate(der)
	mustf(t, err, "parse ca")
	return pveCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// issue signs a server certificate that names exactly the given DNS names and IPs.
func (ca pveCA) issue(t *testing.T, dns []string, ips ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustf(t, err, "leaf key")
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "pve"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: dns,
	}
	for _, ip := range ips {
		tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	mustf(t, err, "leaf cert")
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func leafOf(t *testing.T, c tls.Certificate) *x509.Certificate {
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	mustf(t, err, "parse leaf")
	return leaf
}

func TestTLSServerNameIsTheFirstOfLocalhostLoopbackAndHostnameTheLeafNames(t *testing.T) {
	ca := newPVECA(t)
	layouts := []struct {
		name string
		dns  []string
		ips  []string
		want string
	}{
		{"localhost", []string{"localhost"}, nil, "localhost"},
		{"loopback address only", nil, []string{"127.0.0.1"}, "127.0.0.1"},
		{"hostname only", []string{"pve1"}, nil, "pve1"},
		{"localhost wins over the rest", []string{"pve1", "localhost"}, []string{"127.0.0.1"}, "localhost"},
		{"loopback wins over the hostname", []string{"pve1"}, []string{"10.0.0.2", "127.0.0.1"}, "127.0.0.1"},
		{"a wildcard names the hostname", []string{"*.lan"}, nil, ""},
		{"an fqdn is not the short hostname", []string{"pve1.lan"}, []string{"10.0.0.2"}, ""},
		{"no names at all", nil, nil, ""},
	}
	for _, l := range layouts {
		got, err := tlsServerNameOf(leafOf(t, ca.issue(t, l.dns, l.ips...)), "pve1")
		if l.want == "" {
			if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
				t.Errorf("%s: got %q, err %v; want CAPABILITY_UNAVAILABLE", l.name, got, err)
				continue
			}
			for _, name := range append(append([]string{}, l.dns...), l.ips...) {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("%s: the error does not list %q: %v", l.name, name, err)
				}
			}
			continue
		}
		if err != nil || got != l.want {
			t.Errorf("%s: got %q, err %v; want %q", l.name, got, err, l.want)
		}
	}
}

// pveAPI is the PVE API behind the relay: TLS with cert, GET /version with the token.
type pveAPI struct {
	cert     tls.Certificate
	listener net.Listener
	token    func() string // the token the API accepts

	mu       sync.Mutex
	requests []string // Authorization headers seen
	opened   []ssh.Target
}

func newPVEAPI(t *testing.T, cert tls.Certificate, token func() string) *pveAPI {
	// A loopback socket stands for the relay: the kernel buffers it, as the SSH channel does.
	tcp, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	mustf(t, err, "listen")
	a := &pveAPI{cert: cert, token: token}
	a.listener = tls.NewListener(tcp, &tls.Config{Certificates: []tls.Certificate{cert}})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.requests = append(a.requests, r.Header.Get("Authorization"))
		a.mu.Unlock()
		if r.URL.Path != "/api2/json/version" || r.Header.Get("Authorization") != "PVEAPIToken="+a.token() {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"version":"9.0.3","release":"9.0"}}`)
	})}
	go func() { _ = srv.Serve(a.listener) }()
	t.Cleanup(func() { _ = srv.Close() })
	return a
}

func (a *pveAPI) relay(ctx context.Context, t ssh.Target, _ templates.Relay) (net.Conn, error) {
	a.mu.Lock()
	a.opened = append(a.opened, t)
	a.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, "tcp", a.listener.Addr().String())
}

func (a *pveAPI) authorizations() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.requests...)
}

// pveHostScript makes the admin session of a setting behave like a PVE 9 host
// that keeps its identities between runs.
type pveHostScript struct {
	mu     sync.Mutex
	users  map[string]string
	roles  map[string]string
	tokens map[string]string
	acls   int
	ca     string
}

func quotedArgs(line string) []string {
	parts := strings.Split(line, "'")
	var args []string
	for i := 1; i < len(parts); i += 2 {
		args = append(args, parts[i])
	}
	return args
}

func rowsOf(m map[string]string, idKey, valueKey string) string {
	var rows []string
	for id, v := range m {
		rows = append(rows, fmt.Sprintf(`{%q:%q,%q:%q}`, idKey, id, valueKey, v))
	}
	return "[" + strings.Join(rows, ",") + "]"
}

func scriptPVEHost(admin *fakeNode, caPEM string) *pveHostScript {
	h := &pveHostScript{users: map[string]string{}, roles: map[string]string{}, tokens: map[string]string{}, ca: caPEM}
	sudo := templates.SudoVariantSuffix
	locked := func(f func(c templates.Command) string) func(templates.Command) (transport.Result, error) {
		return func(c templates.Command) (transport.Result, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return transport.Result{Stdout: []byte(f(c))}, nil
		}
	}
	admin.reply(templates.PVEVersionStep+sudo, "pve-manager/9.0.3/abcdef (running kernel: 6.14.8-2-pve)\n")
	admin.reply(templates.SocatPathRead, "/usr/bin/socat\n")
	admin.reply(templates.HostnameRead, "pve1\n")
	admin.reply(templates.PVERootCAStep+sudo, caPEM)
	admin.on(templates.PVEUserListStep+sudo, locked(func(templates.Command) string { return rowsOf(h.users, "userid", "comment") }))
	admin.on(templates.PVERoleListStep+sudo, locked(func(templates.Command) string { return rowsOf(h.roles, "roleid", "privs") }))
	admin.on(templates.PVETokenListStep+sudo, locked(func(templates.Command) string { return rowsOf(h.tokens, "tokenid", "comment") }))
	admin.on(templates.PVEUserAddStep+sudo, locked(func(c templates.Command) string {
		a := quotedArgs(c.Line)
		h.users[a[0]] = a[1]
		return ""
	}))
	admin.on(templates.PVERoleAddStep+sudo, locked(func(c templates.Command) string {
		a := quotedArgs(c.Line)
		h.roles[a[0]] = a[1]
		return ""
	}))
	for _, step := range []string{templates.PVEACLAddUserStep, templates.PVEACLAddTokenStep} {
		admin.on(step+sudo, locked(func(templates.Command) string { h.acls++; return "" }))
	}
	admin.on(templates.PVETokenAddStep+sudo, locked(func(c templates.Command) string {
		a := quotedArgs(c.Line)
		h.tokens[a[1]] = a[2]
		return fmt.Sprintf(`{"full-tokenid":%q,"info":{},"value":%q}`, a[0]+"!"+a[1], pveTestSecret)
	}))
	admin.on(templates.PVETokenRemoveStep+sudo, locked(func(c templates.Command) string {
		delete(h.tokens, quotedArgs(c.Line)[1])
		return ""
	}))
	return h
}

// proxmoxSetting is a setting whose node is a PVE host with an API behind the relay.
type proxmoxSetting struct {
	*setting
	host    *pveHostScript
	api     *pveAPI
	secrets *memSecrets
	ca      pveCA
}

func newProxmoxSetting(t *testing.T, dns []string, ips ...string) *proxmoxSetting {
	t.Helper()
	s := newSetting(t)
	ps := &proxmoxSetting{setting: s, secrets: newMemSecrets(), ca: newPVECA(t)}
	ps.host = scriptPVEHost(s.dialer.as("admin"), ps.ca.pem)
	ps.serve(ps.ca.issue(t, dns, ips...))
	s.handler.secrets = ps.secrets
	return ps
}

// serve puts an API with cert behind the relay.
func (ps *proxmoxSetting) serve(cert tls.Certificate) {
	ps.api = newPVEAPI(ps.t, cert, func() string {
		token, err := ps.secrets.Get(context.Background(), secrets.Ref{Name: "proxmox/web-1"})
		if err != nil {
			return "no token stored"
		}
		return token.Reveal()
	})
	ps.dialer.relay = ps.api.relay
}

func proxmoxSetupParams() map[string]any {
	p := defaultSetup()
	p["proxmox"] = "true"
	return p
}

func (ps *proxmoxSetting) setupProxmox() error {
	ps.t.Helper()
	ps.setupPlan(proxmoxSetupParams())
	return ps.run()
}

func TestProxmoxSetupProvesTLSAndTheAPIBeforeRecordingAnything(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"localhost", "pve1"}, "127.0.0.1")

	mustf(t, ps.setupProxmox(), "setup --proxmox")

	meta, ok := ps.setupCapability()
	if !ok || meta.SetupVersion != 4 || meta.ProxmoxState() == nil {
		t.Fatalf("metadata = %+v", meta)
	}
	px := meta.ProxmoxState()
	if px.CAPEM != ps.ca.pem || px.TokenRef != "secret://proxmox/web-1" || px.TLSServerName != "localhost" ||
		px.RelayPath != "/usr/bin/socat" || !strings.HasSuffix(px.TokenID, "@pve!sm") || px.InstalledAt.IsZero() {
		t.Errorf("proxmox meta = %+v", px)
	}
	stored, err := ps.secrets.Get(context.Background(), secrets.Ref{Name: "proxmox/web-1"})
	mustf(t, err, "stored token")
	if stored.Reveal() != px.TokenID+"="+pveTestSecret {
		t.Error("the stored token is not user@realm!id=secret")
	}
	if got := ps.api.authorizations(); len(got) != 1 || got[0] != "PVEAPIToken="+stored.Reveal() {
		t.Errorf("API requests = %q: want exactly one authenticated GET /version", got)
	}
	for _, target := range ps.api.opened {
		if target.User != "supermgmt" || target.CredentialRef != "secret://ssh/default@1" {
			t.Errorf("relay opened as %+v: want the dedicated account with the pinned key", target)
		}
	}
	if len(ps.api.opened) < 2 {
		t.Errorf("%d relays: one for the handshake and one for the request", len(ps.api.opened))
	}
	created := ps.events("node.proxmox.token_created")
	if len(created) != 1 || created[0].Data["pve_id"] != px.TokenID {
		t.Errorf("token events = %+v", created)
	}
	completed := ps.events("node.setup.completed")
	if len(completed) != 1 {
		t.Fatalf("completion events = %d", len(completed))
	}
	raw, _ := json.Marshal(completed[0].Data["proxmox"])
	if !strings.Contains(string(raw), "type: proxmox\\nname: web-1\\nvia_node: web-1") {
		t.Errorf("completion lacks the provider block: %s", raw)
	}
}

func TestProxmoxSetupKeepsTheSecretOutOfTheAuditTrailAndEveryCommandLine(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"localhost"})
	mustf(t, ps.setupProxmox(), "setup --proxmox")

	all, err := json.Marshal(ps.events())
	mustf(t, err, "events")
	if strings.Contains(string(all), pveTestSecret) {
		t.Error("the token secret is in the audit trail")
	}
	for _, c := range ps.dialer.as("admin").callsCopy() {
		if strings.Contains(c.Line, pveTestSecret) {
			t.Errorf("secret on a command line: %s", c.Template)
		}
	}
}

func TestProxmoxSetupRefusesACertificateThatDoesNotChainToTheHostsCA(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"localhost"})
	ps.serve(newPVECA(t).issue(t, []string{"localhost"})) // another CA signs the API certificate

	err := ps.setupProxmox()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	if got := ps.api.authorizations(); len(got) != 0 {
		t.Errorf("a request carried the token before TLS was proved: %q", got)
	}
	if _, ok := ps.setupCapability(); ok {
		t.Error("capability recorded without a proven handshake")
	}
}

func TestProxmoxSetupRefusesACertificateThatNamesNoneOfTheCandidates(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"pve1.example.com"}, "10.0.0.2")

	err := ps.setupProxmox()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	if !strings.Contains(err.Error(), "pve1.example.com") || !strings.Contains(err.Error(), "10.0.0.2") {
		t.Errorf("the error must list the names found: %v", err)
	}
	if len(ps.api.authorizations()) != 0 {
		t.Error("a request carried the token")
	}
	if _, ok := ps.setupCapability(); ok {
		t.Error("capability recorded")
	}
}

func TestProxmoxSetupFailsWhenTheAPIRejectsTheToken(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"localhost"})
	ps.api = newPVEAPI(t, ps.api.cert, func() string { return "another token" })
	ps.dialer.relay = ps.api.relay

	err := ps.setupProxmox()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	if strings.Contains(err.Error(), pveTestSecret) {
		t.Errorf("the error quotes the token: %v", err)
	}
	if _, ok := ps.setupCapability(); ok {
		t.Error("capability recorded although GET /version failed")
	}
}

func TestProxmoxSetupRepairsALostTokenAndKeepsTheStateOtherwise(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"localhost"})
	mustf(t, ps.setupProxmox(), "first setup")

	// A rerun with the secret in the store creates nothing.
	mustf(t, ps.setupProxmox(), "rerun")
	if got := ps.events("node.proxmox.token_created", "node.proxmox.token_deleted"); len(got) != 1 {
		t.Errorf("token events after a plain rerun = %d, want 1", len(got))
	}

	// The secret is lost: the owned token is deleted and created again.
	ps.secrets.mu.Lock()
	delete(ps.secrets.vals, "proxmox/web-1")
	ps.secrets.mu.Unlock()
	mustf(t, ps.setupProxmox(), "repair")
	if ps.secrets.versions("proxmox/web-1") != 1 {
		t.Error("the token was not stored again")
	}
	if got := ps.events("node.proxmox.token_deleted"); len(got) != 1 {
		t.Errorf("deletion events = %d, want 1", len(got))
	}
	if got := ps.events("node.proxmox.token_created"); len(got) != 2 {
		t.Errorf("creation events = %d, want 2", len(got))
	}
}

func TestASetupWithoutProxmoxKeepsTheProxmoxState(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"localhost"})
	mustf(t, ps.setupProxmox(), "setup --proxmox")
	before, _ := ps.setupCapability()

	ps.setupPlan(defaultSetup())
	mustf(t, ps.run(), "plain rerun")

	after, _ := ps.setupCapability()
	if after.ProxmoxState() == nil || after.ProxmoxState().TokenID != before.ProxmoxState().TokenID {
		t.Errorf("proxmox state after = %+v", after.ProxmoxState())
	}
}

func TestProxmoxSetupOnAHostThatIsNotPVE9ChangesNothing(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"localhost"})
	ps.dialer.as("admin").reply(templates.PVEVersionStep+templates.SudoVariantSuffix, "pve-manager/8.4.1/abc\n")

	err := ps.setupProxmox()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	if got := ps.dialer.as("admin").count("setup.user_add.sudo"); got != 0 || len(ps.host.users) != 0 || ps.secrets.versions("proxmox/web-1") != 0 {
		t.Errorf("something changed: user_add %d, users %v", got, ps.host.users)
	}
}

func TestProxmoxSetupNeedsAStoreAndALowerCaseNodeName(t *testing.T) {
	ps := newProxmoxSetting(t, []string{"localhost"})
	ps.handler.secrets = nil
	ps.setupPlan(proxmoxSetupParams())
	wantError(t, ps.run(), smerr.CodeCapabilityUnavailable, "")

	if _, err := proxmoxSecretName("Web-1"); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("an upper-case node name: %v", err)
	}
	if name, err := proxmoxSecretName("pve-1"); err != nil || name != "proxmox/pve-1" {
		t.Errorf("name %q, err %v", name, err)
	}
}

func TestSetupParameterProxmoxMustBeABoolean(t *testing.T) {
	if _, err := parseSetupRequest(map[string]any{"proxmox": "yes"}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("err = %v", err)
	}
	req, err := parseSetupRequest(map[string]any{"proxmox": "true"})
	if err != nil || !req.Proxmox {
		t.Errorf("req = %+v, err %v", req, err)
	}
	if req, err = parseSetupRequest(map[string]any{}); err != nil || req.Proxmox {
		t.Errorf("absent: %+v, %v", req, err)
	}
}

func (f *fakeNode) callsCopy() []templates.Command {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]templates.Command(nil), f.calls...)
}
