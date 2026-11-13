package installer

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/config"
)

// selfSigned turns the host into a self-signed install: direct TLS with the generated CA and leaf.
func (h *uhost) selfSigned(t *testing.T) certMaterial {
	t.Helper()
	l := applianceLayout()
	f := selfSignedFiles(l)
	m, err := generateSelfSigned("sm.example.com", nil, testNow)
	if err != nil {
		t.Fatal(err)
	}
	h.dirs[f.Dir] = true
	for path, data := range map[string][]byte{f.CACert: m.CACert, f.CAKey: m.CAKey, f.Cert: m.Cert, f.Key: m.Key} {
		h.put(path, string(data))
	}
	cfg, err := renderServerConfig(l, serverSettings{
		Name: "supermgmt", Listen: "0.0.0.0:8443", PublicURL: "https://sm.example.com", TLS: config.TLSDirect,
		CertFile: f.Cert, KeyFile: f.Key,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.put(l.ConfigFile, string(cfg))
	return m
}

func (h *uhost) upgradeWith(sans ...string) error {
	o := h.upgradeOpts()
	o.TLSSANs = sans
	return New(h.deps()).upgrade(context.Background(), o, defaultHooks())
}

// covers says whether a client that trusts only the installed CA accepts the installed leaf for name.
func (h *uhost) covers(t *testing.T, name string) bool {
	t.Helper()
	f := selfSignedFiles(applianceLayout())
	return handshakePEM(t, []byte(h.content(f.CACert)), []byte(h.content(f.Cert)), []byte(h.content(f.Key)), name) == nil
}

func TestUpgrade_TLSSANReSignsTheLeafWithTheSameCAWhileTheServiceIsStopped(t *testing.T) {
	h := newUHost(t)
	before := h.selfSigned(t)
	f := selfSignedFiles(applianceLayout())
	if err := h.upgradeWith(tailscaleIP, tailscaleName); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.out.String())
	}
	for _, name := range []string{tailscaleIP, tailscaleName, "sm.example.com", "localhost", "127.0.0.1"} {
		if !h.covers(t, name) {
			t.Errorf("the leaf does not cover %s", name)
		}
	}
	if strings.Contains(h.out.String(), "keeps the previous certificate") {
		t.Error("the install-server hint printed during an upgrade, which restarts the service itself")
	}
	if h.content(f.CACert) != string(before.CACert) || h.content(f.CAKey) != string(before.CAKey) || h.content(f.Key) != string(before.Key) {
		t.Error("the CA, its key or the server key changed")
	}
	stopped, resigned, started := h.index("waitstopped "), h.index("write "+f.Cert), h.index("start ")
	if stopped < 0 || resigned < stopped || started < resigned {
		t.Errorf("the leaf must be re-signed after the stop and before the start: %v", h.events)
	}
	if h.live() != binV2 || !h.running || h.startedAs != binV2 {
		t.Errorf("live %q running %t as %q", h.live(), h.running, h.startedAs)
	}
	if st, ok := h.state(); !ok || st.Phase != upDone || strings.Join(st.TLSSANs, ",") != tailscaleIP+","+tailscaleName {
		t.Errorf("state = %+v", st)
	}
	h.noViolations(t)
}

func TestUpgrade_WithoutTLSSANTheLeafIsLeftAlone(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	f := selfSignedFiles(applianceLayout())
	leaf := h.content(f.Cert)
	if err := h.upgradeWith(); err != nil {
		t.Fatal(err)
	}
	if h.content(f.Cert) != leaf {
		t.Error("the leaf was re-signed without --tls-san")
	}
}

func TestUpgrade_SameBuildWithTLSSANReSignsAndRestarts(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	l := applianceLayout()
	h.put("/usr/local/src/sm-new", binV1)
	if err := h.upgradeWith(tailscaleIP); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.out.String())
	}
	if !h.covers(t, tailscaleIP) || !h.covers(t, "sm.example.com") {
		t.Error("the leaf must cover the new and the old names")
	}
	if h.index("stop ") < 0 || h.index("start ") < 0 || !h.running {
		t.Errorf("the service must be stopped and started again: %v", h.events)
	}
	if h.live() != binV1 || h.Exists(l.Binary+".new") || h.Exists(l.Binary+".prev") {
		t.Errorf("the binary is untouched, and no staged or previous copy is left: live %q", h.live())
	}
	if st, ok := h.state(); !ok || st.Phase != upDone {
		t.Errorf("state = %+v", st)
	}
	if !strings.Contains(h.out.String(), "is unchanged") {
		t.Errorf("the report must say the binary is unchanged:\n%s", h.out.String())
	}
	h.noViolations(t)
}

func TestUpgrade_SameBuildWithoutTLSSANStillExitsEarly(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	h.put("/usr/local/src/sm-new", binV1)
	if err := h.upgradeWith(); err != nil {
		t.Fatal(err)
	}
	if h.index("stop ") >= 0 || !strings.Contains(h.out.String(), "nothing to upgrade") {
		t.Errorf("events %v\n%s", h.events, h.out.String())
	}
}

func TestUpgrade_TLSSANIsRefusedWhenTheInstallIsNotSelfSigned(t *testing.T) {
	h := newUHost(t) // the default fake serves behind a proxy
	if got := exitCodeOf(t, h.upgradeWith(tailscaleIP)); got != ExitInvalid {
		t.Errorf("exit = %d, want %d", got, ExitInvalid)
	}
	if h.index("stop ") >= 0 || h.live() != binV1 {
		t.Errorf("a refused upgrade must change nothing: %v", h.events)
	}
	if _, ok := h.state(); ok {
		t.Error("a refused upgrade must leave no state")
	}
}

func TestUpgrade_TLSSANIsRefusedForADirectInstallWithItsOwnCertificate(t *testing.T) {
	h := newUHost(t)
	cfg, err := renderServerConfig(applianceLayout(), serverSettings{
		Name: "supermgmt", Listen: "0.0.0.0:8443", PublicURL: "https://sm.example.com", TLS: config.TLSDirect,
		CertFile: "/etc/ssl/own.pem", KeyFile: "/etc/ssl/own.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	h.put(applianceLayout().ConfigFile, string(cfg))
	if got := exitCodeOf(t, h.upgradeWith(tailscaleIP)); got != ExitInvalid {
		t.Errorf("exit = %d, want %d", got, ExitInvalid)
	}
}

func TestUpgrade_AMalformedTLSSANIsRefusedBeforeAnythingHappens(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	if got := exitCodeOf(t, h.upgradeWith("https://100.84.213.96")); got != ExitInvalid {
		t.Errorf("exit = %d, want %d", got, ExitInvalid)
	}
	if len(h.events) != 0 {
		t.Errorf("events: %v", h.events)
	}
}

func TestUpgrade_AResumeCarriesItsOwnNamesWithoutTheFlag(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	h.seedUpgrade(t, upgradeState{Phase: upPrepared, TLSSANs: []string{tailscaleIP}}, binV2)
	h.put(applianceLayout().Binary+".new", binV2)
	if err := h.upgradeWith(); err != nil {
		t.Fatalf("resume: %v\n%s", err, h.out.String())
	}
	if !h.covers(t, tailscaleIP) {
		t.Error("the resumed upgrade must still add the names it carries")
	}
	h.noViolations(t)
}

func TestUpgrade_AResumeAcceptsTheSameNamesInAnyOrder(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	h.seedUpgrade(t, upgradeState{Phase: upPrepared, TLSSANs: []string{tailscaleName, tailscaleIP}}, binV2)
	h.put(applianceLayout().Binary+".new", binV2)
	if err := h.upgradeWith(tailscaleIP, tailscaleName); err != nil {
		t.Fatalf("resume: %v\n%s", err, h.out.String())
	}
}

func TestUpgrade_AResumeWithOtherNamesIsRefused(t *testing.T) {
	cases := map[string][]string{
		"different names": {"10.0.0.9"},
		"more names":      {tailscaleIP, "10.0.0.9"},
	}
	for name, asked := range cases {
		t.Run(name, func(t *testing.T) {
			h := newUHost(t)
			h.selfSigned(t)
			h.seedUpgrade(t, upgradeState{Phase: upPrepared, TLSSANs: []string{tailscaleIP}}, binV2)
			h.put(applianceLayout().Binary+".new", binV2)
			if got := exitCodeOf(t, h.upgradeWith(asked...)); got != ExitInvalid {
				t.Errorf("exit = %d, want %d", got, ExitInvalid)
			}
			if h.index("stop ") >= 0 {
				t.Errorf("a refused resume must change nothing: %v", h.events)
			}
		})
	}
}

func TestUpgrade_AResumeOfAnUpgradeWithoutNamesRefusesNewOnes(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	h.seedUpgrade(t, upgradeState{Phase: upPrepared}, binV2)
	h.put(applianceLayout().Binary+".new", binV2)
	if got := exitCodeOf(t, h.upgradeWith(tailscaleIP)); got != ExitInvalid {
		t.Errorf("exit = %d, want %d", got, ExitInvalid)
	}
}

func TestUpgradeAppliance_ForwardsTLSSANNormalized(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	o := p.upgradeOpts()
	o.TLSSANs = []string{tailscaleIP, "MGMT.Tail1234.ts.net"}
	if err := p.run(o, fastHooks(), false); err != nil {
		t.Fatal(err)
	}
	want := []string{"900", stagedBinary, "install", "upgrade", "--binary", stagedBinary, "--tls-san", tailscaleIP, "--tls-san", tailscaleName}
	if !slices.Equal(p.upgrades[0].argv, want) {
		t.Errorf("argv = %v, want %v", p.upgrades[0].argv, want)
	}
}

func TestUpgradeAppliance_AMalformedTLSSANNeverReachesTheContainer(t *testing.T) {
	p := newPVEWrap(t)
	p.mustInstall(t)
	o := p.upgradeOpts()
	o.TLSSANs = []string{"*.example.com"}
	if got := exitCodeOf(t, p.run(o, fastHooks(), false)); got != ExitInvalid {
		t.Errorf("exit = %d, want %d", got, ExitInvalid)
	}
	if len(p.upgrades) != 0 {
		t.Errorf("the container was asked to upgrade: %v", p.upgrades)
	}
}

func TestUpgrade_ABrokenCAIsRefusedBeforeTheServiceIsStopped(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	f := selfSignedFiles(applianceLayout())
	foreign, err := generateSelfSigned("other.example.com", nil, testNow)
	if err != nil {
		t.Fatal(err)
	}
	h.put(f.CAKey, string(foreign.CAKey))
	if got := exitCodeOf(t, h.upgradeWith(tailscaleIP)); got != ExitConfiguration {
		t.Errorf("exit = %d, want %d", got, ExitConfiguration)
	}
	if h.index("stop ") >= 0 {
		t.Errorf("a certificate problem must not stop the service: %v", h.events)
	}
	if _, ok := h.state(); ok {
		t.Error("nothing must be recorded")
	}
	if h.content(applianceLayout().Binary) != binV1 {
		t.Error("the installed binary must be untouched")
	}
}

func TestUpgrade_AResumeRevalidatesTheNamesItCarries(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	h.seedUpgrade(t, upgradeState{Phase: upSwapped, TLSSANs: []string{"*.evil.example"}}, binV2)
	h.put(applianceLayout().Binary, binV2)
	if got := exitCodeOf(t, h.upgradeWith()); got != ExitConfiguration {
		t.Errorf("exit = %d, want %d", got, ExitConfiguration)
	}
	if h.covers(t, "x.evil.example") {
		t.Error("a name that fails validation must never be signed")
	}
}

func TestUpgrade_AResumeTrustsNamesOnlyFromARootOwnedState(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	h.seedUpgrade(t, upgradeState{Phase: upSwapped, TLSSANs: []string{"evil.example"}}, binV2)
	h.put(applianceLayout().Binary, binV2)
	h.owners = map[string]int{applianceLayout().DataDir + "/" + upgradeStateFile: 999}
	if got := exitCodeOf(t, h.upgradeWith()); got != ExitConfiguration {
		t.Errorf("exit = %d, want %d", got, ExitConfiguration)
	}
	if h.covers(t, "evil.example") {
		t.Error("a state the service account could have written must not reach the CA")
	}
}

func TestUpgrade_AStateSwappedAfterItWasReadStillCountsAsTheServiceAccountsFile(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	statePath := applianceLayout().DataDir + "/" + upgradeStateFile
	h.seedUpgrade(t, upgradeState{Phase: upSwapped, TLSSANs: []string{"evil.example"}}, binV2)
	h.put(applianceLayout().Binary, binV2)
	h.owners = map[string]int{statePath: 999}
	h.afterRead = func(p string) { h.owners[p] = 0 } // the service account swaps in a root-owned file
	if got := exitCodeOf(t, h.upgradeWith()); got != ExitConfiguration {
		t.Errorf("exit = %d, want %d", got, ExitConfiguration)
	}
	if h.covers(t, "evil.example") {
		t.Error("the owner must come from the file that was read, not from a later look at the path")
	}
}

func TestUpgrade_AbandoningAnUpgradeKeepsItsNames(t *testing.T) {
	h := newUHost(t)
	h.selfSigned(t)
	h.seedUpgrade(t, upgradeState{Phase: upPrepared, TLSSANs: []string{tailscaleIP}}, binV2)
	h.put("/usr/local/src/sm-new", binV2+";another build")
	if err := h.upgradeWith(); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.out.String())
	}
	if !h.covers(t, tailscaleIP) {
		t.Error("the names of the abandoned upgrade must still be applied")
	}
}
