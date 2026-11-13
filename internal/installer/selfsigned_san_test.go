package installer

import (
	"context"
	"strings"
	"testing"
	"time"
)

const (
	tailscaleIP   = "100.84.213.96"
	tailscaleName = "mgmt.tail1234.ts.net"
)

// reinstall is `sm install server` run again on a host that already has its certificates.
func reinstall(t *testing.T, from *world, o Options) (*world, error) {
	t.Helper()
	w, _, err := reinstallWithOutput(t, from, o)
	return w, err
}

func reinstallWithOutput(t *testing.T, from *world, o Options) (*world, string, error) {
	t.Helper()
	w := newWorld()
	for _, name := range []string{"ca.pem", "ca.key", "server.pem", "server.key"} {
		w.files[tlsDir+name] = from.files[tlsDir+name]
	}
	d, out := w.deps("linux", 0, false)
	err := New(d).Run(context.Background(), o)
	return w, out.String(), err
}

func resign(w *world, sans ...string) error {
	d, _ := w.deps("linux", 0, false)
	_, err := New(d).resignLeaf(Options{Mode: ModeServer}.serverLayout(), sans)
	return err
}

func putMaterial(w *world, m certMaterial) {
	w.files[tlsDir+"ca.pem"], w.files[tlsDir+"ca.key"] = m.CACert, m.CAKey
	w.files[tlsDir+"server.pem"], w.files[tlsDir+"server.key"] = m.Cert, m.Key
}

func TestTLSSANNamesGoIntoTheFirstLeafAndKeepTheOthers(t *testing.T) {
	o := selfSignedOpts("https://mgmt.example.com", false)
	o.TLSSANs = []string{tailscaleIP, "MGMT.Tail1234.ts.net"}
	w, _ := installSelfSigned(t, o)
	for _, name := range []string{tailscaleIP, tailscaleName, "mgmt.example.com", "localhost", "127.0.0.1"} {
		if err := handshake(t, w, name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTLSSANIsRefusedWithoutSelfSigned(t *testing.T) {
	w := newWorld()
	d, _ := w.deps("linux", 0, false)
	o := serverOpts()
	o.TLSSANs = []string{tailscaleIP}
	if got := exitCodeOf(t, New(d).Run(context.Background(), o)); got != ExitInvalid {
		t.Errorf("exit = %d, want %d", got, ExitInvalid)
	}
	if len(w.events) != 0 {
		t.Errorf("a rejected install must change nothing: %v", w.events)
	}
}

func TestTLSSANRefusesWhatIsNotABareIPOrName(t *testing.T) {
	for name, san := range map[string]string{
		"url":               "https://mgmt.example.com",
		"url path":          "mgmt.example.com/x",
		"host and port":     "mgmt.example.com:8443",
		"ip and port":       "100.84.213.96:8443",
		"bracketed ipv6":    "[::1]",
		"whitespace":        "mgmt example.com",
		"padded":            " mgmt.example.com",
		"wildcard":          "*.example.com",
		"malformed ip":      "999.84.213.96",
		"short ip":          "100.84.213",
		"empty":             "",
		"underscore":        "my_host.example.com",
		"label with a dash": "-bad.example.com",
		"empty label":       "a..example.com",
		"zone":              "fe80::1%eth0",
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld()
			d, _ := w.deps("linux", 0, false)
			o := selfSignedOpts("https://mgmt.example.com", false)
			o.TLSSANs = []string{san}
			if got := exitCodeOf(t, New(d).Run(context.Background(), o)); got != ExitInvalid {
				t.Errorf("exit = %d, want %d", got, ExitInvalid)
			}
			if len(w.events) != 0 {
				t.Errorf("a rejected install must change nothing: %v", w.events)
			}
		})
	}
}

func TestTLSSANIsNormalized(t *testing.T) {
	got, err := normalizeSANs([]string{"MGMT.Example.COM", "mgmt.example.com", "::ffff:100.84.213.96", "100.84.213.96", "fe80:0:0:0:0:0:0:1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "mgmt.example.com,100.84.213.96,fe80::1"; strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

func TestReinstallWithANewTLSSANReSignsTheLeafWithTheSameCAAndKey(t *testing.T) {
	first, _ := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", true))
	o := selfSignedOpts("https://mgmt.example.com", true)
	o.TLSSANs = []string{tailscaleIP}
	w, out, err := reinstallWithOutput(t, first, o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "keeps the previous certificate until it is restarted") {
		t.Errorf("the output must say the running service still serves the old leaf:\n%s", out)
	}
	for _, name := range []string{"ca.pem", "ca.key", "server.key"} {
		if string(w.files[tlsDir+name]) != string(first.files[tlsDir+name]) {
			t.Errorf("%s changed", name)
		}
	}
	for _, name := range []string{tailscaleIP, "mgmt.example.com", "localhost", "127.0.0.1"} {
		if err := handshake(t, w, name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := handshake(t, first, tailscaleIP); err == nil {
		t.Error("the first leaf was meant not to cover the new address")
	}
}

func TestReinstallWithoutTLSSANKeepsTheLeaf(t *testing.T) {
	first, _ := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", true))
	w, err := reinstall(t, first, selfSignedOpts("https://mgmt.example.com", true))
	if err != nil {
		t.Fatal(err)
	}
	if string(w.files[tlsDir+"server.pem"]) != string(first.files[tlsDir+"server.pem"]) {
		t.Error("the leaf was re-signed without a new name")
	}
}

func TestReSigningAgainWithTheSameNamesChangesNothing(t *testing.T) {
	w, _ := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", true))
	if err := resign(w, tailscaleIP); err != nil {
		t.Fatal(err)
	}
	signed := string(w.files[tlsDir+"server.pem"])
	w.events = nil
	if err := resign(w, tailscaleIP, "localhost"); err != nil {
		t.Fatal(err)
	}
	if string(w.files[tlsDir+"server.pem"]) != signed || len(w.events) != 0 {
		t.Errorf("a leaf that already covers the names was rewritten: %v", w.events)
	}
}

func TestReSigningAddsToTheNamesTheLeafAlreadyHas(t *testing.T) {
	w, _ := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", true))
	for _, san := range []string{tailscaleIP, tailscaleName} {
		if err := resign(w, san); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{tailscaleIP, tailscaleName, "mgmt.example.com", "localhost", "::1"} {
		if err := handshake(t, w, name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReSigningRefusesMaterialThatIsNotOneSet(t *testing.T) {
	other, _ := installSelfSigned(t, selfSignedOpts("https://other.example.com", true))
	cases := map[string]struct {
		swapped []string
		wantMsg string
	}{
		"a CA key that is not the CA's":     {[]string{"ca.key"}, "is not the key of"},
		"a leaf issued by another CA":       {[]string{"server.pem", "server.key"}, "was not issued by"},
		"a leaf key that is not the leaf's": {[]string{"server.key"}, "does not match"},
	}
	for name, tc := range cases {
		swapped, wantMsg := tc.swapped, tc.wantMsg
		t.Run(name, func(t *testing.T) {
			w, _ := installSelfSigned(t, selfSignedOpts("https://mgmt.example.com", true))
			for _, file := range swapped {
				w.files[tlsDir+file] = other.files[tlsDir+file]
			}
			before := string(w.files[tlsDir+"server.pem"])
			err := resign(w, tailscaleIP)
			if got := exitCodeOf(t, err); got != ExitConfiguration || !strings.Contains(err.Error(), wantMsg) {
				t.Errorf("exit = %d, want %d with %q: %v", got, ExitConfiguration, wantMsg, err)
			}
			if string(w.files[tlsDir+"server.pem"]) != before {
				t.Error("a refused re-signing must leave the leaf as it was")
			}
		})
	}
}

func TestReSigningRefusesAnExpiredCA(t *testing.T) {
	w := newWorld()
	old, err := generateSelfSigned("mgmt.example.com", nil, testNow.Add(-11*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	putMaterial(w, old)
	if got := exitCodeOf(t, resign(w, tailscaleIP)); got != ExitConfiguration {
		t.Errorf("exit = %d, want %d", got, ExitConfiguration)
	}
}

func TestAReSignedLeafNeverOutlivesItsCA(t *testing.T) {
	w := newWorld()
	aged, err := generateSelfSigned("mgmt.example.com", nil, testNow.Add(-8*365*24*time.Hour)) // the CA has two years left
	if err != nil {
		t.Fatal(err)
	}
	putMaterial(w, aged)
	if err := resign(w, tailscaleIP); err != nil {
		t.Fatal(err)
	}
	cas, err := parseCertificates(w.files[tlsDir+"ca.pem"])
	if err != nil {
		t.Fatal(err)
	}
	leaves, err := parseCertificates(w.files[tlsDir+"server.pem"])
	if err != nil {
		t.Fatal(err)
	}
	ca, leaf := cas[0], leaves[0]
	if leaf.NotAfter.After(ca.NotAfter) || !leaf.NotAfter.After(testNow) {
		t.Errorf("leaf expires %s, CA %s, now %s", leaf.NotAfter, ca.NotAfter, testNow)
	}
}
