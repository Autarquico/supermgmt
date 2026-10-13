package installer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fuzzInputLimit is far beyond anything the installer reads from a guest, a journal or a report.
const fuzzInputLimit = 1 << 20

func fuzzSkipOversize(t *testing.T, n int) {
	t.Helper()
	if n > fuzzInputLimit {
		t.Skip("input beyond the size the installer ever reads")
	}
}

func fuzzSeedCertificatePEM(f *testing.F) []byte {
	f.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fuzz seed"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func FuzzParseGuestConfig(f *testing.F) {
	f.Add("arch: amd64\nfeatures: nesting=1,keyctl=1\nnet0: name=eth0,bridge=vmbr0,ip=dhcp\nunprivileged: 1\n")
	f.Add("")
	f.Add(": \n: : :\nfeatures: =\nfeatures: a=b=c,,\n")
	f.Fuzz(func(t *testing.T, config string) {
		fuzzSkipOversize(t, len(config))
		if parseGuestConfig(config).Features == nil {
			t.Fatal("Features must never be nil")
		}
	})
}

func FuzzParseACLName(f *testing.F) {
	f.Add("/vms/900|PVEVMAdmin|u:sm@pve")
	f.Add("/|R|t:sm@pve!tok")
	f.Add("||")
	f.Add("a|b|c|d")
	f.Fuzz(func(t *testing.T, name string) {
		fuzzSkipOversize(t, len(name))
		acl, ok := parseACLName(name)
		if !ok {
			return
		}
		if again, ok := parseACLName(aclName(acl)); !ok || again != acl {
			t.Fatalf("%q parsed to %+v, which does not round-trip (%+v, %v)", name, acl, again, ok)
		}
	})
}

func FuzzParseSemver(f *testing.F) {
	for _, s := range []string{"v1.2.3", "1.2.3-rc.1+build", "0.0.0", "", "v", "1.2", "99999999999999999999.0.0", "1.2.3-", "1.2.3-..."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, version string) {
		fuzzSkipOversize(t, len(version))
		first, firstOK := parseSemver(version)
		second, secondOK := parseSemver(version)
		if firstOK != secondOK || !reflect.DeepEqual(first, second) {
			t.Fatalf("parseSemver(%q) is not deterministic", version)
		}
	})
}

func FuzzOpenInstallerJournal(f *testing.F) {
	f.Add([]byte(`{"seq":1,"step":"S0","resource":"journal","id":"ab12cd34","phase":"begun"}` + "\n"))
	f.Add([]byte(`{"seq":1,"step":"S0","resou`))
	f.Add([]byte("\n\n{}\n{not json}\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzSkipOversize(t, len(data))
		w := newAW(t)
		dir := journalDirFor("ab12cd34")
		w.files[dir+"/"+journalFile] = data
		j, err := openJournal(w, dir)
		if err != nil {
			return
		}
		_ = j.toUndo()
		if _, err := openJournal(w, dir); err != nil {
			t.Fatalf("a journal openJournal accepted must reopen after its repair: %v", err)
		}
	})
}

func FuzzDecodeUpgradeState(f *testing.F) {
	f.Add([]byte(`{"phase":"backed_up","old_sha256":"aa","new_sha256":"bb","schema_before":3}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzSkipOversize(t, len(data))
		w := newAW(t)
		u := &upgrader{d: w.deps(false), t: upgradeTarget{l: applianceLayout()}}
		w.files[u.t.statePath()] = data
		st, found, err := u.loadState()
		if err != nil && found {
			t.Fatal("an unreadable state must not be reported as found")
		}
		if err == nil {
			_ = st.beforeSwap()
		}
	})
}

func FuzzParseCertificates(f *testing.F) {
	f.Add(fuzzSeedCertificatePEM(f))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzSkipOversize(t, len(data))
		if certs, err := parseCertificates(data); err == nil {
			for _, c := range certs {
				if c == nil {
					t.Fatal("nil certificate without error")
				}
			}
		}
	})
}

func FuzzReadDoctorReport(f *testing.F) {
	f.Add(`{"ok":true,"format_version":1,"database_schema_version":5,"checks":[]}`)
	f.Add(`{"ok":true,"checks":[{"name":"schema","status":"ok","detail":"version 3 matches this binary"}]}`)
	f.Add(`{"checks":[{"name":"schema","detail":"schema version 99999999999999999999 is behind"}]}`)
	f.Add(`{"format_version":1}`)
	f.Add("not json")
	f.Fuzz(func(t *testing.T, report string) {
		fuzzSkipOversize(t, len(report))
		u := &upgrader{d: Deps{Runner: doctorStub(report)}, t: upgradeTarget{l: applianceLayout()}}
		version, err := u.schemaVersion(context.Background(), applianceLayout().Binary)
		if err == nil && !strings.Contains(report, "schema") {
			t.Fatalf("schema %d read from a report that never mentions one", version)
		}
	})
}
