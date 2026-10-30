package pveid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCertPEM is a self-signed certificate; isCA decides whether it is a CA.
func testCertPEM(t testing.TB, isCA bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Proxmox Virtual Environment"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testCA(t testing.TB) string { return testCertPEM(t, true) }

func TestParseCAPEMTakesExactlyOneCACertificate(t *testing.T) {
	ca := testCA(t)
	if _, canonical, err := ParseCAPEM([]byte("\n" + ca + "\n\n")); err != nil || canonical != ca {
		t.Fatalf("a CA with white space around it: %v", err)
	}
	notCA := testCertPEM(t, false)
	for name, in := range map[string]string{
		"empty":      "",
		"two":        ca + ca,
		"leading":    "x\n" + ca,
		"trailing":   ca + "x",
		"not a CA":   notCA,
		"wrong type": strings.ReplaceAll(ca, "CERTIFICATE", "PRIVATE KEY"),
		"headers":    strings.Replace(ca, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n", 1),
		"too big":    ca + strings.Repeat(" ", maxCAPEM),
	} {
		if _, _, err := ParseCAPEM([]byte(in)); !errors.Is(err, ErrNotACA) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestOwnershipReadsOfUsersAndRoles(t *testing.T) {
	users := []byte(`[{"userid":"sm-ab12@pve","comment":"supermgmt install ab12"},{"userid":"sm-cd34@pve","comment":"someone else"}]`)
	for user, want := range map[string][2]bool{"sm-ab12@pve": {true, true}, "sm-cd34@pve": {true, false}, "sm-ef56@pve": {false, false}} {
		present, owned, err := ParseOwnedUser(users, user)
		if err != nil || present != want[0] || owned != want[1] {
			t.Errorf("%s: present %v owned %v err %v", user, present, owned, err)
		}
	}
	privs, present, err := ParseRolePrivileges([]byte(`[{"roleid":"R","privs":"VM.Audit,Sys.Audit"}]`), "R")
	if err != nil || !present || strings.Join(privs, ",") != "Sys.Audit,VM.Audit" {
		t.Errorf("role: %v %v %v", privs, present, err)
	}
	if _, _, err := ParseRolePrivileges([]byte(`{`), "R"); !errors.Is(err, ErrUnreadable) {
		t.Errorf("unreadable role list: %v", err)
	}
}
