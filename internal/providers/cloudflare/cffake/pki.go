package cffake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// The certificates are valid over a fixed, wide range so the fake never reads
// the wall clock.
var (
	validFrom  = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// newPKI makes a throwaway CA and a server certificate for ServerIP signed by
// it, and returns the certificate and the CA in PEM.
func newPKI(t testing.TB) (tls.Certificate, []byte) {
	t.Helper()
	caKey := newKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cffake root ca"},
		NotBefore: validFrom, NotAfter: validUntil,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER := sign(t, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := newKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "cffake"},
		NotBefore: validFrom, NotAfter: validUntil,
		IPAddresses: []net.IP{net.ParseIP(ServerIP)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER := sign(t, leafTmpl, ca, &leafKey.PublicKey, caKey)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
