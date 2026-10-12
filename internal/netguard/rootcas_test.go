package netguard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	validFrom  = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// privateCAServer serves TLS for the IP 10.0.0.9 with a leaf signed by a
// throwaway CA, and returns that CA as a pool.
func privateCAServer(t *testing.T, h http.Handler) (*reaching, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: validFrom, NotAfter: validUntil,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "pve"},
		NotBefore: validFrom, NotAfter: validUntil,
		IPAddresses: []net.IP{net.ParseIP("10.0.0.9")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &reaching{target: srv.Listener.Addr().String()}, pool
}

func TestWithRootCAsTrustsAPrivateCAAndKeepsTheFilter(t *testing.T) {
	r, pool := privateCAServer(t, okHandler("private"))
	allow := Allow{AllowAllPrivate: true}

	body, err := get(NewClient(allow, nil, testTimeout, testMaxBody, WithTestDialer(r.dial), WithRootCAs(pool)), "https://10.0.0.9/")
	if err != nil || body != "private" {
		t.Fatalf("private CA must be trusted: %q, %v", body, err)
	}
	if _, err := get(NewClient(allow, nil, testTimeout, testMaxBody, WithTestDialer(r.dial)), "https://10.0.0.9/"); err == nil {
		t.Fatal("without WithRootCAs the private CA must not be trusted")
	}
	if _, err := get(NewClient(Allow{}, nil, testTimeout, testMaxBody, WithTestDialer(r.dial), WithRootCAs(pool)), "https://10.0.0.9/"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("private range without allowlist: err = %v, want ErrBlocked", err)
	}
}

func TestWithRootCAsKeepsRedirectsRefused(t *testing.T) {
	r, pool := privateCAServer(t, http.RedirectHandler("/elsewhere", http.StatusFound))
	client := NewClient(Allow{AllowAllPrivate: true}, nil, testTimeout, testMaxBody, WithTestDialer(r.dial), WithRootCAs(pool))
	if _, err := get(client, "https://10.0.0.9/"); !errors.Is(err, ErrRedirect) {
		t.Fatalf("err = %v, want ErrRedirect", err)
	}
}
