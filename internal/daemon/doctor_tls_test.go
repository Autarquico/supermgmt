package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var tlsDoctorNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func writeTLSDoctorCertificate(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sm.test"},
		NotBefore: notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDoctorTLS_StatusByRemainingValidity(t *testing.T) {
	for _, tt := range []struct {
		name      string
		remaining time.Duration
		want      string
	}{
		{"expired a second ago", -time.Second, checkFail},
		{"expires right now", 0, checkFail},
		{"inside the warning window", 29 * 24 * time.Hour, checkWarn},
		{"exactly thirty days", 30 * 24 * time.Hour, checkWarn},
		{"beyond thirty days", 30*24*time.Hour + time.Second, checkOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			notAfter := tlsDoctorNow.Add(tt.remaining)
			got := TLSCertificateCheck(writeTLSDoctorCertificate(t, notAfter), tlsDoctorNow)

			if got.Name != "tls" || got.Status != tt.want {
				t.Errorf("check = %+v, want status %s", got, tt.want)
			}
			if got.Detail != notAfter.Format(time.RFC3339) {
				t.Errorf("detail = %q, want NotAfter %s", got.Detail, notAfter.Format(time.RFC3339))
			}
		})
	}
}

func TestDoctorTLS_FailsWhenTheCertificateCannotBeRead(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing file": filepath.Join(t.TempDir(), "absent.pem"),
		"no PEM block": garbage,
	} {
		t.Run(name, func(t *testing.T) {
			got := TLSCertificateCheck(path, tlsDoctorNow)

			if got.Name != "tls" || got.Status != checkFail || got.Detail == "" {
				t.Errorf("check = %+v, want a failing tls check with a reason", got)
			}
		})
	}
}
