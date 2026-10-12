package installer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
)

// Validity of the generated certificates. There is no renewal flow, so the
// leaf outlives a typical appliance; clients trust the CA, not the leaf.
const (
	selfSignedCAValidity   = 10 * 365 * 24 * time.Hour
	selfSignedLeafValidity = 5 * 365 * 24 * time.Hour
	selfSignedBackdate     = time.Hour
	caFileName             = "ca.pem"
)

// tlsFiles are the paths of the generated certificate material (ADR-0026).
type tlsFiles struct{ Dir, CACert, CAKey, Cert, Key string }

func selfSignedFiles(l layout) tlsFiles {
	dir := filepath.Join(l.ConfigDir, "tls")
	return tlsFiles{
		Dir: dir, CACert: filepath.Join(dir, caFileName), CAKey: filepath.Join(dir, "ca.key"),
		Cert: filepath.Join(dir, "server.pem"), Key: filepath.Join(dir, "server.key"),
	}
}

// resolveSelfSigned is resolveServer for `--tls self-signed`: direct TLS with
// the leaf the installer is about to generate, so no pair is read yet.
func resolveSelfSigned(o Options, l layout) (serverSettings, error) {
	if o.CertFile != "" || o.KeyFile != "" {
		return serverSettings{}, fail(ExitInvalid, "--tls-cert and --tls-key conflict with --tls self-signed")
	}
	if len(o.TrustedProxies) > 0 {
		return serverSettings{}, fail(ExitInvalid, "--trusted-proxy applies only to --tls proxy")
	}
	publicURL := strings.TrimRight(o.PublicURL, "/")
	if _, err := publicHost(publicURL); err != nil {
		return serverSettings{}, err
	}
	f := selfSignedFiles(l)
	return serverSettings{
		Name: firstNonEmpty(o.InstanceName, "supermgmt"), Listen: firstNonEmpty(o.Listen, defaultDirectListen),
		PublicURL: publicURL, TLS: config.TLSDirect, CertFile: f.Cert, KeyFile: f.Key,
	}, nil
}

// certMaterial is a CA and a server leaf, PEM encoded.
type certMaterial struct{ CACert, CAKey, Cert, Key []byte }

// generateSelfSigned creates an ECDSA P-256 CA and a leaf it signs, valid for
// host (a DNS name or an IP) plus the loopback names.
func generateSelfSigned(host string, now time.Time) (certMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certMaterial{}, fmt.Errorf("generate CA key: %w", err)
	}
	caTpl, err := caTemplate(host, now)
	if err != nil {
		return certMaterial{}, err
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return certMaterial{}, fmt.Errorf("sign CA certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return certMaterial{}, fmt.Errorf("parse CA certificate: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certMaterial{}, fmt.Errorf("generate server key: %w", err)
	}
	leafTpl, err := leafTemplate(host, now)
	if err != nil {
		return certMaterial{}, err
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return certMaterial{}, fmt.Errorf("sign server certificate: %w", err)
	}
	caKeyPEM, err := encodeKey(caKey)
	if err != nil {
		return certMaterial{}, err
	}
	leafKeyPEM, err := encodeKey(leafKey)
	if err != nil {
		return certMaterial{}, err
	}
	return certMaterial{CACert: encodeCert(caDER), CAKey: caKeyPEM, Cert: encodeCert(leafDER), Key: leafKeyPEM}, nil
}

func caTemplate(host string, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "SuperMgmt CA (" + host + ")"},
		NotBefore: now.Add(-selfSignedBackdate), NotAfter: now.Add(selfSignedCAValidity),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil
}

func leafTemplate(host string, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	dns, ips := subjectAltNames(host)
	return &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-selfSignedBackdate), NotAfter: now.Add(selfSignedLeafValidity),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: dns, IPAddresses: ips,
	}, nil
}

// subjectAltNames lists host and the loopback names the installer's own
// readiness probe and local administration use, without duplicates.
func subjectAltNames(host string) (dns []string, ips []net.IP) {
	names := []string{host, "localhost", "127.0.0.1", "::1"}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	return dns, ips
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// fingerprint is the colon-separated SHA-256 of a PEM certificate's DER form.
func fingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate in PEM data")
	}
	sum := sha256.Sum256(block.Bytes)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":"), nil
}

// ensureSelfSigned writes the CA and server certificate unless a server
// certificate is already in place; existing material is never regenerated.
func (in *Installer) ensureSelfSigned(l layout, s serverSettings) error {
	f := selfSignedFiles(l)
	if in.d.Files.Exists(f.Cert) {
		in.say("keeping existing certificate %s", f.Cert)
		return nil
	}
	host, err := publicHost(s.PublicURL)
	if err != nil {
		return err
	}
	m, err := generateSelfSigned(host, in.d.Clock.Now())
	if err != nil {
		return failWrap(ExitCreation, "generate self-signed certificates", err)
	}
	return in.writeSelfSigned(f, m)
}

func (in *Installer) writeSelfSigned(f tlsFiles, m certMaterial) error {
	svc := Owner{User: ServiceUser, Group: ServiceUser}
	root := Owner{User: "root", Group: "root"}
	if err := in.d.Files.MkdirAll(f.Dir, 0o750, Owner{User: "root", Group: ServiceUser}); err != nil {
		return failWrap(ExitCreation, "create "+f.Dir, err)
	}
	files := []struct {
		path  string
		data  []byte
		mode  fs.FileMode
		owner Owner
	}{
		{f.CAKey, m.CAKey, 0o600, root},
		{f.CACert, m.CACert, 0o644, root},
		{f.Key, m.Key, 0o600, svc},
		{f.Cert, m.Cert, 0o644, root},
	}
	for _, file := range files {
		if err := in.d.Files.WriteFile(file.path, file.data, file.mode, file.owner); err != nil {
			return failWrap(ExitConfiguration, "write "+file.path, err)
		}
	}
	return nil
}

// printCA tells the operator how clients come to trust this server.
func (in *Installer) printCA(l layout) error {
	f := selfSignedFiles(l)
	pemData, err := in.d.Files.ReadFile(f.CACert)
	if err != nil {
		return failWrap(ExitConfiguration, "read CA certificate", err)
	}
	fp, err := fingerprint(pemData)
	if err != nil {
		return failWrap(ExitConfiguration, "fingerprint CA certificate", err)
	}
	in.say("CA certificate: %s\nSHA-256 fingerprint: %s\nCopy the CA to each client and run `sm login --ca-file <ca.pem>`.\n%s", f.CACert, fp, strings.TrimSpace(string(pemData)))
	return nil
}
