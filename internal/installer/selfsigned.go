package installer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

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
	sans, err := normalizeSANs(o.TLSSANs)
	if err != nil {
		return serverSettings{}, err
	}
	publicURL := strings.TrimRight(o.PublicURL, "/")
	if _, err := publicHost(publicURL); err != nil {
		return serverSettings{}, err
	}
	f := selfSignedFiles(l)
	return serverSettings{
		Name: firstNonEmpty(o.InstanceName, "supermgmt"), Listen: firstNonEmpty(o.Listen, defaultDirectListen),
		PublicURL: publicURL, TLS: config.TLSDirect, CertFile: f.Cert, KeyFile: f.Key, SANs: sans,
	}, nil
}

// certMaterial is a CA and a server leaf, PEM encoded.
type certMaterial struct{ CACert, CAKey, Cert, Key []byte }

// generateSelfSigned creates an ECDSA P-256 CA and a leaf it signs, valid for
// host (a DNS name or an IP), the loopback names and any extra names.
func generateSelfSigned(host string, extra []string, now time.Time) (certMaterial, error) {
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
	dns, ips := subjectAltNames(host, extra...)
	leafTpl, err := leafTemplate(host, dns, ips, now)
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

func leafTemplate(commonName string, dns []string, ips []net.IP, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-selfSignedBackdate), NotAfter: now.Add(selfSignedLeafValidity),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: dns, IPAddresses: ips,
	}, nil
}

// subjectAltNames lists host, the loopback names the installer's own readiness
// probe and local administration use, and the extra names, without duplicates.
func subjectAltNames(host string, extra ...string) (dns []string, ips []net.IP) {
	return splitNames(append([]string{host, "localhost", "127.0.0.1", "::1"}, extra...))
}

// splitNames sorts names into DNS names and IPs, dropping repeats (an IP
// repeats when it is written two ways).
func splitNames(names []string) (dns []string, ips []net.IP) {
	seen := map[string]bool{}
	for _, n := range names {
		key := n
		ip := net.ParseIP(n)
		if ip != nil {
			key = ip.String()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	return dns, ips
}

// normalizeSANs validates the --tls-san values (a bare IP or DNS name each) and
// returns them canonical and without repeats. A URL, a port, a wildcard,
// whitespace or a malformed IP is refused rather than guessed at.
func normalizeSANs(raw []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, r := range raw {
		name, err := normalizeSAN(r)
		if err != nil {
			return nil, fail(ExitInvalid, "--tls-san %q: %v", r, err)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

func normalizeSAN(v string) (string, error) {
	switch {
	case v == "":
		return "", errors.New("is empty")
	case strings.ContainsFunc(v, unicode.IsSpace):
		return "", errors.New("must not contain whitespace")
	case strings.Contains(v, "/"):
		return "", errors.New("must be a bare IP address or DNS name, not a URL")
	case strings.Contains(v, "*"):
		return "", errors.New("wildcards are not supported")
	}
	if ip := net.ParseIP(v); ip != nil {
		return ip.String(), nil
	}
	if strings.ContainsAny(v, ":[]%") {
		return "", errors.New("is not a valid IP address, and a port or brackets are not part of a name")
	}
	name := strings.ToLower(v)
	if !validDNSName(name) {
		return "", errors.New("is not a valid IP address or DNS name")
	}
	return name, nil
}

// validDNSName follows RFC 1123 labels. A numeric last label is how a
// malformed IP (999.1.1.1) shows up, and no real top-level domain is numeric.
func validDNSName(name string) bool {
	if len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
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
// certificate is already in place. Existing material is never regenerated: the
// CA stays, and the leaf is only re-signed to cover names it does not yet have.
func (in *Installer) ensureSelfSigned(l layout, s serverSettings) error {
	f := selfSignedFiles(l)
	if in.d.Files.Exists(f.Cert) {
		if len(s.SANs) == 0 {
			in.say("keeping existing certificate %s", f.Cert)
			return nil
		}
		return in.resignLeaf(l, s.SANs)
	}
	host, err := publicHost(s.PublicURL)
	if err != nil {
		return err
	}
	m, err := generateSelfSigned(host, s.SANs, in.d.Clock.Now())
	if err != nil {
		return failWrap(ExitCreation, "generate self-signed certificates", err)
	}
	return in.writeSelfSigned(f, m)
}

// resignLeaf makes the installed leaf cover sans as well as the names it
// already has, signed by the existing CA for the existing key: clients that
// trust the CA keep trusting it. It changes nothing when every name is covered.
// The CA, its key and the leaf are checked first, so a damaged or mismatched
// set is refused rather than papered over. server.pem is replaced atomically
// (Files.WriteFile) and signing again with the same names is harmless, so a
// run repeated after a crash converges.
func (in *Installer) resignLeaf(l layout, sans []string) error {
	f := selfSignedFiles(l)
	now := in.d.Clock.Now()
	ca, caKey, leaf, err := in.verifiedSelfSigned(f)
	if err != nil {
		return err
	}
	if now.After(ca.NotAfter) {
		return fail(ExitConfiguration, "the CA %s expired on %s; the certificates cannot be extended", f.CACert, ca.NotAfter.UTC().Format(time.DateOnly))
	}
	have := leafNames(leaf)
	dns, ips := splitNames(append(slices.Clone(have), sans...))
	if len(dns)+len(ips) == len(have) {
		in.say("the certificate %s already covers %s", f.Cert, strings.Join(sans, ", "))
		return nil
	}
	tpl, err := leafTemplate(leaf.Subject.CommonName, dns, ips, now)
	if err != nil {
		return err
	}
	tpl.NotAfter = minTime(tpl.NotAfter, ca.NotAfter) // a leaf never outlives its CA
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, leaf.PublicKey, caKey)
	if err != nil {
		return failWrap(ExitConfiguration, "sign the server certificate", err)
	}
	if err := in.d.Files.WriteFile(f.Cert, encodeCert(der), 0o644, Owner{User: "root", Group: "root"}); err != nil {
		return failWrap(ExitConfiguration, "write "+f.Cert, err)
	}
	in.say("re-signed %s with the existing CA; it now covers %s", f.Cert, strings.Join(append(slices.Clone(dns), ipStrings(ips)...), ", "))
	return nil
}

// verifiedSelfSigned loads the generated material and proves it is one set: the CA
// key belongs to the CA, the leaf was issued by that CA, and the leaf key is the
// leaf's.
func (in *Installer) verifiedSelfSigned(f tlsFiles) (*x509.Certificate, crypto.Signer, *x509.Certificate, error) {
	var pems [4][]byte
	for i, path := range []string{f.CACert, f.CAKey, f.Cert, f.Key} {
		data, err := in.d.Files.ReadFile(path)
		if err != nil {
			return nil, nil, nil, failWrap(ExitConfiguration, "read "+path, err)
		}
		pems[i] = data
	}
	caPEM, caKeyPEM, leafPEM, leafKeyPEM := pems[0], pems[1], pems[2], pems[3]
	ca, err := certFromPEM(caPEM)
	if err != nil {
		return nil, nil, nil, failWrap(ExitConfiguration, "parse "+f.CACert, err)
	}
	caKey, err := signerFromPEM(caKeyPEM)
	if err != nil {
		return nil, nil, nil, failWrap(ExitConfiguration, "parse "+f.CAKey, err)
	}
	if pub, ok := caKey.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(ca.PublicKey) {
		return nil, nil, nil, fail(ExitConfiguration, "%s is not the key of %s", f.CAKey, f.CACert)
	}
	leaf, err := certFromPEM(leafPEM)
	if err != nil {
		return nil, nil, nil, failWrap(ExitConfiguration, "parse "+f.Cert, err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return nil, nil, nil, failWrap(ExitConfiguration, f.Cert+" was not issued by "+f.CACert, err)
	}
	if _, err := tls.X509KeyPair(leafPEM, leafKeyPEM); err != nil {
		return nil, nil, nil, failWrap(ExitConfiguration, f.Key+" does not match "+f.Cert, err)
	}
	return ca, caKey, leaf, nil
}

func certFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate in PEM data")
	}
	return x509.ParseCertificate(block.Bytes)
}

func signerFromPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no private key in PEM data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("not a signing key")
	}
	return signer, nil
}

// leafNames is the leaf's SANs as the strings splitNames takes.
func leafNames(leaf *x509.Certificate) []string {
	return append(slices.Clone(leaf.DNSNames), ipStrings(leaf.IPAddresses)...)
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
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
	in.say("CA certificate: %s\nSHA-256 fingerprint: %s\nCopy the CA to each client, then run `sm profile add <name> --url <public URL> --ca-file <ca.pem> --use` and `sm login`.\n%s", f.CACert, fp, strings.TrimSpace(string(pemData)))
	return nil
}
