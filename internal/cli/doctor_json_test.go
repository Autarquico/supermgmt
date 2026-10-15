package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

func decodeDoctorJSON(t *testing.T, stdout string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &fields); err != nil {
		t.Fatalf("doctor --json is not a JSON object: %v\n%s", err, stdout)
	}
	return fields
}

func TestDoctorOfflineJSON_CarriesTheFormatAndSchemaVersions(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)

	r := s.run("doctor", "--offline", "--json")

	if r.code != 0 {
		t.Fatalf("code = %d, stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
	fields := decodeDoctorJSON(t, r.stdout)
	for name, want := range map[string]string{"format_version": "1", "ok": "true", "database_schema_version": "6", "binary_schema_version": "6"} {
		if got := string(fields[name]); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if _, ok := fields["checks"]; !ok {
		t.Error("the checks array must stay in the report")
	}
}

func TestDoctorOfflineJSON_HasNoDatabaseVersionWithoutADatabase(t *testing.T) {
	s := newSandbox(t)

	r := s.run("doctor", "--offline", "--json")

	fields := decodeDoctorJSON(t, r.stdout)
	if _, present := fields["database_schema_version"]; present {
		t.Errorf("database_schema_version = %s for a machine without a database", fields["database_schema_version"])
	}
	if string(fields["format_version"]) != "1" || string(fields["binary_schema_version"]) == "" {
		t.Errorf("format_version and binary_schema_version must be present: %s", r.stdout)
	}
}

func writeDoctorCertificate(t *testing.T, path string, notAfter time.Time) {
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
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s sandbox) writeDirectTLSConfig(t *testing.T, certFile string) {
	t.Helper()
	s.writeConfig(t, "version: 1\ninstance:\n  mode: server\n  data_dir: "+filepath.Join(s.dir, "data")+"\n"+
		"server:\n  admin_socket: "+filepath.Join(s.dir, "run", "admin.sock")+"\n"+
		"  tls:\n    mode: direct\n    cert_file: "+certFile+"\n    key_file: "+filepath.Join(s.dir, "key.pem")+"\n")
}

func TestDoctorOfflineTLS_ByCertificateValidity(t *testing.T) {
	for _, tt := range []struct {
		name      string
		remaining time.Duration
		wantCode  int
		wantState string
	}{
		{"expired", -time.Hour, 1, "fail"},
		{"expires within thirty days", 10 * 24 * time.Hour, 0, "warn"},
		{"valid for a year", 365 * 24 * time.Hour, 0, "ok"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newSandbox(t)
			cert := filepath.Join(s.dir, "cert.pem")
			notAfter := domain.SystemClock{}.Now().Add(tt.remaining).UTC().Truncate(time.Second)
			writeDoctorCertificate(t, cert, notAfter)
			s.writeDirectTLSConfig(t, cert)

			r := s.run("doctor", "--offline", "--json")

			var report struct {
				Checks []check `json:"checks"`
			}
			if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
				t.Fatalf("%v\n%s", err, r.stdout)
			}
			var tls *check
			for i := range report.Checks {
				if report.Checks[i].Name == "tls" {
					tls = &report.Checks[i]
				}
			}
			if tls == nil || tls.Status != tt.wantState || tls.Detail != notAfter.Format(time.RFC3339) {
				t.Fatalf("tls check = %+v, want %s with NotAfter %s", tls, tt.wantState, notAfter.Format(time.RFC3339))
			}
			if r.code != tt.wantCode {
				t.Errorf("code = %d, want %d", r.code, tt.wantCode)
			}
		})
	}
}

func TestDoctorOfflineTLS_FailsOnAnUnreadableCertificate(t *testing.T) {
	s := newSandbox(t)
	s.writeDirectTLSConfig(t, filepath.Join(s.dir, "absent.pem"))

	r := s.run("doctor", "--offline")

	if r.code != 1 || !strings.Contains(r.stdout, "tls") {
		t.Errorf("code = %d, stdout %q; want a failing tls row", r.code, r.stdout)
	}
}

func TestDoctorOfflineTLS_IsOmittedWithoutDirectTLS(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)

	r := s.run("doctor", "--offline")

	if strings.Contains(r.stdout, "tls") {
		t.Errorf("a local configuration has no certificate to check:\n%s", r.stdout)
	}
}

func TestDoctorOnALocalInstallationRunsTheOfflineChecks(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)

	r := s.run("doctor", "--json")

	if r.code != 0 {
		t.Fatalf("code = %d, stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
	if got := string(decodeDoctorJSON(t, r.stdout)["database_schema_version"]); got != "6" {
		t.Errorf("database_schema_version = %q, want the offline inspection's 6", got)
	}
}

func TestDoctorOnALocalInstallationReportsARunningDaemonWithoutFailing(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)
	lock, err := database.AcquireDatabaseLock(s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()

	local := s.run("doctor")
	offline := s.run("doctor", "--offline")

	if local.code != 0 || !strings.Contains(local.stdout, "a daemon is running") {
		t.Errorf("sm doctor: exit %d, %q", local.code, local.stdout)
	}
	if offline.code == 0 {
		t.Errorf("sm doctor --offline must still fail while a daemon holds the database: %q", offline.stdout)
	}
}

func TestDoctorOnALocalInstallationWithoutAConfigFileUsesTheDaemonsDefaults(t *testing.T) {
	s := newSandbox(t) // without --config, the default location under HOME has no file

	r := runWithEnv(s.env, "doctor")

	if r.code != 0 || !strings.Contains(r.stdout, "built-in defaults") {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
}
