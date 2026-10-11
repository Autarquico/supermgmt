package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/backup"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestAFreshServerHasNoLocalAdminAndBootstrapSucceedsOnce(t *testing.T) {
	i := newServerInstance(t, "")
	r := i.start()
	db := i.openDB()

	var locals, admins int
	scan := func(query string, into *int) {
		t.Helper()
		if err := db.Reader().QueryRowContext(context.Background(), query).Scan(into); err != nil {
			t.Fatal(err)
		}
	}
	scan(`SELECT COUNT(*) FROM identities WHERE subject LIKE 'local:%'`, &locals)
	scan(`SELECT COUNT(*) FROM role_bindings`, &admins)
	if locals != 0 || admins != 0 {
		t.Fatalf("a fresh server has %d local identities and %d role bindings; bootstrap would be refused forever", locals, admins)
	}
	var system int
	scan(`SELECT COUNT(*) FROM identities WHERE actor_type = 'system'`, &system)
	if system != 1 {
		t.Errorf("system identities = %d, want the one scheduled jobs run as", system)
	}

	first := r.bootstrap()

	if first.Session == nil || first.APIToken == nil {
		t.Fatalf("bootstrap = %+v, want a session and an API token", first)
	}
	status, body := r.call(http.MethodGet, wire.PathMe, first.APIToken.Value, "")
	me := decodeData[wire.Me](t, body)
	if status != http.StatusOK || me.IdentityID != first.IdentityID || me.Roles[0] != "admin" || me.Credential != domain.CredentialAPIToken || me.InstanceMode != "server" {
		t.Errorf("me = %d %+v", status, me)
	}
	status, body = r.callAdmin(http.MethodPost, wire.AdminPathBootstrapCode, "")
	if status != http.StatusConflict {
		t.Errorf("a second bootstrap code after the admin exists: %d %s", status, body)
	}
}

func TestABootstrapCodeWorksOnceAndTheNewestCodeInvalidatesTheOlder(t *testing.T) {
	i := newServerInstance(t, "")
	r := i.start()
	issue := func() string {
		_, body := r.callAdmin(http.MethodPost, wire.AdminPathBootstrapCode, "")
		return decodeData[wire.BootstrapCodeIssued](t, body).Code
	}
	older, newer := issue(), issue()

	status, _ := r.call(http.MethodPost, wire.PathBootstrap, "", `{"code":"`+older+`","display_name":"A"}`)
	if status != http.StatusUnauthorized {
		t.Errorf("the superseded code: status %d", status)
	}
	status, _ = r.call(http.MethodPost, wire.PathBootstrap, "", `{"code":"`+newer+`","display_name":"A"}`)
	if status != http.StatusOK {
		t.Fatalf("the newest code: status %d", status)
	}
	status, _ = r.call(http.MethodPost, wire.PathBootstrap, "", `{"code":"`+newer+`","display_name":"B"}`)
	if status != http.StatusUnauthorized {
		t.Errorf("the same code twice: status %d", status)
	}
}

func TestTheAdminSocketIsPrivateAndServesOnlyItsFourRoutes(t *testing.T) {
	i := newServerInstance(t, "")
	r := i.start()

	info, err := os.Stat(i.admin)
	if err != nil || info.Mode().Perm() != 0o660 || info.Mode().Type() != os.ModeSocket {
		t.Fatalf("admin socket = %v, %v; want a 0660 socket", info, err)
	}
	status, body := r.callAdmin(http.MethodGet, wire.AdminPathDoctor, "")
	doctor := decodeData[wire.AdminDoctor](t, body)
	if status != http.StatusOK || doctor.Mode != "server" || doctor.AdminBound || len(doctor.Checks) == 0 {
		t.Errorf("doctor = %d %+v", status, doctor)
	}
	for _, path := range []string{wire.PathMasterKeyRotate, wire.PathMasterKeyExport, wire.PathSecrets, wire.PathMe} {
		if status, _ := r.callAdmin(http.MethodPost, path, "{}"); status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
			t.Errorf("%s on the admin socket: status %d", path, status)
		}
	}
	r.stop()
	if err := r.wait(); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	if _, err := os.Lstat(i.admin); !os.IsNotExist(err) {
		t.Errorf("the admin socket survived shutdown: %v", err)
	}
}

func TestTheServerRefusesAnAdminDirectoryOthersCouldReplaceTheSocketIn(t *testing.T) {
	i := newServerInstance(t, "")
	if err := os.MkdirAll(filepath.Dir(i.admin), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(i.admin), 0o777); err != nil {
		t.Fatal(err)
	}

	r := i.start()

	var unsafe *UnsafeSocketDirError
	if err := r.wait(); !errors.As(err, &unsafe) {
		t.Errorf("RunServer = %v, want an unsafe directory error", err)
	}
}

func TestAServerRefusesToRunAsALocalDaemonAndViceVersa(t *testing.T) {
	server := newServerInstance(t, "")
	if err := Run(context.Background(), Options{Config: server.cfg, Socket: filepath.Join(server.root, "s")}); err == nil || !strings.Contains(err.Error(), "sm server") {
		t.Errorf("Run on a server configuration = %v", err)
	}
	local := newInstance(t, "")
	if err := RunServer(context.Background(), Options{Config: local.cfg}); err == nil || !strings.Contains(err.Error(), "sm daemon") {
		t.Errorf("RunServer on a local configuration = %v", err)
	}
}

func TestTheLocalSocketStillRefusesBearerTokens(t *testing.T) {
	i := newInstance(t, "")
	i.start()
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", i.socket)
		},
	}}
	defer c.CloseIdleConnections()

	status, body := send(t, c, http.MethodGet, "http://sm"+wire.PathMe, "smt_"+strings.Repeat("A", 43), "")

	var env wire.ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil || status != http.StatusUnauthorized || env.Error.Code != smerr.CodeUnauthenticated {
		t.Errorf("status %d body %s", status, body)
	}
}

// ---- restore hold --------------------------------------------------------------

func TestAPersistedHoldKeepsWorkersFromClaimingAfterARestartUntilRestoreComplete(t *testing.T) {
	i := newServerInstance(t, "")
	first := i.start()
	first.stop()
	_ = first.wait()
	job := i.submitBackupWhileStopped()
	i.setHold(true)

	r := i.start()

	time.Sleep(1500 * time.Millisecond) // several engine polls
	if state := i.jobStateWhileRunning(r, job); state != domain.JobQueued || len(i.archives()) != 0 {
		t.Fatalf("job is %s with %d archives after the restart; workers must not claim during the hold", state, len(i.archives()))
	}
	status, _ := r.callAdmin(http.MethodPost, wire.AdminPathRestoreComplete, "")
	if status != http.StatusOK {
		t.Fatalf("restore-complete: %d", status)
	}
	waitUntil(t, func() bool { return len(i.archives()) == 1 })
}

// jobStateWhileRunning reads the job through a second connection; the server
// holds the database open, which SQLite allows for readers.
func (i *serverInstance) jobStateWhileRunning(_ *runningServer, id domain.ID) domain.JobState {
	return i.jobState(id)
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := clockNow().Add(waitLimit)
	for clockNow().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	failWithGoroutines(t, "the condition was not reached")
}

func TestAnUnreadableHoldRefusesTheStart(t *testing.T) {
	i := newServerInstance(t, "")
	first := i.start()
	first.stop()
	_ = first.wait()
	db := i.openDB()
	err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		return database.PutSetting(ctx, tx, database.Setting{Key: database.SettingRestoreHold, Value: json.RawMessage(`"maybe"`), UpdatedAt: clockNow()})
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	r := i.start()

	if err := r.wait(); err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("RunServer = %v, want the start refused", err)
	}
}

func TestDuringHoldLoginAndGrantWorkButWritesAreRefusedOverHTTPS(t *testing.T) {
	i := newServerInstance(t, "")
	first := i.start()
	admin := first.bootstrap()
	first.stop()
	_ = first.wait()
	i.setHold(true)
	r := i.start()

	status, body := r.call(http.MethodPost, wire.PathTokens, admin.APIToken.Value, `{"name":"x","expires_at":"`+clockNow().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)
	var env wire.ErrorEnvelope
	_ = json.Unmarshal(body, &env)
	if status != http.StatusConflict || env.Error.Reason() != smerr.ReasonRestoreHold {
		t.Errorf("write during hold: %d %s", status, body)
	}
	// Tokens were not revoked here (no restore ran), so the admin can still read.
	if status, _ := r.call(http.MethodGet, wire.PathMe, admin.APIToken.Value, ""); status != http.StatusOK {
		t.Errorf("read during hold: %d", status)
	}
	// The recovery path: grant and bootstrap over the admin socket pass the hold.
	grant := `{"identity_id":"` + admin.IdentityID.String() + `","role":"viewer"}`
	if status, body := r.callAdmin(http.MethodPost, wire.AdminPathGrant, grant); status != http.StatusOK {
		t.Errorf("grant during hold: %d %s", status, body)
	}
	if status, body := r.callAdmin(http.MethodPost, wire.AdminPathBootstrapCode, ""); status != http.StatusOK {
		t.Errorf("bootstrap-code during hold: %d %s", status, body)
	}
}

// ---- startup order ---------------------------------------------------------------

func TestStartupRecoversAnUnfinishedRestoreBeforeOpeningTheDatabase(t *testing.T) {
	i := newServerInstance(t, "")
	dataDir := i.dataDir()
	staging := filepath.Join(dataDir, "restore-"+domain.UUIDv7Generator{}.NewID().String())
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(staging, "supermgmt.db")
	stageDatabase(t, staged, "restored-instance")
	sum := fileDigest(t, staged)
	journal := map[string]any{
		"id": "restore-1", "state": "staged", "staging": staging,
		"moves": []map[string]string{{"kind": "install", "from": staged, "to": i.cfg.Storage.SQLite.Path, "status": "intent", "sha256": sum}},
	}
	data, _ := json.Marshal(journal)
	if err := os.WriteFile(filepath.Join(dataDir, backup.JournalName), data, 0o600); err != nil {
		t.Fatal(err)
	}

	r := i.start()
	r.stop()
	_ = r.wait()

	db := i.openDB()
	instance, err := database.GetInstance(context.Background(), db.Reader())
	if err != nil || instance.Name != "restored-instance" {
		t.Errorf("instance = %+v, %v; the unfinished restore was not completed before the database opened", instance, err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, backup.JournalName)); !os.IsNotExist(err) {
		t.Errorf("the journal survived recovery: %v", err)
	}
}

func TestAJournalRecoveryCannotFinishRefusesTheStartWithoutTouchingTheLiveFiles(t *testing.T) {
	i := newServerInstance(t, "")
	if err := os.MkdirAll(i.dataDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(i.dataDir(), backup.JournalName), []byte(`{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	live := i.cfg.Storage.SQLite.Path
	if err := os.WriteFile(live, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := i.start()

	if err := r.wait(); err == nil || !strings.Contains(err.Error(), "restore") {
		t.Errorf("RunServer = %v, want the interrupted restore to refuse the start", err)
	}
	if got, _ := os.ReadFile(live); string(got) != "live" {
		t.Errorf("the live database was touched: %q", got)
	}
}

func stageDatabase(t *testing.T, path, instanceName string) {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(ctx, path, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		return database.CreateInstance(ctx, tx, database.Instance{ID: domain.UUIDv7Generator{}.NewID(), Name: instanceName, CreatedAt: clockNow()})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			t.Fatalf("%s%s left behind by a clean close", path, suffix)
		}
	}
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ---- backups through the real path -------------------------------------------------

func TestABackupSubmittedThroughTheAPIIsClaimedAndProducesAnArchive(t *testing.T) {
	i := newServerInstance(t, "")
	r := i.start()
	admin := r.bootstrap()

	status, body := r.call(http.MethodPost, wire.PathBackups, admin.APIToken.Value, "", wire.HeaderIdempotencyKey, "backup-1")
	if status != http.StatusAccepted {
		t.Fatalf("POST /backups: %d %s", status, body)
	}
	job := decodeData[wire.Submission](t, body).Job
	if job.State != domain.JobQueued {
		t.Fatalf("job = %s; backup.create needs no approval for an admin", job.State)
	}

	waitUntil(t, func() bool { return len(i.archives()) == 1 })
	waitUntil(t, func() bool {
		_, body := r.call(http.MethodGet, strings.Replace(wire.PathJob, "{id}", job.ID.String(), 1), admin.APIToken.Value, "")
		return decodeData[wire.JobDetail](t, body).Job.State == domain.JobSucceeded
	})

	status, body = r.call(http.MethodGet, wire.PathBackups, admin.APIToken.Value, "")
	listed := decodeData[wire.Page[wire.Backup]](t, body)
	if status != http.StatusOK || len(listed.Items) != 1 || listed.Items[0].Name != filepath.Base(i.archives()[0]) {
		t.Errorf("GET /backups = %d %s", status, body)
	}
}

// ---- TLS ---------------------------------------------------------------------------

func TestDirectTLSServesTheOperatorCertificateAndReloadsItOnSignal(t *testing.T) {
	root, err := os.MkdirTemp("", "smt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	certFile, keyFile := filepath.Join(root, "tls.crt"), filepath.Join(root, "tls.key")
	writeCertificate(t, certFile, keyFile, "first.test")
	i := newServerInstance(t, "")
	rewriteTLS(t, i, "direct", certFile, keyFile)
	reload := make(chan struct{})
	r := i.start(func(o *Options) { o.Reload = reload })

	if got := servedName(t, r.ep.HTTP.String(), tls.VersionTLS12); got != "first.test" {
		t.Fatalf("served %q", got)
	}
	writeCertificate(t, certFile, keyFile, "second.test")
	reload <- struct{}{}
	waitUntil(t, func() bool { return servedName(t, r.ep.HTTP.String(), tls.VersionTLS12) == "second.test" })

	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	reload <- struct{}{}
	reload <- struct{}{} // the second send returns only after the first reload finished
	if got := servedName(t, r.ep.HTTP.String(), tls.VersionTLS12); got != "second.test" {
		t.Errorf("a failed reload replaced the certificate: %q", got)
	}
	conn, err := dialTLS(r.ep.HTTP.String(), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11})
	if err == nil {
		_ = conn.Close()
		t.Error("a TLS 1.1 handshake succeeded")
	}
}

func rewriteTLS(t *testing.T, i *serverInstance, mode, cert, key string) {
	t.Helper()
	data, err := os.ReadFile(i.file)
	if err != nil {
		t.Fatal(err)
	}
	extra := "  tls:\n    mode: " + mode + "\n    cert_file: " + cert + "\n    key_file: " + key + "\n"
	text := strings.Replace(string(data), "server:\n", "server:\n"+extra, 1)
	text = strings.Replace(text, "  trusted_proxies: [10.0.0.0/8]\n", "", 1)
	if err := os.WriteFile(i.file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(i.file, []string{"HOME=" + i.root})
	if err != nil {
		t.Fatal(err)
	}
	i.cfg = loaded.Config
}

func servedName(t *testing.T, addr string, min uint16) string {
	t.Helper()
	conn, err := dialTLS(addr, &tls.Config{InsecureSkipVerify: true, MinVersion: min})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
}

func writeCertificate(t *testing.T, certFile, keyFile, name string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(clockNow().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: clockNow().Add(-time.Hour), NotAfter: clockNow().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func dialTLS(addr string, cfg *tls.Config) (*tls.Conn, error) {
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}
