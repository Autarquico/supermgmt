package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const kekID domain.ID = "0192a000-0000-7000-8000-00000000f001"

const passphrase = "correct horse battery"

// writableSecrets lets a test create the first master key, and its check
// record, in a real database; the product code only ever reads it.
type writableSecrets struct {
	database.ReadOnlySecrets
	db *database.DB
}

func (w writableSecrets) PutSettings(ctx context.Context, values map[string]string) error {
	return w.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		for key, valueJSON := range values {
			setting := database.Setting{Key: key, Value: json.RawMessage(valueJSON), UpdatedAt: domain.SystemClock{}.Now()}
			if err := database.PutSetting(ctx, tx, setting); err != nil {
				return err
			}
		}
		return nil
	})
}

func (f *fakeAPI) runIn(stdin string, args ...string) result {
	return f.runCtx(context.Background(), stdin, args...)
}

func appliedOrPending[T any](w http.ResponseWriter, applied *T, pending *wire.Submission) {
	reply(w, 200, wire.Direct[T]{Applied: applied, Pending: pending})
}

func awaiting(job string) *wire.Submission {
	return &wire.Submission{
		Job:    wire.Job{ID: domain.ID(job), Type: "control_plane.apply", State: domain.JobAwaitingApproval},
		Policy: wire.Policy{Decision: "allow", ApprovalRequired: true, Quorum: 1},
	}
}

// ---- no secret has a flag --------------------------------------------------------------------------

func TestNoCommandTakesASecretOnItsCommandLine(t *testing.T) {
	secretish := regexp.MustCompile(`(?i)pass|secret|password|token|code|value|key-material`)
	flagName := regexp.MustCompile(`--([a-z][a-z0-9-]*)`)
	// token-file names a file and show-token prints a token instead of taking one: no secret is on the command line.
	allowed := map[string]bool{"token-stdin": true, "token-file": true, "show-token": true}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, m := range flagName.FindAllStringSubmatch(c.LocalFlags().FlagUsages(), -1) {
			if secretish.MatchString(m[1]) && !allowed[m[1]] {
				t.Errorf("%s has a --%s flag: secrets come from a terminal or stdin only", c.CommandPath(), m[1])
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(testRoot(nil))
}

// ---- secrets import ----------------------------------------------------------------------------------

func secretsAPI(t *testing.T, got *wire.ImportSecretRequest, keyHeader *string, answer func(http.ResponseWriter)) *fakeAPI {
	return newFakeAPI(t, router(routes{
		"POST " + wire.PathSecrets: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(got)
			*keyHeader = r.Header.Get(wire.HeaderIdempotencyKey)
			answer(w)
		},
	}))
}

func TestSecretsImportReadsAMultiLineValueFromStdin(t *testing.T) {
	var got wire.ImportSecretRequest
	var key string
	f := secretsAPI(t, &got, &key, func(w http.ResponseWriter) {
		appliedOrPending(w, &wire.SecretVersion{Name: "providers/pve/token", Version: 2}, nil)
	})
	const value = "-----BEGIN KEY-----\nabc\n-----END KEY-----"

	r := f.runIn(value+"\n", "secrets", "import", "--name", "providers/pve/token")

	if r.code != 0 || got.Name != "providers/pve/token" || got.Value != value {
		t.Fatalf("exit %d, request %+v, stderr %s", r.code, got, r.stderr)
	}
	if key == "" {
		t.Error("secret writes are keyed: the request carried no Idempotency-Key")
	}
	assertNoSecret(t, "abc", r)
	if !strings.Contains(r.stdout, "version 2") {
		t.Errorf("stdout = %q", r.stdout)
	}
}

func TestSecretsImportThatWaitsForApprovalSaysSo(t *testing.T) {
	var got wire.ImportSecretRequest
	var key string
	f := secretsAPI(t, &got, &key, func(w http.ResponseWriter) { appliedOrPending[wire.SecretVersion](w, nil, awaiting("job-9")) })

	r := f.runIn("v\n", "secrets", "import", "--name", "n")

	if r.code != 0 || !strings.Contains(r.stdout, "job-9") || !strings.Contains(r.stdout, "approval required") {
		t.Errorf("exit %d, stdout %q", r.code, r.stdout)
	}
}

func TestSecretsImportFromFileRequiresAPrivateFile(t *testing.T) {
	var got wire.ImportSecretRequest
	var key string
	f := secretsAPI(t, &got, &key, func(w http.ResponseWriter) {
		appliedOrPending(w, &wire.SecretVersion{Name: "n", Version: 1}, nil)
	})
	dir := t.TempDir()
	open := filepath.Join(dir, "open")
	private := filepath.Join(dir, "private")
	writeFile(t, open, "value\n")
	writeFile(t, private, "value\n")
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}

	if r := f.run("secrets", "import", "--name", "n", "--from-file", open); r.code != exitUsage || !strings.Contains(r.stderr, "readable by others") {
		t.Errorf("world-readable file: exit %d, %q", r.code, r.stderr)
	}
	if r := f.run("secrets", "import", "--name", "n", "--from-file", private); r.code != 0 || got.Value != "value" {
		t.Errorf("private file: exit %d, value %q, %s", r.code, got.Value, r.stderr)
	}
	if r := f.run("secrets", "import", "--name", "n", "--from-file", dir); r.code != exitUsage {
		t.Errorf("directory: exit %d", r.code)
	}
}

func TestSecretsImportRefusesAMissingNameAnEmptyValueAndAnOversizedOne(t *testing.T) {
	var got wire.ImportSecretRequest
	var key string
	f := secretsAPI(t, &got, &key, func(w http.ResponseWriter) { appliedOrPending(w, &wire.SecretVersion{}, nil) })

	cases := map[string][]string{
		"no name":   {"secrets", "import"},
		"empty":     {"secrets", "import", "--name", "n"},
		"oversized": {"secrets", "import", "--name", "n"},
	}
	stdin := map[string]string{"no name": "v\n", "empty": "", "oversized": strings.Repeat("x", maxSecretValueBytes+1)}
	for name, args := range cases {
		if r := f.runIn(stdin[name], args...); r.code != exitUsage {
			t.Errorf("%s: exit %d, %q", name, r.code, r.stderr)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests were sent for refused input", n)
	}
}

// ---- master key rotation and retirement --------------------------------------------------------------------

func TestRotateMasterKeyAsksFirst(t *testing.T) {
	f := newFakeAPI(t, router(routes{
		"POST " + wire.PathMasterKeyRotate: func(w http.ResponseWriter, _ *http.Request) {
			appliedOrPending(w, &wire.MasterKeyRotated{ActiveKEKID: "new", PreviousKEKID: "old", Rewrapped: 4}, nil)
		},
	}))

	if r := f.run("secrets", "rotate-master-key"); r.code != exitUsage || len(f.Requests()) != 0 {
		t.Errorf("unconfirmed: exit %d, %d requests", r.code, len(f.Requests()))
	}
	r := f.run("secrets", "rotate-master-key", "--yes")
	if r.code != 0 || !strings.Contains(r.stdout, "4 secret(s) rewrapped") {
		t.Errorf("exit %d, stdout %q", r.code, r.stdout)
	}
}

func TestRetireKeyNeedsTheExternalBackupsAcknowledgement(t *testing.T) {
	var got wire.RetireKeyRequest
	f := newFakeAPI(t, router(routes{
		"POST " + wire.PathMasterKeyRetire: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			appliedOrPending(w, &struct{}{}, nil)
		},
	}))

	if r := f.run("secrets", "retire-key", string(kekID), "--yes"); r.code != exitUsage || !strings.Contains(r.stderr, "external-backups-handled") {
		t.Errorf("without the acknowledgement: exit %d, %q", r.code, r.stderr)
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("%d requests without the acknowledgement", n)
	}
	r := f.run("secrets", "retire-key", string(kekID), "--external-backups-handled", "--yes")
	if r.code != 0 || got.KEKID != kekID || !got.ExternalBackupsHandled {
		t.Errorf("exit %d, request %+v, %s", r.code, got, r.stderr)
	}
	if bad := f.run("secrets", "retire-key", "nope", "--external-backups-handled", "--yes"); bad.code != exitUsage {
		t.Errorf("malformed id: exit %d", bad.code)
	}
}

// ---- export-key: the two steps on the local socket -----------------------------------------------------------

func exportAPI(t *testing.T, bodies *[]wire.ExportKeyRequest, answer func(req wire.ExportKeyRequest) wire.Direct[wire.ExportedKey]) *fakeAPI {
	return newFakeAPI(t, router(routes{
		"POST " + wire.PathMasterKeyExport: func(w http.ResponseWriter, r *http.Request) {
			var req wire.ExportKeyRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			*bodies = append(*bodies, req)
			if r.Header.Get(wire.HeaderIdempotencyKey) != "" {
				replyError(w, 400, smerr.CodeInvalidArgument, "", "Idempotency-Key is not accepted here")
				return
			}
			reply(w, 200, answer(req))
		},
	}))
}

func TestExportKeyFirstCallRequestsWithoutAPassphraseAndPrintsTheJob(t *testing.T) {
	var bodies []wire.ExportKeyRequest
	f := exportAPI(t, &bodies, func(wire.ExportKeyRequest) wire.Direct[wire.ExportedKey] {
		return wire.Direct[wire.ExportedKey]{Pending: awaiting("job-42")}
	})

	r := f.runIn("", "secrets", "export-key", string(kekID))

	if r.code != 0 || len(bodies) != 1 || bodies[0].Passphrase != "" || bodies[0].KEKID != kekID {
		t.Fatalf("exit %d, bodies %+v, stderr %s", r.code, bodies, r.stderr)
	}
	for _, want := range []string{"job-42", "awaiting_approval", "--execute"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestExportKeyExecuteReadsThePassphraseFromStdinAndWritesAnOwnerOnlyFile(t *testing.T) {
	var bodies []wire.ExportKeyRequest
	export := []byte("SMKEY1-binary\x00\x01\x02")
	f := exportAPI(t, &bodies, func(req wire.ExportKeyRequest) wire.Direct[wire.ExportedKey] {
		return wire.Direct[wire.ExportedKey]{Applied: &wire.ExportedKey{KEKID: req.KEKID, Export: export}}
	})
	out := filepath.Join(t.TempDir(), "kek.smkey")

	r := f.runIn(passphrase+"\n", "secrets", "export-key", string(kekID), "--execute", "--out", out)

	if r.code != 0 || len(bodies) != 1 || bodies[0].Passphrase != passphrase {
		t.Fatalf("exit %d, bodies %+v, stderr %s", r.code, bodies, r.stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(data, export) {
		t.Errorf("file = %q, %v", data, err)
	}
	assertMode(t, out, 0o600)
	assertNoSecret(t, passphrase, r)
}

func TestExportKeyExecuteSettlesLocalProblemsBeforeSpendingTheApproval(t *testing.T) {
	var bodies []wire.ExportKeyRequest
	f := exportAPI(t, &bodies, func(wire.ExportKeyRequest) wire.Direct[wire.ExportedKey] {
		return wire.Direct[wire.ExportedKey]{Applied: &wire.ExportedKey{Export: []byte("x")}}
	})
	existing := filepath.Join(t.TempDir(), "taken")
	writeFile(t, existing, "do not touch")

	short := f.runIn("too short\n", "secrets", "export-key", string(kekID), "--execute", "--out", filepath.Join(t.TempDir(), "k"))
	taken := f.runIn(passphrase+"\n", "secrets", "export-key", string(kekID), "--execute", "--out", existing)

	if short.code != exitUsage || taken.code != exitUsage {
		t.Errorf("exit codes %d and %d, want usage errors", short.code, taken.code)
	}
	if len(bodies) != 0 {
		t.Errorf("%d export calls: the one-time approval was spent although the output could not be written", len(bodies))
	}
	if data, _ := os.ReadFile(existing); string(data) != "do not touch" {
		t.Errorf("an existing file was overwritten: %q", data)
	}
}

func TestExportKeyLeavesNoEmptyFileWhenTheServerRefuses(t *testing.T) {
	f := newFakeAPI(t, router(routes{
		"POST " + wire.PathMasterKeyExport: func(w http.ResponseWriter, _ *http.Request) {
			replyError(w, 409, smerr.CodeConflict, "", "the approved export request was already used")
		},
	}))
	out := filepath.Join(t.TempDir(), "kek.smkey")

	r := f.runIn(passphrase+"\n", "secrets", "export-key", string(kekID), "--execute", "--out", out)

	if r.code == 0 || !strings.Contains(r.stderr, "already used") {
		t.Errorf("exit %d, %q", r.code, r.stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an empty export file was left behind")
	}
}

func TestExportKeyIsNeverRequestedOverHTTPS(t *testing.T) {
	b := newRemoteBox(t, nil)
	b.useProfile()
	b.signIn(tokenOne)

	r := b.run(passphrase+"\n", "secrets", "export-key", string(kekID), "--execute", "--out", filepath.Join(b.dir, "k"))

	if r.code != exitUsage || !strings.Contains(r.stderr, "--offline") || len(b.requests()) != 0 {
		t.Errorf("exit %d, stderr %q, %d requests", r.code, r.stderr, len(b.requests()))
	}
}

// ---- offline key commands ----------------------------------------------------------------------------------------

// keyedSandbox is a stopped local instance with a migrated database and a
// master key whose check record is in it.
func keyedSandbox(t *testing.T) (sandbox, domain.ID) {
	t.Helper()
	s := newSandbox(t)
	s.migratedDatabase(t)
	result, err := config.Load(s.configFile, s.env)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), s.dbPath, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys, err := secrets.OpenFileKeys(context.Background(), result.Config.Security.KeysDir, writableSecrets{ReadOnlySecrets: database.ReadOnlySecrets{Q: db.Reader()}, db: db}, domain.UUIDv7Generator{})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := keys.Active()
	return s, id
}

func keysDirOf(t *testing.T, s sandbox) string {
	t.Helper()
	result, err := config.Load(s.configFile, s.env)
	if err != nil {
		t.Fatal(err)
	}
	return result.Config.Security.KeysDir
}

func (s sandbox) runIn(stdin string, args ...string) result {
	r := execRoot(s.env, stdin, append(append([]string{}, args...), "--config", s.configFile))
	r.stdout, r.stderr = s.normalize(r.stdout), s.normalize(r.stderr)
	return r
}

func TestOfflineExportThenImportRoundTripsAKeyIntoAFreshHost(t *testing.T) {
	src, id := keyedSandbox(t)
	export := filepath.Join(t.TempDir(), "kek.smkey")

	out := src.runIn(passphrase+"\n", "secrets", "export-key", string(id), "--offline", "--out", export)

	if out.code != 0 {
		t.Fatalf("export: exit %d: %s", out.code, out.stderr)
	}
	assertMode(t, export, 0o600)
	data, _ := os.ReadFile(export)
	gotID, kek, err := secrets.DecodeKeyExport(data, passphrase)
	if err != nil || gotID != id || len(kek) != 32 {
		t.Fatalf("the export does not decode: %v (id %s)", err, gotID)
	}
	assertNoSecret(t, passphrase, out)

	fresh := newSandbox(t)
	in := fresh.runIn(passphrase+"\n", "secrets", "import-key", "--offline", "--from", export)

	if in.code != 0 || !strings.Contains(in.stdout, "key.pending") {
		t.Fatalf("import: exit %d, %s %s", in.code, in.stdout, in.stderr)
	}
	pending := filepath.Join(keysDirOf(t, fresh), string(id)+".key.pending")
	assertMode(t, pending, 0o600)
	if _, err := os.Stat(fresh.dbPath); err == nil {
		t.Error("import-key created a database: it needs none")
	}
}

func TestOfflineImportVerifiesAgainstTheDatabaseThatReferencesTheKey(t *testing.T) {
	s, id := keyedSandbox(t)
	export := filepath.Join(t.TempDir(), "kek.smkey")
	if r := s.runIn(passphrase+"\n", "secrets", "export-key", string(id), "--offline", "--out", export); r.code != 0 {
		t.Fatalf("export: %s", r.stderr)
	}
	keyFile := filepath.Join(keysDirOf(t, s), string(id)+".key")
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}

	r := s.runIn(passphrase+"\n", "secrets", "import-key", "--offline", "--from", export)

	if r.code != 0 || !strings.Contains(r.stdout, "verified") {
		t.Fatalf("exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
	assertMode(t, keyFile, 0o600)
}

func TestOfflineImportWithAWrongPassphraseInstallsNothing(t *testing.T) {
	src, id := keyedSandbox(t)
	export := filepath.Join(t.TempDir(), "kek.smkey")
	src.runIn(passphrase+"\n", "secrets", "export-key", string(id), "--offline", "--out", export)
	fresh := newSandbox(t)

	r := fresh.runIn("not the right passphrase\n", "secrets", "import-key", "--offline", "--from", export)

	if r.code == 0 {
		t.Fatal("a wrong passphrase imported a key")
	}
	if entries, _ := os.ReadDir(keysDirOf(t, fresh)); len(entries) != 0 {
		t.Errorf("the key directory is not empty: %v", entries)
	}
}

func TestOfflineKeyCommandsRefuseWhileADaemonHoldsTheDatabase(t *testing.T) {
	s, id := keyedSandbox(t)
	lock, err := database.AcquireDatabaseLock(s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	export := filepath.Join(t.TempDir(), "kek.smkey")
	writeFile(t, export, "irrelevant")

	exp := s.runIn(passphrase+"\n", "secrets", "export-key", string(id), "--offline", "--out", filepath.Join(t.TempDir(), "o"))
	imp := s.runIn(passphrase+"\n", "secrets", "import-key", "--offline", "--from", export)

	for name, r := range map[string]result{"export-key": exp, "import-key": imp} {
		if r.code != exitPrerequisite || !strings.Contains(r.stderr, "stop the service") {
			t.Errorf("%s: exit %d, %q; want a prerequisite failure", name, r.code, r.stderr)
		}
	}
}

func TestImportKeyOnlyRunsOffline(t *testing.T) {
	s := newSandbox(t)
	if r := s.runIn("", "secrets", "import-key", "--from", "x"); r.code != exitUsage || !strings.Contains(r.stderr, "--offline") {
		t.Errorf("exit %d, %q", r.code, r.stderr)
	}
	if r := s.runIn("", "secrets", "import-key", "--offline"); r.code != exitUsage {
		t.Errorf("without --from: exit %d", r.code)
	}
}

// ---- reading secrets ------------------------------------------------------------------------------------------------

func TestReadSecretFromAPipe(t *testing.T) {
	tests := []struct {
		name, stdin string
		in          secretInput
		want        string
		wantErr     bool
	}{
		{"one line", "hunter2\nrest\n", secretInput{limit: 64}, "hunter2", false},
		{"crlf", "hunter2\r\n", secretInput{limit: 64}, "hunter2", false},
		{"no newline", "hunter2", secretInput{limit: 64}, "hunter2", false},
		{"whole", "a\nb\n", secretInput{limit: 64, whole: true}, "a\nb", false},
		{"empty", "", secretInput{limit: 64}, "", true},
		{"blank line", "\n", secretInput{limit: 64}, "", true},
		{"too long", strings.Repeat("x", 65) + "\n", secretInput{limit: 64}, "", true},
		{"whole too long", strings.Repeat("x", 65), secretInput{limit: 64, whole: true}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.SetIn(strings.NewReader(tc.stdin))
			got, err := readSecret(cmd, tc.in)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("got %q, %v; want %q (error %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// lockedBuffer is an io.Writer that tests can poll while a command writes to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func echoOn(t *testing.T, tty *os.File) bool {
	t.Helper()
	attrs, err := unix.IoctlGetTermios(int(tty.Fd()), ioctlReadTermios)
	if err != nil {
		t.Fatal(err)
	}
	return attrs.Lflag&unix.ECHO != 0
}

func TestReadSecretFromATerminalTurnsEchoOffAndRestoresIt(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	cmd := &cobra.Command{}
	cmd.SetIn(slave)
	prompts := &lockedBuffer{}
	cmd.SetErr(prompts)
	type outcome struct {
		value string
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		v, err := readSecret(cmd, secretInput{prompt: "Passphrase: ", confirm: true, limit: 64})
		done <- outcome{v, err}
	}()

	waitFor(t, func() bool { return strings.Contains(prompts.String(), "Passphrase: ") })
	if echoOn(t, slave) {
		t.Fatal("the terminal still echoes while the passphrase is typed")
	}
	if _, err := master.WriteString("hunter2 hunter2\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return strings.Contains(prompts.String(), "Repeat: ") })
	if _, err := master.WriteString("hunter2 hunter2\n"); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-done:
		if got.err != nil || got.value != "hunter2 hunter2" {
			t.Errorf("got %q, %v", got.value, got.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("readSecret did not return")
	}
	if !echoOn(t, slave) {
		t.Error("echo was not restored")
	}
	assertNoSecret(t, "hunter2", result{stderr: prompts.String()})
}

func TestReadSecretFromATerminalRefusesTwoDifferentEntries(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	cmd := &cobra.Command{}
	cmd.SetIn(slave)
	cmd.SetErr(io.Discard)
	_, _ = master.WriteString("first-entry\nsecond-entry\n")

	_, err = readSecret(cmd, secretInput{prompt: "P: ", confirm: true, limit: 64})

	if smerr.CodeOf(err) != smerr.CodeInvalidArgument || !strings.Contains(err.Error(), "differ") {
		t.Errorf("err = %v", err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	const step = 5 * time.Millisecond
	for waited := time.Duration(0); !condition(); waited += step {
		if waited > 10*time.Second {
			t.Fatal("timed out waiting")
		}
		time.Sleep(step)
	}
}

// ---- nodes setup and repin -------------------------------------------------------------------------------------------

const (
	idWeb  domain.ID = "0192a000-0000-7000-8000-00000000a001"
	idPlan domain.ID = "0192a000-0000-7000-8000-00000000d001"
	hashOf           = "5f1d2c3b4a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3"
)

type setupAPI struct {
	*fakeAPI
	plans     []wire.CreatePlanRequest
	submitted []wire.PlanHashRequest
	current   *wire.Setup // the node's recorded setup; nil before the first one
	endpoint  wire.Endpoint
}

func newSetupAPI(t *testing.T, policy wire.Policy) *setupAPI {
	s := &setupAPI{}
	s.fakeAPI = newFakeAPI(t, router(routes{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{{ID: idWeb, Name: "web-1"}}})
		},
		"GET " + wire.Path(wire.PathNode, string(idWeb)): func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Node{ID: idWeb, Name: "web-1", Kind: "ssh", Setup: s.current, Endpoint: s.endpoint})
		},
		"POST " + wire.PathPlans: func(w http.ResponseWriter, r *http.Request) {
			var req wire.CreatePlanRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.plans = append(s.plans, req)
			reply(w, 200, wire.CreatedPlan{PlanID: idPlan, PlanHash: hashOf, Policy: policy})
		},
		"POST " + wire.Path(wire.PathPlanSubmit, string(idPlan)): func(w http.ResponseWriter, r *http.Request) {
			var req wire.PlanHashRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.submitted = append(s.submitted, req)
			reply(w, 200, *awaiting("job-setup"))
		},
	}))
	return s
}

var approvalPolicy = wire.Policy{Decision: "allow", ApprovalRequired: true, Quorum: 1}

func TestNodesSetupSendsExplicitParametersAndSubmitsThePlanHash(t *testing.T) {
	s := newSetupAPI(t, approvalPolicy)

	r := s.run("nodes", "setup", "web-1", "--yes")

	if r.code != 0 || len(s.plans) != 1 {
		t.Fatalf("exit %d, plans %d, stderr %s", r.code, len(s.plans), r.stderr)
	}
	plan := s.plans[0]
	if plan.Action != "node.setup" || plan.Targets[0].ID != idWeb {
		t.Errorf("plan = %+v", plan)
	}
	if plan.Parameters["docker_access"] != "false" || plan.Parameters["logs_mode"] != "journal-group" {
		t.Errorf("parameters = %v; docker_access must always be sent, false unless asked", plan.Parameters)
	}
	if len(s.submitted) != 1 || s.submitted[0].PlanHash != hashOf {
		t.Errorf("submitted = %+v", s.submitted)
	}
	if !strings.Contains(r.stdout, "job-setup") || !strings.Contains(r.stderr, "1 approval") {
		t.Errorf("stdout %q, stderr %q", r.stdout, r.stderr)
	}
	if strings.Contains(r.stderr, "docker") {
		t.Errorf("a docker warning without --docker-access: %q", r.stderr)
	}
}

func TestNodesSetupDockerAccessIsExplicitAndWarned(t *testing.T) {
	s := newSetupAPI(t, approvalPolicy)

	r := s.run("nodes", "setup", "web-1", "--docker-access", "--logs-mode", "broker", "--yes")

	if r.code != 0 || s.plans[0].Parameters["docker_access"] != "true" || s.plans[0].Parameters["logs_mode"] != "broker" {
		t.Fatalf("exit %d, parameters %v", r.code, s.plans[0].Parameters)
	}
	if !strings.Contains(r.stderr, "equivalent to root") {
		t.Errorf("stderr lacks the root-equivalence warning: %q", r.stderr)
	}
}

func TestNodesSetupSubmitsNothingUnlessConfirmed(t *testing.T) {
	declined := newSetupAPI(t, approvalPolicy)
	if r := declined.runIn("no\n", "nodes", "setup", "web-1"); r.code != exitUsage || len(declined.submitted) != 0 {
		t.Errorf("declined: exit %d, %d submissions", r.code, len(declined.submitted))
	}
	silent := newSetupAPI(t, approvalPolicy)
	if r := silent.runIn("", "nodes", "setup", "web-1"); r.code != exitUsage || len(silent.submitted) != 0 {
		t.Errorf("no answer: exit %d, %d submissions", r.code, len(silent.submitted))
	}
	accepted := newSetupAPI(t, approvalPolicy)
	if r := accepted.runIn("yes\n", "nodes", "setup", "web-1"); r.code != 0 || len(accepted.submitted) != 1 {
		t.Errorf("accepted: exit %d, %d submissions", r.code, len(accepted.submitted))
	}
}

func TestNodesSetupRefusesAPlanPolicyDenies(t *testing.T) {
	s := newSetupAPI(t, wire.Policy{Decision: "deny", Reason: smerr.ReasonDefaultDeny})

	r := s.run("nodes", "setup", "web-1", "--yes")

	if r.code == 0 || !strings.Contains(r.stderr, "deny") || len(s.submitted) != 0 {
		t.Errorf("exit %d, stderr %q, %d submissions", r.code, r.stderr, len(s.submitted))
	}
}

func TestNodesSetupGrantsTheUnitsAskedFor(t *testing.T) {
	s := newSetupAPI(t, approvalPolicy)

	r := s.run("nodes", "setup", "web-1", "--unit", "nginx.service", "--unit", "app.service:restart", "--yes")

	if r.code != 0 {
		t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
	}
	want := []any{"start nginx.service", "stop nginx.service", "restart nginx.service", "restart app.service"}
	if got := s.plans[0].Parameters["grants"]; !reflect.DeepEqual(got, want) {
		t.Errorf("grants = %v, want %v", got, want)
	}
	if !strings.Contains(r.stderr, "units: nginx.service (start, stop, restart), app.service (restart)") {
		t.Errorf("the plan must show the grants it writes: %q", r.stderr)
	}
}

func TestNodesSetupKeepsTheNodesGrantsUnlessToldOtherwise(t *testing.T) {
	current := &wire.Setup{Units: []wire.UnitGrant{{Unit: "nginx.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}}}}
	for name, tc := range map[string]struct {
		args   []string
		grants any
		shown  string
	}{
		"re-run keeps them":    {nil, []any{"restart nginx.service"}, "units: nginx.service (restart) (kept from the previous setup)"},
		"--unit replaces":      {[]string{"--unit", "app.service:stop"}, []any{"stop app.service"}, "units: app.service (stop) (was: nginx.service (restart))"},
		"--no-units drops all": {[]string{"--no-units"}, nil, "units: none (was: nginx.service (restart))"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSetupAPI(t, approvalPolicy)
			s.current = current

			r := s.run(append([]string{"nodes", "setup", "web-1", "--yes"}, tc.args...)...)

			if r.code != 0 {
				t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
			}
			if got := s.plans[0].Parameters["grants"]; !reflect.DeepEqual(got, tc.grants) {
				t.Errorf("grants = %#v, want %#v", got, tc.grants)
			}
			if !strings.Contains(r.stderr, tc.shown) {
				t.Errorf("stderr %q, want %q", r.stderr, tc.shown)
			}
		})
	}
}

func TestNodesSetupRerunKeepsDockerLogsAndTunnelUnlessGiven(t *testing.T) {
	for name, tc := range map[string]struct {
		args                 []string
		docker, logs, tunnel any
	}{
		"bare re-run keeps them":     {nil, "true", "broker", "true"},
		"explicit flags change them": {[]string{"--docker-access=false", "--logs-mode", "journal-group"}, "false", "journal-group", "true"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSetupAPI(t, approvalPolicy)
			s.current = &wire.Setup{DockerAccess: true, LogsMode: "broker"}
			s.endpoint = wire.Endpoint{Transport: domain.TransportCloudflare, TunnelHostname: "ssh-web-1.example.com"}

			r := s.run(append([]string{"nodes", "setup", "web-1", "--yes"}, tc.args...)...)

			p := s.plans[0].Parameters
			if r.code != 0 || p["docker_access"] != tc.docker || p["logs_mode"] != tc.logs || p["tunnel"] != tc.tunnel {
				t.Errorf("exit %d, parameters %v, want docker %v, logs %v, tunnel %v", r.code, p, tc.docker, tc.logs, tc.tunnel)
			}
		})
	}
}

func TestNodesSetupMergesARepeatedUnit(t *testing.T) {
	s := newSetupAPI(t, approvalPolicy)

	r := s.run("nodes", "setup", "web-1", "--unit", "a.service:restart", "--unit", "a.service:start", "--yes")

	if got, want := s.plans[0].Parameters["grants"], []any{"start a.service", "restart a.service"}; r.code != 0 || !reflect.DeepEqual(got, want) {
		t.Errorf("exit %d, grants %v, want %v", r.code, got, want)
	}
	if !strings.Contains(r.stderr, "units: a.service (start, restart)") {
		t.Errorf("stderr %q", r.stderr)
	}
}

func TestNodesSetupRefusesUnitsWithNoUnitsAndBadVerbs(t *testing.T) {
	for _, args := range [][]string{{"--unit", "a.service", "--no-units"}, {"--unit", "a.service:reload"}, {"--unit", ":restart"}} {
		s := newSetupAPI(t, approvalPolicy)

		r := s.run(append([]string{"nodes", "setup", "web-1", "--yes"}, args...)...)

		if r.code != exitUsage || len(s.plans) != 0 {
			t.Errorf("%v: exit %d, %d plans, stderr %q", args, r.code, len(s.plans), r.stderr)
		}
	}
}

func TestNodesSetupRejectsAnUnknownLogsModeBeforeAnyRequest(t *testing.T) {
	s := newSetupAPI(t, approvalPolicy)

	if r := s.run("nodes", "setup", "web-1", "--logs-mode", "syslog", "--yes"); r.code != exitUsage || len(s.Requests()) != 0 {
		t.Errorf("exit %d, %d requests", r.code, len(s.Requests()))
	}
}

type repinAPI struct {
	*fakeAPI
	scans   []wire.ScanHostKeyRequest
	patches []sentRequest
}

const (
	oldPrint = "SHA256:oldoldoldoldoldoldoldoldoldoldoldoldoldoldo"
	newPrint = "SHA256:newnewnewnewnewnewnewnewnewnewnewnewnewnewne"
	newKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKeyForTestsOnly000000000000"
)

func newRepinAPI(t *testing.T, scannedPrint string) *repinAPI {
	r := &repinAPI{}
	node := wire.Node{
		ID: idWeb, Name: "web-1", SpecRevision: 7,
		Endpoint: wire.Endpoint{Host: "10.0.0.5", Port: 2222, HostKeyFingerprintSHA256: oldPrint},
	}
	r.fakeAPI = newFakeAPI(t, router(routes{
		"GET " + wire.PathNodes: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Node]{Items: []wire.Node{node}})
		},
		"GET " + wire.Path(wire.PathNode, string(idWeb)): func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, node) },
		"POST " + wire.PathNodesSSHHostKey: func(w http.ResponseWriter, req *http.Request) {
			var scan wire.ScanHostKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&scan)
			r.scans = append(r.scans, scan)
			reply(w, 200, wire.HostKey{Type: "ssh-ed25519", AuthorizedKey: newKey, FingerprintSHA256: scannedPrint})
		},
		"PATCH " + wire.Path(wire.PathNode, string(idWeb)): func(w http.ResponseWriter, req *http.Request) {
			body, _ := io.ReadAll(req.Body)
			r.patches = append(r.patches, sentRequest{Header: req.Header.Clone(), Body: string(body)})
			reply(w, 200, wire.Direct[wire.Node]{Applied: &node})
		},
	}))
	return r
}

func TestNodesRepinScansConfirmsAndPatchesWithTheRevision(t *testing.T) {
	a := newRepinAPI(t, newPrint)

	r := a.run("nodes", "repin", "web-1", "--fingerprint", newPrint)

	if r.code != 0 || len(a.patches) != 1 {
		t.Fatalf("exit %d, patches %d, stderr %s", r.code, len(a.patches), r.stderr)
	}
	if a.scans[0].Host != "10.0.0.5" || a.scans[0].Port != 2222 {
		t.Errorf("scan = %+v, want the node's own endpoint", a.scans[0])
	}
	patch := a.patches[0]
	var body wire.NodePatch
	_ = json.Unmarshal([]byte(patch.Body), &body)
	if patch.Header.Get(wire.HeaderIfMatch) != "7" || body.HostPublicKey == nil || *body.HostPublicKey != newKey {
		t.Errorf("patch If-Match %q body %s", patch.Header.Get(wire.HeaderIfMatch), patch.Body)
	}
	for _, want := range []string{oldPrint, newPrint} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr does not show %s:\n%s", want, r.stderr)
		}
	}
}

func TestNodesRepinNeedsConfirmation(t *testing.T) {
	declined := newRepinAPI(t, newPrint)
	if r := declined.runIn("no\n", "nodes", "repin", "web-1"); r.code != exitUsage || len(declined.patches) != 0 {
		t.Errorf("declined: exit %d, %d patches", r.code, len(declined.patches))
	}
	accepted := newRepinAPI(t, newPrint)
	if r := accepted.runIn("yes\n", "nodes", "repin", "web-1"); r.code != 0 || len(accepted.patches) != 1 {
		t.Errorf("accepted: exit %d, %d patches", r.code, len(accepted.patches))
	}
}

func TestNodesRepinRefusesAFingerprintOtherThanTheOneYouVerified(t *testing.T) {
	a := newRepinAPI(t, newPrint)

	r := a.run("nodes", "repin", "web-1", "--fingerprint", "SHA256:somethingelse")

	if r.code == 0 || len(a.patches) != 0 || !strings.Contains(r.stderr, "not the expected") {
		t.Errorf("exit %d, %d patches, stderr %q", r.code, len(a.patches), r.stderr)
	}
}

func TestNodesRepinRefusesWhenTheKeyHasNotChanged(t *testing.T) {
	a := newRepinAPI(t, oldPrint)

	r := a.run("nodes", "repin", "web-1", "--fingerprint", oldPrint)

	if r.code != exitUsage || len(a.patches) != 0 || !strings.Contains(r.stderr, "nothing to re-pin") {
		t.Errorf("exit %d, %d patches, stderr %q", r.code, len(a.patches), r.stderr)
	}
}

// ---- ssh-key rotate and backups ----------------------------------------------------------------------------------------

func TestSSHKeyRotate(t *testing.T) {
	f := newFakeAPI(t, router(routes{
		"POST " + wire.PathSSHKeyRotate: func(w http.ResponseWriter, _ *http.Request) {
			appliedOrPending(w, &wire.SSHKey{Ref: "secret://ssh/default", Version: 3, FingerprintSHA256: "SHA256:abc"}, nil)
		},
	}))

	if r := f.run("ssh-key", "rotate"); r.code != exitUsage || len(f.Requests()) != 0 {
		t.Errorf("unconfirmed: exit %d, %d requests", r.code, len(f.Requests()))
	}
	r := f.run("ssh-key", "rotate", "--yes")
	if r.code != 0 || !strings.Contains(r.stdout, "version 3") || !strings.Contains(r.stdout, "sm nodes setup") {
		t.Errorf("exit %d, stdout %q", r.code, r.stdout)
	}
	if f.Requests()[0].Header.Get(wire.HeaderIdempotencyKey) == "" {
		t.Error("the rotation is keyed: it must carry an Idempotency-Key")
	}
}

func TestBackupCreateListAndTheAttachedRestore(t *testing.T) {
	f := newFakeAPI(t, router(routes{
		"POST " + wire.PathBackups: func(w http.ResponseWriter, _ *http.Request) { reply(w, 202, *awaiting("job-backup")) },
		"GET " + wire.PathBackups: func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, wire.Page[wire.Backup]{Items: []wire.Backup{{
				Name: "supermgmt-20261010T120000Z.tar.zst", SizeBytes: 4096, CreatedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
				SchemaVersion: 3, SMVersion: "0.2.0", KEKIDs: []domain.ID{kekID},
			}}})
		},
	}))

	create := f.run("backup", "create")
	list := f.run("backup", "list")
	help := f.run("backup", "--help")

	if create.code != 0 || !strings.Contains(create.stdout, "job-backup") {
		t.Errorf("create: exit %d, %q", create.code, create.stdout)
	}
	for _, want := range []string{"supermgmt-20261010T120000Z.tar.zst", "4096", string(kekID), "2026-10-10T12:00:00Z"} {
		if !strings.Contains(list.stdout, want) {
			t.Errorf("list lacks %q:\n%s", want, list.stdout)
		}
	}
	if !strings.Contains(help.stdout, "restore") {
		t.Errorf("sm backup --help does not list restore:\n%s", help.stdout)
	}
}

// ---- sm doctor against a running server ---------------------------------------------------------------------------------------

func TestDoctorAsksTheRunningServerOverItsAdminSocket(t *testing.T) {
	file, root := serverConfig(t)
	env := []string{"HOME=" + root}
	loaded, err := config.Load(file, env)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serving := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.RunServer(ctx, daemon.Options{Config: loaded.Config, ConfigFile: file, OnServing: func(daemon.Endpoints) { close(serving) }})
	}()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-serving:
	case err := <-done:
		t.Fatalf("the server stopped: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not start")
	}

	human := execRoot(env, "", []string{"doctor", "--config", file}, newDoctorCmd(env))
	asJSON := execRoot(env, "", []string{"doctor", "--json", "--config", file}, newDoctorCmd(env))

	if human.code != 0 {
		t.Fatalf("exit %d: %s %s", human.code, human.stdout, human.stderr)
	}
	for _, want := range []string{"mode", "server", "administrator", "bootstrap-code"} {
		if !strings.Contains(human.stdout, want) {
			t.Errorf("doctor lacks %q:\n%s", want, human.stdout)
		}
	}
	var report doctorReport
	if err := json.Unmarshal([]byte(asJSON.stdout), &report); err != nil || !report.OK || len(report.Checks) < 3 {
		t.Errorf("json = %q, %v", asJSON.stdout, err)
	}
}

func TestDoctorOnlineFailsAsAPrerequisiteWhenNoServerRuns(t *testing.T) {
	file, root := serverConfig(t)
	env := []string{"HOME=" + root}

	r := execRoot(env, "", []string{"doctor", "--config", file}, newDoctorCmd(env))

	if r.code != exitPrerequisite || !strings.Contains(r.stderr, "admin socket") || !strings.Contains(r.stderr, "--offline") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestServerChecksShowHoldAndMissingAdministratorAsWarnings(t *testing.T) {
	checks := serverChecks(wire.AdminDoctor{
		Mode: "server", RestoreHold: true, AdminBound: false,
		Checks: []wire.DoctorCheck{{Name: "tls", Status: "ok", Detail: "direct"}},
	})

	got := map[string]string{}
	for _, c := range checks {
		got[c.Name] = c.Status
	}
	want := fmt.Sprint(map[string]string{"mode": "ok", "restore_hold": "warn", "administrator": "warn", "tls": "ok"})
	if fmt.Sprint(got) != want {
		t.Errorf("checks = %v, want %s", got, want)
	}
}
