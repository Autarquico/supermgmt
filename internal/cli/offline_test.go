package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
)

// sandbox is a throwaway HOME with a local-mode config pointing at it.
type sandbox struct {
	dir        string
	env        []string
	configFile string
	dbPath     string
}

func newSandbox(t *testing.T) sandbox {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "data")
	writeFile(t, filepath.Join(dir, "config.yaml"),
		"version: 1\ninstance:\n  name: test\n  mode: local\n  data_dir: "+dataDir+"\ndaemon:\n  socket: "+filepath.Join(dir, "run", "sm.sock")+"\n")
	return sandbox{
		dir:        dir,
		env:        []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "xdg")},
		configFile: filepath.Join(dir, "config.yaml"),
		dbPath:     filepath.Join(dataDir, "supermgmt.db"),
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// migratedDatabase creates the data dir (0700) and a migrated database (0600).
func (s sandbox) migratedDatabase(t *testing.T) {
	t.Helper()
	dataDir := filepath.Dir(s.dbPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), s.dbPath, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.dbPath, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s sandbox) run(args ...string) result {
	if !slices.Contains(args, "--config") {
		args = append(slices.Clone(args), "--config", s.configFile)
	}
	r := runWithEnv(s.env, args...)
	r.stdout = s.normalize(r.stdout)
	r.stderr = s.normalize(r.stderr)
	return r
}

func (s sandbox) normalize(out string) string {
	out = strings.ReplaceAll(out, s.dir, "<tmp>")
	return strings.ReplaceAll(out, "PID "+strconv.Itoa(os.Getpid()), "PID <pid>")
}

func (s sandbox) writeConfig(t *testing.T, body string) {
	t.Helper()
	writeFile(t, s.configFile, body)
}

func TestConfigValidateAcceptsExamples(t *testing.T) {
	r := runWithEnv([]string{"HOME=" + t.TempDir()}, "config", "validate",
		"--config", "../../examples/config.yaml", "--policy", "../../examples/policies.yaml")
	if r.code != 0 {
		t.Fatalf("code = %d, stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestConfigValidateOutput(t *testing.T) {
	s := newSandbox(t)
	policyFile := filepath.Join(s.dir, "policy.yaml")
	writeFile(t, policyFile, `version: 1
rules:
  - name: ops-read
    subjects: ["role:operator"]
    allow: ["node.read"]
`)
	tests := []struct {
		golden string
		setup  func()
		args   []string
		code   int
	}{
		{"validate.ok.human.golden", func() {}, []string{"config", "validate"}, 0},
		{"validate.ok.json.golden", func() {}, []string{"config", "validate", "--json"}, 0},
		{"validate.policy.human.golden", func() {}, []string{"config", "validate", "--policy", policyFile}, 0},
		{"validate.invalid.human.golden", func() {
			s.writeConfig(t, "version: 1\ninstance:\n  mode: local\n  nope: 1\nbogus: true\n")
		}, []string{"config", "validate"}, 2},
		{"validate.invalid.json.golden", func() {}, []string{"config", "validate", "--json"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			tt.setup()
			r := s.run(tt.args...)
			if r.code != tt.code {
				t.Fatalf("code = %d, want %d (stdout %q stderr %q)", r.code, tt.code, r.stdout, r.stderr)
			}
			assertGolden(t, tt.golden, r.stdout)
		})
	}
}

func TestConfigValidateUnknownFieldReportsPathAndLine(t *testing.T) {
	s := newSandbox(t)
	s.writeConfig(t, "version: 1\nui:\n  colour: red\n")
	r := s.run("config", "validate")
	if r.code != 2 || !strings.Contains(r.stdout, "ui.colour (line 3): unknown field") {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
}

func TestConfigValidateReportsEveryProblem(t *testing.T) {
	s := newSandbox(t)
	s.writeConfig(t, "version: 1\nfoo: 1\nbar: 2\n")
	r := s.run("config", "validate", "--json")
	var report validateReport
	if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Config.Problems) != 2 {
		t.Errorf("problems = %v, want both unknown fields", report.Config.Problems)
	}
}

func TestConfigValidateExitCodes(t *testing.T) {
	s := newSandbox(t)
	badPolicy := filepath.Join(s.dir, "bad.yaml")
	writeFile(t, badPolicy, "version: 1\nrules:\n  - name: x\n    subjects: []\n    allow: [\"*\"]\n")
	tests := []struct {
		name string
		args []string
		code int
	}{
		{"missing config file", []string{"config", "validate", "--config", filepath.Join(s.dir, "absent.yaml")}, 2},
		{"missing policy file", []string{"config", "validate", "--policy", filepath.Join(s.dir, "absent.yaml")}, 2},
		{"invalid policy", []string{"config", "validate", "--policy", badPolicy}, 2},
		{"valid", []string{"config", "validate"}, 0},
		{"unexpected argument", []string{"config", "validate", "extra"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r := s.run(tt.args...); r.code != tt.code {
				t.Fatalf("code = %d, want %d (stdout %q stderr %q)", r.code, tt.code, r.stdout, r.stderr)
			}
		})
	}
}

func TestConfigValidateNeverTouchesTheDataDir(t *testing.T) {
	s := newSandbox(t)
	if r := s.run("config", "validate"); r.code != 0 {
		t.Fatalf("code = %d: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Dir(s.dbPath)); !os.IsNotExist(err) {
		t.Errorf("data dir was created by validate (stat err = %v)", err)
	}
}

func TestConfigValidateWarnsAboutUnknownEnvironment(t *testing.T) {
	s := newSandbox(t)
	s.env = append(s.env, "SUPERMGMT_NOT_A_THING=1")
	r := s.run("config", "validate")
	if r.code != 0 || !strings.Contains(r.stdout, "warning: unknown environment variable SUPERMGMT_NOT_A_THING ignored") {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
}

func TestConfigValidateUsesDefaultLocation(t *testing.T) {
	s := newSandbox(t)
	defaultConfig := localPaths(s.env).Config
	writeFile(t, defaultConfig, "version: 1\ninstance:\n  mode: local\n")
	r := runWithEnv(s.env, "config", "validate")
	if r.code != 0 || !strings.Contains(r.stdout, "config: "+defaultConfig+": valid") {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
}

func TestDoctorHealthyDatabase(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)
	for _, tt := range []struct{ golden, flag string }{
		{"doctor.ok.human.golden", ""},
		{"doctor.ok.json.golden", "--json"},
	} {
		t.Run(tt.golden, func(t *testing.T) {
			args := []string{"doctor", "--offline"}
			if tt.flag != "" {
				args = append(args, tt.flag)
			}
			r := s.run(args...)
			if r.code != 0 {
				t.Fatalf("code = %d, stdout %q stderr %q", r.code, r.stdout, r.stderr)
			}
			assertGolden(t, tt.golden, r.stdout)
		})
	}
}

func TestDoctorMissingDatabaseWarnsAndIsNotCreated(t *testing.T) {
	s := newSandbox(t)
	r := s.run("doctor", "--offline")
	if r.code != 0 {
		t.Fatalf("code = %d, stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
	assertGolden(t, "doctor.nodb.human.golden", r.stdout)
	if _, err := os.Stat(s.dbPath); !os.IsNotExist(err) {
		t.Errorf("doctor created the database (stat err = %v)", err)
	}
}

func TestDoctorFailsWhileADaemonHoldsTheLock(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)
	lock, err := database.AcquireDatabaseLock(s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	r := s.run("doctor", "--offline")
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if r.code != 1 {
		t.Fatalf("code = %d, want 1", r.code)
	}
	assertGolden(t, "doctor.locked.human.golden", r.stdout)
}

func TestDoctorReleasesTheLockWhenDone(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)
	if r := s.run("doctor", "--offline"); r.code != 0 {
		t.Fatalf("code = %d: %s", r.code, r.stdout)
	}
	lock, err := database.AcquireDatabaseLock(s.dbPath)
	if err != nil {
		t.Fatalf("lock still held after doctor: %v", err)
	}
	_ = lock.Release()
}

func TestDoctorFailsOnSchemaNewerThanBinary(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)
	ctx := context.Background()
	db, err := database.Open(ctx, s.dbPath, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (999999, 0)`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.dbPath, 0o600); err != nil {
		t.Fatal(err)
	}

	r := s.run("doctor", "--offline")
	if r.code != 1 {
		t.Fatalf("code = %d, want 1", r.code)
	}
	assertGolden(t, "doctor.toonew.human.golden", r.stdout)
}

func TestDoctorFailsOnACorruptDatabaseFile(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)
	writeFile(t, s.dbPath, strings.Repeat("this is not a sqlite database. ", 200))
	r := s.run("doctor", "--offline")
	if r.code != 1 || !strings.Contains(r.stdout, "fail    schema") {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
}

func TestDoctorWarnsAboutUnknownEnvironmentAndLooseModes(t *testing.T) {
	s := newSandbox(t)
	s.migratedDatabase(t)
	if err := os.Chmod(s.dbPath, 0o644); err != nil {
		t.Fatal(err)
	}
	s.env = append(s.env, "SUPERMGMT_MYSTERY=1")
	r := s.run("doctor", "--offline")
	if r.code != 0 {
		t.Fatalf("warnings must not fail doctor, code = %d", r.code)
	}
	for _, want := range []string{"warn    environment", "SUPERMGMT_MYSTERY", "warn    database_file", "mode 0644"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in\n%s", want, r.stdout)
		}
	}
}

func TestDoctorReportsAnInvalidConfig(t *testing.T) {
	s := newSandbox(t)
	s.writeConfig(t, "version: 1\nbogus: 1\n")
	r := s.run("doctor", "--offline", "--json")
	if r.code != 1 {
		t.Fatalf("code = %d, want 1", r.code)
	}
	var report doctorReport
	if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.OK || len(report.Checks) != 1 || report.Checks[0].Name != "config" || report.Checks[0].Status != "fail" {
		t.Errorf("report = %+v", report)
	}
}
