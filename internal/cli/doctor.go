package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	statusOK   = "ok"
	statusWarn = "warn"
	statusFail = "fail"

	integrityRowsShown = 5
)

type check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	OK     bool    `json:"ok"`
	Checks []check `json:"checks"`
}

func newDoctorCmd(env []string) *cobra.Command {
	var offline bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose configuration, paths and database health",
		Long: "Diagnose this machine. --offline checks the configuration, paths and database files without contacting\n" +
			"the service. Without it, doctor asks a running server what it can tell about itself over its admin\n" +
			"socket (run it as root or the service user).",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configFlag, _ := cmd.Flags().GetString("config")
			asJSON, _ := cmd.Flags().GetBool("json")
			var checks []check
			if offline {
				checks = offlineChecks(cmd.Context(), configPath(configFlag, env), env)
			} else {
				var err error
				if checks, err = onlineChecks(cmd, env); err != nil {
					return err
				}
			}
			report := newDoctorReport(checks)
			if err := writeDoctorReport(cmd.OutOrStdout(), report, asJSON); err != nil {
				return err
			}
			if !report.OK {
				return errors.New("doctor found failing checks")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "check this machine without contacting the daemon")
	return cmd
}

// onlineChecks asks the server's admin socket (spec §23.1) for its doctor
// report. Only a server has that socket: a local daemon is checked offline.
func onlineChecks(cmd *cobra.Command, env []string) ([]check, error) {
	configFlag, _ := cmd.Flags().GetString("config")
	file := configPath(configFlag, env)
	result, err := config.Load(file, env)
	if err != nil {
		return nil, usageErrorf("configuration %s is invalid: %s", file, joinProblems(configProblems(err)))
	}
	if result.Config.Instance.Mode != config.ModeServer {
		return nil, usageErrorf("online doctor asks a server over its admin socket; this configuration is local: use --offline")
	}
	admin := adminClient(result.Config.Server.AdminSocket)
	report, err := adminCall[wire.AdminDoctor](cmd.Context(), admin, http.MethodGet, wire.AdminPathDoctor, nil)
	if err != nil {
		return nil, fmt.Errorf("%w (use --offline when the server is stopped)", err)
	}
	return serverChecks(report), nil
}

// serverChecks turns the server's self-report into doctor rows: its state
// first, then each check it ran.
func serverChecks(r wire.AdminDoctor) []check {
	hold := check{"restore_hold", statusOK, "not held"}
	if r.RestoreHold {
		hold = check{"restore_hold", statusWarn, "writes are blocked until `sm admin restore-complete`"}
	}
	admin := check{"administrator", statusOK, "an administrator is bound"}
	if !r.AdminBound {
		admin = check{"administrator", statusWarn, "none yet: issue a code with `sm admin bootstrap-code`"}
	}
	checks := []check{{"mode", statusOK, r.Mode}, hold, admin}
	for _, c := range r.Checks {
		checks = append(checks, check{c.Name, c.Status, c.Detail})
	}
	return checks
}

func newDoctorReport(checks []check) doctorReport {
	report := doctorReport{OK: true, Checks: checks}
	for _, c := range checks {
		if c.Status == statusFail {
			report.OK = false
		}
	}
	return report
}

func writeDoctorReport(w io.Writer, r doctorReport, asJSON bool) error {
	if asJSON {
		return writeJSON(w, r)
	}
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(table, "STATUS\tCHECK\tDETAIL")
	for _, c := range r.Checks {
		_, _ = fmt.Fprintf(table, "%s\t%s\t%s\n", c.Status, c.Name, c.Detail)
	}
	return table.Flush()
}

// offlineChecks runs every offline check. Checks that need the configuration
// are omitted when it does not load.
func offlineChecks(ctx context.Context, configFile string, env []string) []check {
	result, err := config.Load(configFile, env)
	if err != nil {
		return []check{{"config", statusFail, fmt.Sprintf("%s: %s", configFile, strings.Join(configProblems(err), "; "))}}
	}
	cfg := result.Config
	checks := []check{
		{"config", statusOK, configFile},
		environmentCheck(result.Warnings),
		dataDirCheck(cfg.Instance.DataDir),
		socketCheck(socketPath(cfg, env)),
		databaseFileCheck(cfg.Storage.SQLite.Path),
	}
	return append(checks, databaseChecks(ctx, cfg.Storage.SQLite.Path, cfg.Security.KeysDir)...)
}

func environmentCheck(warnings []string) check {
	if len(warnings) == 0 {
		return check{"environment", statusOK, "no unrecognized SUPERMGMT_* variables"}
	}
	return check{"environment", statusWarn, strings.Join(warnings, "; ")}
}

func socketPath(cfg *config.Config, env []string) string {
	switch {
	case cfg.Instance.Mode == config.ModeServer:
		return cfg.Server.AdminSocket
	case cfg.Daemon.Socket != "":
		return cfg.Daemon.Socket
	}
	return localPaths(env).Socket
}

func dataDirCheck(dir string) check {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return check{"data_dir", statusWarn, dir + ": does not exist yet"}
	case err != nil:
		return check{"data_dir", statusFail, err.Error()}
	case !info.IsDir():
		return check{"data_dir", statusFail, dir + ": not a directory"}
	}
	return modeCheck("data_dir", dir, info.Mode(), 0o022, "writable by group or others")
}

// socketCheck inspects the socket's directory; the daemon creates it.
func socketCheck(socket string) check {
	if info, err := os.Lstat(socket); err == nil && info.Mode().Type() != fs.ModeSocket {
		return check{"socket", statusFail, socket + ": exists and is not a socket"}
	}
	dir := filepath.Dir(socket)
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return check{"socket", statusOK, socket + ": directory is created by the daemon"}
	case err != nil:
		return check{"socket", statusFail, err.Error()}
	}
	return modeCheck("socket", socket, info.Mode(), 0o022, "directory writable by group or others")
}

func databaseFileCheck(path string) check {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return check{"database_file", statusWarn, path + ": does not exist yet (the daemon creates it)"}
	case err != nil:
		return check{"database_file", statusFail, err.Error()}
	case !info.Mode().IsRegular():
		return check{"database_file", statusFail, path + ": not a regular file"}
	}
	return modeCheck("database_file", path, info.Mode(), 0o077, "accessible by group or others")
}

func modeCheck(name, path string, mode, forbidden fs.FileMode, problem string) check {
	perm := mode.Perm()
	if perm&forbidden != 0 {
		return check{name, statusWarn, fmt.Sprintf("%s: %s (mode %04o)", path, problem, perm)}
	}
	return check{name, statusOK, fmt.Sprintf("%s (mode %04o)", path, perm)}
}

// databaseChecks holds the database lock for as long as it inspects the file,
// so no daemon can start underneath it (spec §2.1.1).
func databaseChecks(ctx context.Context, path, keysDir string) []check {
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return []check{{"database_lock", statusWarn, "skipped: database directory does not exist"}}
	}
	lock, err := database.AcquireDatabaseLock(path)
	var held *database.LockHeldError
	switch {
	case errors.As(err, &held):
		return []check{{"database_lock", statusFail, heldDetail(held)}}
	case err != nil:
		return []check{{"database_lock", statusFail, err.Error()}}
	}
	defer func() { _ = lock.Release() }()

	checks := []check{{"database_lock", statusOK, "no other process holds " + lock.Path()}}
	if !fileExists(path) {
		return checks
	}
	checks = append(checks, inspectDatabase(ctx, path)...)
	if orphans, ok := orphanKeysCheck(ctx, path, keysDir); ok {
		checks = append(checks, orphans)
	}
	return checks
}

func heldDetail(held *database.LockHeldError) string {
	if held.PID == 0 {
		return "held by another process: " + held.Path
	}
	return fmt.Sprintf("held by PID %d (a daemon is running): %s", held.PID, held.Path)
}

// inspectDatabase reads the file read-only; it never migrates or writes.
func inspectDatabase(ctx context.Context, path string) []check {
	found, err := database.Inspect(ctx, path)
	if err != nil {
		return []check{{"schema", statusFail, err.Error()}}
	}
	latest, err := database.LatestSchemaVersion()
	if err != nil {
		return []check{{"schema", statusFail, err.Error()}}
	}
	return []check{schemaCheck(found, latest), integrityCheck(found.IntegrityFindings)}
}

func schemaCheck(found database.Inspection, latest int) check {
	current := found.SchemaVersion
	switch {
	case !found.HasSchema:
		return check{"schema", statusWarn, "database has no schema yet"}
	case current > latest:
		return check{"schema", statusFail, (&database.SchemaTooNewError{DatabaseVersion: current, BinaryVersion: latest}).Error()}
	case current < latest:
		return check{"schema", statusWarn, fmt.Sprintf("database schema version %d is behind this binary (%d); the daemon migrates on start", current, latest)}
	}
	return check{"schema", statusOK, fmt.Sprintf("version %d matches this binary", current)}
}

// integrityCheck reports PRAGMA integrity_check findings; none means ok.
func integrityCheck(findings []string) check {
	if len(findings) == 0 {
		return check{"integrity", statusOK, "PRAGMA integrity_check: ok"}
	}
	if len(findings) > integrityRowsShown {
		findings = append(findings[:integrityRowsShown:integrityRowsShown], "...")
	}
	return check{"integrity", statusFail, strings.Join(findings, "; ")}
}

// orphanKeysCheck warns about <id>.key files that nothing in the database
// refers to (no secret, no active setting, no kek_check record): a leftover of
// an interrupted rotation or an import, never loaded by the daemon (ADR-0021).
// It is omitted when there is no key directory or no schema to compare with.
// The caller holds the database lock.
func orphanKeysCheck(ctx context.Context, dbPath, keysDir string) (check, bool) {
	files, err := os.ReadDir(keysDir)
	if err != nil {
		return check{}, false
	}
	db, err := database.OpenReadOnly(ctx, dbPath)
	if err != nil {
		return check{"orphan_keys", statusWarn, "not checked: " + err.Error()}, true
	}
	defer func() { _ = db.Close() }()
	if has, err := db.HasSchema(ctx); err != nil || !has {
		return check{}, false
	}
	referenced, err := database.ReferencedKEKIDs(ctx, db.Querier())
	if err != nil {
		return check{"orphan_keys", statusWarn, "not checked: " + err.Error()}, true
	}
	var orphans []string
	for _, f := range files {
		id, isKey := strings.CutSuffix(f.Name(), ".key")
		if isKey && !slices.Contains(referenced, domain.ID(id)) {
			orphans = append(orphans, f.Name())
		}
	}
	if len(orphans) == 0 {
		return check{"orphan_keys", statusOK, "every key file in " + keysDir + " is referenced"}, true
	}
	return check{"orphan_keys", statusWarn, fmt.Sprintf("%s: not referenced by the database: %s (remove them once no backup needs them)", keysDir, strings.Join(orphans, ", "))}, true
}
