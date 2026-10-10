package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
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
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !offline {
				return usageErrorf("online doctor is not available yet; use --offline")
			}
			configFlag, _ := cmd.Flags().GetString("config")
			asJSON, _ := cmd.Flags().GetBool("json")
			report := newDoctorReport(offlineChecks(cmd.Context(), configPath(configFlag, env), env))
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
	return append(checks, databaseChecks(ctx, cfg.Storage.SQLite.Path)...)
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
func databaseChecks(ctx context.Context, path string) []check {
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
	return append(checks, inspectDatabase(ctx, path)...)
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
