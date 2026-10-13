package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
)

// runUpgrade replaces the installed binary (spec §29.3, ADR-0027).
func (in *Installer) runUpgrade(ctx context.Context, o Options) error {
	return in.upgrade(ctx, o, defaultHooks())
}

func (in *Installer) upgrade(ctx context.Context, o Options, h provisionHooks) error {
	in.reportHost()
	release, held, err := in.lockForAppliances()
	if err != nil {
		return err
	}
	defer release()
	rec, delegated, err := in.selectAppliance(o)
	if err != nil {
		return err
	}
	if delegated {
		return in.delegateUpgrade(ctx, o, rec)
	}
	t, err := in.installedTarget(o, true)
	if err != nil {
		return err
	}
	if t.server && !held {
		release, err := in.lockInstaller()
		if err != nil {
			return err
		}
		defer release()
	}
	return (&upgrader{in: in, d: in.d, o: o, h: h, t: t}).run(ctx)
}

// lockForAppliances takes the installer lock before the appliance record is even looked up, on a
// Proxmox host where the installer runs as root: the VMID the record names must not be purged,
// reused or upgraded by another installer between the selection and the last step.
func (in *Installer) lockForAppliances() (release func(), held bool, err error) {
	if in.d.PVE == nil || in.d.Host.UID != 0 {
		return func() {}, false, nil
	}
	release, err = in.lockInstaller()
	return release, err == nil, err
}

func (in *Installer) lockInstaller() (func(), error) {
	release, err := in.d.Files.Lock(installerLockPath)
	if err != nil {
		return nil, failWrap(ExitPrerequisite, "another SuperMgmt installer is running", err)
	}
	return release, nil
}

// upgrader is one upgrade of one installation: stop, back up, replace, start,
// each step recorded so a crash resumes or rolls back by phase.
type upgrader struct {
	in *Installer
	d  Deps
	o  Options
	h  provisionHooks
	t  upgradeTarget
	st upgradeState
}

func (u *upgrader) hit(point string) error {
	if err := u.h.at(point); err != nil {
		return err
	}
	return crashFromEnv(u.d.Host.Env, point)
}

func (u *upgrader) say(format string, args ...any) { u.in.say(format, args...) }

func (u *upgrader) newBinary() string { return firstNonEmpty(u.o.UpgradeBinary, u.o.Binary) }

func (u *upgrader) run(ctx context.Context) error {
	st, found, err := u.loadState()
	if err != nil {
		return err
	}
	switch {
	case !found || st.Phase == upDone:
		return u.fresh(ctx)
	case st.Phase == upFailed:
		u.st = st
		return u.holdFailed(ctx)
	}
	return u.resume(ctx, st)
}

// ---- fresh upgrade ----

func (u *upgrader) fresh(ctx context.Context) error {
	files, t := u.d.Files, u.t
	newBin := u.newBinary()
	if newBin == "" {
		return fail(ExitInvalid, "the new sm binary is unknown; pass --binary")
	}
	if !files.Exists(t.l.Binary) {
		return fail(ExitPrerequisite, "%s is not installed", t.l.Binary)
	}
	oldSHA, err := files.Hash(t.l.Binary)
	if err != nil {
		return failWrap(ExitConfiguration, "hash the installed sm", err)
	}
	newSHA, err := files.Hash(newBin)
	if err != nil {
		return failWrap(ExitInvalid, "read the new sm binary", err)
	}
	if oldSHA == newSHA {
		u.say("%s already is this build; nothing to upgrade", t.l.Binary)
		return nil
	}
	if err := u.checkDisk(newBin); err != nil {
		return err
	}
	if err := u.stage(newBin, newSHA); err != nil {
		return err
	}
	u.st = upgradeState{OldSHA256: oldSHA, NewSHA256: newSHA}
	if err := u.checkVersions(ctx); err != nil {
		_ = files.RemoveAll(t.staged())
		return err
	}
	if err := u.in.confirmPlan(u.o); err != nil {
		_ = files.RemoveAll(t.staged())
		return err
	}
	if err := u.linkPrevious(oldSHA); err != nil {
		return err
	}
	if err := u.hit("U:prev-linked"); err != nil {
		return err
	}
	if err := u.record(upPrepared); err != nil {
		return err
	}
	return u.advance(ctx)
}

// checkDisk needs room for the staged binary (twice, in case the previous one
// is copied rather than linked) and for the backup of the database.
func (u *upgrader) checkDisk(newBin string) error {
	disk := u.d.Files
	size, err := disk.FileSize(newBin)
	if err != nil {
		return failWrap(ExitInvalid, "read the new sm binary", err)
	}
	if err := u.requireFree(disk, u.t.l.BinDir, 2*uint64(size)); err != nil { //nolint:gosec // a file size is non-negative
		return err
	}
	if !u.in.hasData(u.t) {
		return nil
	}
	need := uint64(0)
	for _, f := range []string{u.t.dbPath, u.t.dbPath + "-wal"} {
		if u.d.Files.Exists(f) {
			n, err := disk.FileSize(f)
			if err != nil {
				return failWrap(ExitPrerequisite, "size "+f, err)
			}
			need += uint64(n) //nolint:gosec // a file size is non-negative
		}
	}
	return u.requireFree(disk, u.existingParent(u.t.backupsDir), need)
}

func (u *upgrader) existingParent(dir string) string {
	for dir != "/" && dir != "." && !u.d.Files.Exists(dir) {
		dir = filepath.Dir(dir)
	}
	return dir
}

func (u *upgrader) requireFree(disk Files, dir string, need uint64) error {
	free, err := disk.FreeBytes(dir)
	if err != nil {
		return failWrap(ExitPrerequisite, "check free space under "+dir, err)
	}
	if free < need+diskMargin {
		return fail(ExitPrerequisite, "not enough free space under %s: %d MiB free, %d MiB needed", dir, free>>20, (need+diskMargin)>>20)
	}
	return nil
}

func (u *upgrader) stage(src, wantSHA string) error {
	files, staged := u.d.Files, u.t.staged()
	if err := files.CopyFile(src, staged, 0o755, Owner{}); err != nil {
		return failWrap(ExitConfiguration, "stage the new sm", err)
	}
	got, err := files.Hash(staged)
	if err != nil || got != wantSHA {
		_ = files.RemoveAll(staged)
		return fail(ExitConfiguration, "the staged sm does not match the new binary")
	}
	if err := files.SyncDir(u.t.l.BinDir); err != nil {
		return failWrap(ExitConfiguration, "sync "+u.t.l.BinDir, err)
	}
	return u.hit("U:staged")
}

// checkVersions refuses a lower version unless --allow-downgrade. The staged
// binary reports its own version, run as the service user.
func (u *upgrader) checkVersions(ctx context.Context) error {
	from, err := u.version(ctx, u.t.l.Binary)
	if err != nil {
		return failWrap(ExitPrerequisite, "read the installed version", err)
	}
	to, err := u.version(ctx, u.t.staged())
	if err != nil {
		return failWrap(ExitPrerequisite, "the new sm does not run here", err)
	}
	u.st.FromVersion, u.st.ToVersion = from, to
	if from != to {
		cmp, comparable := compareVersions(from, to)
		switch {
		case comparable && cmp <= 0: // equal precedence (build metadata only) is not a downgrade
		case u.o.AllowDowngrade:
			u.st.AllowDowngrade = true
			u.say("downgrade %s -> %s allowed by --allow-downgrade; recorded in %s", from, to, u.t.statePath())
		case comparable:
			return fail(ExitInvalid, "refusing to downgrade from %s to %s; pass --allow-downgrade to do it deliberately", from, to)
		default:
			return fail(ExitInvalid, "cannot order version %q against %q, so a downgrade cannot be ruled out; pass --allow-downgrade to proceed", to, from)
		}
	}
	u.say("upgrade plan: %s -> %s; the service stops, a read-only backup is taken, then the binary is replaced", from, to)
	return nil
}

func (u *upgrader) version(ctx context.Context, bin string) (string, error) {
	out, err := u.d.Runner.Run(ctx, Command{Name: bin, Args: []string{"version", "--json"}, User: u.t.runAs})
	if err != nil {
		return "", err
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &v); err != nil || v.Version == "" {
		return "", errors.New("unreadable version output")
	}
	return v.Version, nil
}

// linkPrevious makes sm.prev a hard link to the live binary. The swap into
// place is a rename, so sm.prev is never missing once it exists, and a
// sm.prev that already holds the old binary is left alone.
func (u *upgrader) linkPrevious(oldSHA string) error {
	files, t := u.d.Files, u.t
	prev := t.previous()
	if sha, err := files.Hash(prev); err == nil && sha == oldSHA {
		return nil
	}
	tmp := prev + ".link"
	if err := files.RemoveAll(tmp); err != nil {
		return failWrap(ExitConfiguration, "clear "+tmp, err)
	}
	if err := files.Link(t.l.Binary, tmp); err != nil {
		if err := files.CopyFile(t.l.Binary, tmp, 0o755, Owner{}); err != nil {
			return failWrap(ExitConfiguration, "keep the previous sm", err)
		}
	}
	if err := files.Rename(tmp, prev); err != nil {
		return failWrap(ExitConfiguration, "keep the previous sm", err)
	}
	if err := files.SyncDir(t.l.BinDir); err != nil {
		return failWrap(ExitConfiguration, "sync "+t.l.BinDir, err)
	}
	if sha, err := files.Hash(prev); err != nil || sha != oldSHA {
		return fail(ExitConfiguration, "%s does not hold the installed binary", prev)
	}
	return nil
}

// ---- resume ----

func (u *upgrader) resume(ctx context.Context, st upgradeState) error {
	u.st = st
	u.say("an unfinished upgrade %s -> %s is at phase %s", st.FromVersion, st.ToVersion, st.Phase)
	if !st.beforeSwap() {
		return u.advance(ctx)
	}
	newBin := u.newBinary()
	if sha, err := u.d.Files.Hash(newBin); newBin == "" || err != nil || sha != st.NewSHA256 {
		u.say("this run does not carry that upgrade's binary; abandoning the unfinished upgrade")
		if err := u.abandon(ctx); err != nil {
			return err
		}
		return u.fresh(ctx)
	}
	if err := u.ensurePrepared(ctx, newBin); err != nil {
		return err
	}
	if err := u.retakeArchive(ctx); err != nil {
		if isCrash(err) {
			return err
		}
		return u.abortBeforeSwap(ctx, err)
	}
	return u.advance(ctx)
}

// ensurePrepared restores sm.new and sm.prev when a crash left them damaged.
func (u *upgrader) ensurePrepared(ctx context.Context, newBin string) error {
	files, t := u.d.Files, u.t
	live, err := files.Hash(t.l.Binary)
	if err != nil {
		return failWrap(ExitConfiguration, "hash the installed sm", err)
	}
	switch live {
	case u.st.NewSHA256:
		return nil // renamed into place just before the crash
	case u.st.OldSHA256:
	default:
		return fail(ExitConfiguration, "%s matches neither the old nor the new binary of the unfinished upgrade; inspect %s", t.l.Binary, t.statePath())
	}
	if sha, err := files.Hash(t.staged()); err != nil || sha != u.st.NewSHA256 {
		if err := u.stage(newBin, u.st.NewSHA256); err != nil {
			return err
		}
	}
	if err := u.linkPrevious(u.st.OldSHA256); err != nil {
		return err
	}
	return nil
}

// retakeArchive: an archive recorded before a crash is only as good as the guarantee that
// the database did not change after it. The service may have run again, and its WAL is not
// visible to a stopped-service check, so a resume in phase backed_up never trusts it: the
// service is quiesced, a new archive replaces it, and the superseded one is removed last.
func (u *upgrader) retakeArchive(ctx context.Context) error {
	if u.st.Phase != upBackedUp || !u.in.hasData(u.t) {
		return nil
	}
	if live, err := u.d.Files.Hash(u.t.l.Binary); err != nil || live != u.st.OldSHA256 {
		return nil // already swapped: nothing ran on the old database since
	}
	if err := u.quiesce(ctx); err != nil {
		return err
	}
	superseded := u.st.Archive
	if err := u.takeArchive(ctx); err != nil {
		return err
	}
	u.say("the unfinished upgrade's backup is retaken; the earlier one is removed")
	if err := u.record(upBackedUp); err != nil {
		return err
	}
	if superseded != "" && superseded != u.st.Archive {
		if err := u.d.Files.RemoveAll(superseded); err != nil {
			return fmt.Errorf("remove the superseded backup %s: %w", superseded, err)
		}
	}
	return u.hit("U:backup:retaken")
}

// abandon drops an upgrade that never replaced the binary and brings the old service back.
func (u *upgrader) abandon(ctx context.Context) error {
	live, err := u.d.Files.Hash(u.t.l.Binary)
	if err != nil || live != u.st.OldSHA256 {
		return fail(ExitConfiguration, "cannot abandon the unfinished upgrade: %s is not the old binary", u.t.l.Binary)
	}
	if err := u.forgetBackup(); err != nil {
		return err
	}
	if err := u.startService(ctx, "restart the old service"); err != nil {
		return err
	}
	_ = u.d.Files.RemoveAll(u.t.staged())
	return u.clearState()
}

// forgetBackup is recorded before the old service runs again: the backup
// taken so far goes stale then, so a crash from here on must resume by
// stopping the service and taking a new one.
func (u *upgrader) forgetBackup() error {
	u.st.Archive = ""
	return u.record(upPrepared)
}

// ---- the phases ----

func (u *upgrader) advance(ctx context.Context) error {
	for {
		phase := u.st.Phase
		switch phase {
		case upDone:
			u.say("upgraded sm %s -> %s; the previous binary is kept at %s", u.st.FromVersion, u.st.ToVersion, u.t.previous())
			return nil
		case upReverting:
			return u.revert(ctx)
		case upFailed:
			return u.holdFailed(ctx)
		case upPrepared, upStopped, upBackedUp, upSwapped, upStarted:
		}
		err := u.step(ctx, phase)
		switch {
		case err == nil:
		case isCrash(err):
			return err
		case u.st.beforeSwap():
			return u.abortBeforeSwap(ctx, err)
		default:
			return u.healthFailed(ctx, err)
		}
	}
}

func (u *upgrader) step(ctx context.Context, phase upgradePhase) error {
	switch phase {
	case upPrepared:
		return u.stopAndVerify(ctx)
	case upStopped:
		return u.backup(ctx)
	case upBackedUp:
		return u.swap()
	case upSwapped:
		return u.startNew(ctx)
	case upStarted:
		return u.awaitReady(ctx)
	case upDone, upReverting, upFailed:
	}
	return fail(ExitConfiguration, "unexpected upgrade phase %q", phase)
}

func (u *upgrader) stopAndVerify(ctx context.Context) error {
	if err := u.quiesce(ctx); err != nil {
		return err
	}
	if err := u.hit("U:stopped:applied"); err != nil {
		return err
	}
	return u.record(upStopped)
}

// serviceHolder is a ServiceManager that can keep a unit from starting by any route (manual,
// dependency, boot) until Register lifts the hold. Uninstall keeps using plain Disable.
type serviceHolder interface {
	Hold(ctx context.Context, unit Unit) error
}

// quiesce holds the service, stops it, verifies it terminated and that nobody holds the
// database. Every offline sm command takes the database lock itself, so the lock is proven
// free here (taken and released) rather than held across them.
func (u *upgrader) quiesce(ctx context.Context) error {
	if t := u.t; t.unit != nil {
		if err := u.holdService(ctx); err != nil {
			return err
		}
		if err := u.hit("U:hold:applied"); err != nil {
			return err
		}
		if err := t.services.Stop(ctx, *t.unit); err != nil {
			return fmt.Errorf("stop %s: %w", t.unit.Name, err)
		}
		if err := t.services.WaitStopped(ctx, *t.unit, stopTimeout); err != nil {
			return fmt.Errorf("verify %s terminated: %w", t.unit.Name, err)
		}
	}
	release, err := u.lockDatabase()
	if err != nil {
		return err
	}
	release()
	return nil
}

// holdService keeps the service from starting while the upgrade is unfinished. The hold is
// placed before Stop, so no start can slip in between, and lifted only by startService, the
// only way a version is brought back.
func (u *upgrader) holdService(ctx context.Context) error {
	t := u.t
	hold := t.services.Disable
	if h, ok := t.services.(serviceHolder); ok {
		hold = h.Hold
	}
	if err := hold(ctx, *t.unit); err != nil {
		return fmt.Errorf("keep %s from starting during the upgrade: %w", t.unit.Name, err)
	}
	return nil
}

// lockDatabase takes the lock the daemon takes, on the same canonical path, and returns its
// release. With no database, or no lock file yet, there is nothing to hold.
func (u *upgrader) lockDatabase() (release func(), err error) {
	if u.t.dbPath == "" {
		return func() {}, nil
	}
	lockFile, err := u.lockFilePath()
	if err != nil {
		return nil, err
	}
	if !u.d.Files.Exists(lockFile) {
		return func() {}, nil
	}
	release, err = u.d.Files.Lock(lockFile)
	if err != nil {
		return nil, fmt.Errorf("the database is still in use: %w", err)
	}
	return release, nil
}

// lockFilePath is "<canonical database path>.lock", as internal/database names it: the daemon
// resolves the directory, so a relative or symlinked configuration still meets the same file.
func (u *upgrader) lockFilePath() (string, error) {
	db, err := u.d.Files.Canonical(u.t.dbPath)
	if err != nil {
		return "", fmt.Errorf("resolve the database path %s: %w", u.t.dbPath, err)
	}
	return db + ".lock", nil
}

// ---- backup ----

type backupReport struct {
	Path          string `json:"path"`
	SchemaVersion int    `json:"schema_version"`
}

// backup is the pre-upgrade archive: taken by the new binary, which opens the
// database read-only and never migrates it, as the service user. Its schema
// must be the one the old binary reports.
func (u *upgrader) backup(ctx context.Context) error {
	if err := u.quiesce(ctx); err != nil { // a resumed run may find the service running again
		return err
	}
	if !u.in.hasData(u.t) {
		return u.record(upBackedUp)
	}
	if err := u.takeArchive(ctx); err != nil {
		return err
	}
	if err := u.hit("U:backed_up:applied"); err != nil {
		return err
	}
	return u.record(upBackedUp)
}

// takeArchive runs the offline backup and keeps its path and schema in the state (in memory).
func (u *upgrader) takeArchive(ctx context.Context) error {
	before, err := u.schemaVersion(ctx, u.t.l.Binary)
	if err != nil {
		return fmt.Errorf("read the schema version before the upgrade: %w", err)
	}
	out, err := u.d.Runner.Run(ctx, Command{
		Name: u.t.staged(), Args: []string{"backup", "create", "--offline", "--json", "--config", u.t.l.ConfigFile}, User: u.t.runAs,
	})
	if err != nil {
		return fmt.Errorf("pre-upgrade backup: %w", err)
	}
	var report backupReport
	if err := json.Unmarshal(out, &report); err != nil || report.Path == "" {
		return errors.New("pre-upgrade backup: unreadable report")
	}
	if report.SchemaVersion != before {
		return fmt.Errorf("pre-upgrade backup has schema version %d, the database is at %d", report.SchemaVersion, before)
	}
	if !u.d.Files.Exists(report.Path) {
		return fmt.Errorf("pre-upgrade backup %s was reported but is not there", report.Path)
	}
	u.st.SchemaBefore, u.st.Archive = before, report.Path
	u.say("pre-upgrade backup: %s (schema %d)", report.Path, before)
	return nil
}

var (
	reSchemaMatches = regexp.MustCompile(`^version (\d+) matches`)
	reSchemaBehind  = regexp.MustCompile(`schema version (\d+) is behind`)
)

// doctorReport is the part of `sm doctor --offline --json` the upgrader reads. FormatVersion
// is absent (zero) in binaries that predate the stable contract.
type doctorReport struct {
	FormatVersion         int                                     `json:"format_version"`
	DatabaseSchemaVersion *int                                    `json:"database_schema_version"`
	Checks                []struct{ Name, Status, Detail string } `json:"checks"`
}

// schemaVersion asks bin's offline doctor which schema the database is at.
// A failing doctor still prints its report, so only a missing report is an error.
func (u *upgrader) schemaVersion(ctx context.Context, bin string) (int, error) {
	out, err := u.d.Runner.Run(ctx, Command{
		Name: bin, Args: []string{"doctor", "--offline", "--json", "--config", u.t.l.ConfigFile}, User: u.t.runAs,
	})
	var report doctorReport
	if jsonErr := json.Unmarshal(out, &report); jsonErr != nil {
		return 0, fmt.Errorf("doctor --offline gave no report (%w)", errors.Join(err, jsonErr))
	}
	if report.FormatVersion > 0 {
		if report.DatabaseSchemaVersion == nil {
			return 0, errors.New("doctor reports no database schema version")
		}
		return *report.DatabaseSchemaVersion, nil
	}
	return report.schemaFromText()
}

// schemaFromText reads the schema check of a pre-M6 binary, which only describes it in prose.
func (r doctorReport) schemaFromText() (int, error) {
	for _, c := range r.Checks {
		if c.Name != "schema" {
			continue
		}
		for _, re := range []*regexp.Regexp{reSchemaMatches, reSchemaBehind} {
			if m := re.FindStringSubmatch(c.Detail); m != nil {
				return strconv.Atoi(m[1])
			}
		}
		return 0, fmt.Errorf("doctor reports the schema as %s: %s", c.Status, c.Detail)
	}
	return 0, errors.New("doctor reports no schema check")
}

// ---- swap, start, health ----

func (u *upgrader) swap() error {
	files, t := u.d.Files, u.t
	live, err := files.Hash(t.l.Binary)
	if err != nil {
		return fmt.Errorf("hash %s: %w", t.l.Binary, err)
	}
	switch live {
	case u.st.NewSHA256: // renamed before a crash
	case u.st.OldSHA256:
		release, err := u.lockDatabase() // held until the rename is durable
		if err != nil {
			return err
		}
		defer release()
		if sha, err := files.Hash(t.staged()); err != nil || sha != u.st.NewSHA256 {
			return fmt.Errorf("%s is missing or changed", t.staged())
		}
		if err := u.recordDowngrade(); err != nil {
			return err
		}
		if err := u.hit("U:swap:before"); err != nil {
			return err
		}
		if err := files.Rename(t.staged(), t.l.Binary); err != nil {
			return fmt.Errorf("replace %s: %w", t.l.Binary, err)
		}
		if err := files.SyncDir(t.l.BinDir); err != nil {
			return fmt.Errorf("sync %s: %w", t.l.BinDir, err)
		}
		if err := u.hit("U:swap:renamed"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s matches neither the old nor the new binary", t.l.Binary)
	}
	return u.record(upSwapped)
}

func (u *upgrader) startNew(ctx context.Context) error {
	if err := u.startService(ctx, "start the new version"); err != nil {
		return err
	}
	if err := u.hit("U:started:applied"); err != nil {
		return err
	}
	return u.record(upStarted)
}

func (u *upgrader) startService(ctx context.Context, what string) error {
	t := u.t
	if t.unit == nil {
		return nil
	}
	if err := t.services.Register(ctx, *t.unit); err != nil { // lifts the hold
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := t.services.Start(ctx, *t.unit); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

func (u *upgrader) awaitReady(ctx context.Context) error {
	if err := u.waitReady(ctx); err != nil {
		return err
	}
	return u.record(upDone)
}

func (u *upgrader) waitReady(ctx context.Context) error {
	if !u.t.server {
		return nil
	}
	probe, err := u.in.probe(u.t.l)
	if err != nil {
		return err
	}
	if err := u.d.Health.WaitReady(ctx, probe, readyTimeout); err != nil {
		return fmt.Errorf("the service did not become ready: %w", err)
	}
	return nil
}

// ---- failure policy (Q7) ----

// abortBeforeSwap handles a failure before the binary was replaced: the old
// service is started again and the staged files are dropped. It refuses to
// claim that when the live binary is not the old one.
func (u *upgrader) abortBeforeSwap(ctx context.Context, cause error) error {
	live, err := u.d.Files.Hash(u.t.l.Binary)
	if err != nil || live != u.st.OldSHA256 {
		return failWrap(ExitConfiguration, "upgrade failed with the binary in an unexpected state; rerun to resume", cause)
	}
	if err := u.forgetBackup(); err != nil {
		return err
	}
	_ = u.d.Files.RemoveAll(u.t.staged())
	outcome := "the previous version is running again"
	if err := u.startService(ctx, "restart the previous version"); err != nil {
		outcome = fmt.Sprintf("the previous version could NOT be restarted (%v); start it by hand", err)
	} else if err := u.hit("U:abort:restarted"); err != nil {
		return err
	}
	if err := u.clearState(); err != nil {
		return err
	}
	return &Error{Code: ExitRestore, Err: fmt.Errorf("upgrade aborted before the binary was replaced: %w; %s", cause, outcome)}
}

// healthFailed handles a failure after the binary was replaced: stop, then
// look at the schema. Unchanged: the previous binary goes back automatically.
// Advanced (or unknown): the service stays stopped and the operator restores.
func (u *upgrader) healthFailed(ctx context.Context, cause error) error {
	u.say("the new version failed its health check: %v", cause)
	if err := u.quiesce(ctx); err != nil {
		return failWrap(ExitRestore, "could not stop the failed version", err)
	}
	if u.schemaAdvanced(ctx) {
		return u.failAdvanced()
	}
	if err := u.record(upReverting); err != nil {
		return err
	}
	return u.revert(ctx)
}

func (u *upgrader) failAdvanced() error {
	if err := u.record(upFailed); err != nil {
		return err
	}
	return u.reportAdvanced()
}

// holdFailed is every visit to an upgrade that ended with the schema advanced: whatever started
// the service since (a reboot, an operator), it is stopped and verified again before the
// restore instructions are shown.
func (u *upgrader) holdFailed(ctx context.Context) error {
	if err := u.quiesce(ctx); err != nil {
		return failWrap(ExitRestore, "could not stop the failed version", err)
	}
	return u.reportAdvanced()
}

func (u *upgrader) schemaAdvanced(ctx context.Context) bool {
	if !u.in.hasData(u.t) {
		return false
	}
	now, err := u.schemaVersion(ctx, u.t.l.Binary)
	return err != nil || now != u.st.SchemaBefore
}

// revert puts the previous binary back (a link of sm.prev renamed over sm, so
// sm.prev stays) and starts it.
func (u *upgrader) revert(ctx context.Context) error {
	files, t := u.d.Files, u.t
	if err := u.quiesce(ctx); err != nil {
		return failWrap(ExitRestore, "could not stop the failed version", err)
	}
	if u.schemaAdvanced(ctx) { // the failed version may have migrated since the decision to revert
		return u.failAdvanced()
	}
	live, err := files.Hash(t.l.Binary)
	if err != nil {
		return failWrap(ExitRestore, "hash the installed sm", err)
	}
	if live != u.st.OldSHA256 {
		if err := u.restorePrevious(); err != nil {
			return failWrap(ExitRestore, "restore the previous binary; the service stays stopped", err)
		}
		if err := u.hit("U:revert:renamed"); err != nil {
			return err
		}
	}
	startErr := u.startService(ctx, "start the previous version")
	if err := u.hit("U:revert:started"); err != nil {
		return err
	}
	readyErr := error(nil)
	if startErr == nil {
		readyErr = u.waitReady(ctx)
	}
	_ = files.RemoveAll(t.staged())
	if err := u.clearState(); err != nil {
		return err
	}
	outcome := "the previous version was restored and started"
	if err := errors.Join(startErr, readyErr); err != nil {
		outcome = fmt.Sprintf("the previous binary was restored but the service is not healthy: %v", err)
	}
	return fail(ExitRestore, "upgrade to %s failed and was reverted: %s", u.st.ToVersion, outcome)
}

func (u *upgrader) restorePrevious() error {
	files, t := u.d.Files, u.t
	if sha, err := files.Hash(t.previous()); err != nil || sha != u.st.OldSHA256 {
		return fmt.Errorf("%s does not hold the previous binary", t.previous())
	}
	tmp := t.l.Binary + ".revert"
	if err := files.RemoveAll(tmp); err != nil {
		return err
	}
	if err := files.Link(t.previous(), tmp); err != nil {
		if err := files.CopyFile(t.previous(), tmp, 0o755, Owner{}); err != nil {
			return err
		}
	}
	if err := files.Rename(tmp, t.l.Binary); err != nil {
		return err
	}
	return files.SyncDir(t.l.BinDir)
}

// reportAdvanced is the end of an upgrade whose migrations already ran: the
// database is restored from the archive by the operator, never automatically.
func (u *upgrader) reportAdvanced() error {
	t, st := u.t, u.st
	restore := "sm backup restore --offline " + st.Archive
	if t.runAs != "" {
		restore = "runuser -u " + t.runAs + " -- " + t.l.Binary + " backup restore --offline " + st.Archive + " --config " + t.l.ConfigFile
	}
	u.say("The new version %s failed and the database schema moved past %d, so nothing was restored automatically.\n"+
		"The service is left STOPPED. Pre-upgrade backup: %s\n"+
		"To return to %s:\n"+
		"  1. cp -p %s %s.revert && mv -f %s.revert %s\n"+
		"  2. %s\n"+
		"  3. rm %s && systemctl enable --now %s\n"+
		"(On a new host: sm install restore --archive %s --key-export <your key export>.)",
		st.ToVersion, st.SchemaBefore, st.Archive, st.FromVersion,
		t.previous(), t.l.Binary, t.l.Binary, t.l.Binary, restore, t.statePath(), UnitName, st.Archive)
	return fail(ExitRestore, "upgrade to %s failed after the database schema advanced; the service is stopped (restore commands printed above)", st.ToVersion)
}
