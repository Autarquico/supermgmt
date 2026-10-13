package installer

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
)

// upgradePhase is where an upgrade stands (ADR-0027). Each phase names an
// effect that is complete, so every step can be redone after a crash.
type upgradePhase string

const (
	upPrepared  upgradePhase = "prepared"  // sm.new staged, sm.prev linked
	upStopped   upgradePhase = "stopped"   // service stopped, termination verified
	upBackedUp  upgradePhase = "backed_up" // read-only offline backup taken
	upSwapped   upgradePhase = "swapped"   // live binary replaced
	upStarted   upgradePhase = "started"   // service (re)started
	upDone      upgradePhase = "done"
	upReverting upgradePhase = "reverting" // health failed, schema unchanged: restoring the previous binary
	upFailed    upgradePhase = "failed"    // health failed, schema advanced: stopped, manual restore
)

const (
	upgradeStateFile = "upgrade.json"
	stopTimeout      = 90 * time.Second
	probeTimeout     = 3 * time.Second // a service that is stopped answers at once
	diskMargin       = 16 << 20
)

// upgradeState is /var/lib/supermgmt/upgrade.json. It never holds a secret.
type upgradeState struct {
	Phase          upgradePhase `json:"phase"`
	FromVersion    string       `json:"from_version"`
	ToVersion      string       `json:"to_version"`
	OldSHA256      string       `json:"old_sha256"`
	NewSHA256      string       `json:"new_sha256"`
	SchemaBefore   int          `json:"schema_before,omitempty"`
	Archive        string       `json:"archive,omitempty"`
	Superseded     []string     `json:"superseded,omitempty"` // replaced archives not yet removed
	AllowDowngrade bool         `json:"allow_downgrade,omitempty"`
	StartedAt      time.Time    `json:"started_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// beforeSwap says the live binary is still the old one (or just became the new one).
func (s upgradeState) beforeSwap() bool {
	switch s.Phase {
	case upPrepared, upStopped, upBackedUp:
		return true
	case upSwapped, upStarted, upDone, upReverting, upFailed:
	}
	return false
}

// upgradeTarget is the installation an upgrade or uninstall acts on.
type upgradeTarget struct {
	l          layout
	unit       *Unit          // nil: nothing to stop or start
	services   ServiceManager // manages unit
	runAs      string         // account for offline sm commands ("" = the caller)
	server     bool           // a system service with an HTTP readiness endpoint
	dbPath     string         // "" when there is no database
	backupsDir string
}

func (t upgradeTarget) staged() string   { return t.l.Binary + ".new" }
func (t upgradeTarget) previous() string { return t.l.Binary + ".prev" }
func (t upgradeTarget) statePath() string {
	return filepath.Join(t.l.DataDir, upgradeStateFile)
}

// installedTarget finds what is installed: a server (system service) wins over
// a local or client install. An upgrade also needs to know where the database
// is; an uninstall must work even when the configuration is damaged.
func (in *Installer) installedTarget(o Options, withStorage bool) (upgradeTarget, error) {
	files := in.d.Files
	if sl := o.serverLayout(); files.Exists(sl.Binary) || files.Exists(sl.UnitPath) {
		if err := in.requireSystemdRoot(); err != nil {
			return upgradeTarget{}, err
		}
		t := upgradeTarget{
			l: sl, unit: &Unit{Name: UnitName, Path: sl.UnitPath}, services: in.d.Services,
			runAs: ServiceUser, server: true,
		}
		return in.storageIf(withStorage, t)
	}
	ul := o.userLayout(in.d.Host)
	unit, _ := in.residentUnit(ul)
	resident := files.Exists(unit.Path)
	if !files.Exists(ul.Binary) && !resident {
		return upgradeTarget{}, fail(ExitPrerequisite, "no SuperMgmt installation found (looked for %s and %s)", o.serverLayout().Binary, ul.Binary)
	}
	t := upgradeTarget{l: ul}
	if resident {
		t.unit, t.services = &unit, in.d.UserServices
	}
	return in.storageIf(withStorage, t)
}

func (in *Installer) storageIf(wanted bool, t upgradeTarget) (upgradeTarget, error) {
	if !wanted {
		return t, nil
	}
	return in.withStorage(t)
}

// withStorage reads where the database and the backups live from the configuration.
func (in *Installer) withStorage(t upgradeTarget) (upgradeTarget, error) {
	if !in.d.Files.Exists(t.l.ConfigFile) {
		return t, nil
	}
	raw, err := in.d.Files.ReadFile(t.l.ConfigFile)
	if err != nil {
		return t, failWrap(ExitConfiguration, "read configuration", err)
	}
	res, err := config.LoadBytes(raw, nil)
	if err != nil {
		return t, failWrap(ExitConfiguration, "load configuration", err)
	}
	t.dbPath, t.backupsDir = res.Config.Storage.SQLite.Path, res.Config.Backup.Directory
	return t, nil
}

func (in *Installer) hasData(t upgradeTarget) bool {
	return t.dbPath != "" && in.d.Files.Exists(t.dbPath)
}

// ---- state file ----

func (u *upgrader) loadState() (upgradeState, bool, error) {
	raw, err := u.d.Files.ReadFile(u.t.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return upgradeState{}, false, nil
	}
	if err != nil {
		return upgradeState{}, false, failWrap(ExitConfiguration, "read the upgrade state", err)
	}
	var st upgradeState
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, false, failWrap(ExitConfiguration, "the upgrade state "+u.t.statePath()+" is unreadable; inspect it before upgrading", err)
	}
	if st.StartedAt.IsZero() {
		st.StartedAt = st.UpdatedAt // a state written before StartedAt existed
	}
	return st, true, nil
}

// record makes phase durable (temp file, fsync, rename, directory fsync).
func (u *upgrader) record(phase upgradePhase) error {
	now := u.d.Clock.Now().UTC()
	if u.st.StartedAt.IsZero() {
		u.st.StartedAt = now
	}
	u.st.Phase, u.st.UpdatedAt = phase, now
	data, err := json.MarshalIndent(u.st, "", "  ")
	if err != nil {
		return failWrap(ExitConfiguration, "render the upgrade state", err)
	}
	if err := u.d.Files.WriteFile(u.t.statePath(), append(data, '\n'), 0o600, Owner{}); err != nil {
		return failWrap(ExitConfiguration, "write the upgrade state", err)
	}
	if err := u.d.Files.SyncDir(u.t.l.DataDir); err != nil {
		return failWrap(ExitConfiguration, "sync "+u.t.l.DataDir, err)
	}
	return u.hit("U:" + string(phase) + ":recorded")
}

func (u *upgrader) clearState() error {
	if err := u.d.Files.RemoveAll(u.t.statePath()); err != nil {
		return failWrap(ExitConfiguration, "remove the upgrade state", err)
	}
	return u.d.Files.SyncDir(u.t.l.DataDir)
}

// ---- versions ----

type semver struct {
	nums [3]int
	pre  []string
}

func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	s, _, _ = strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		v.nums[i] = n
	}
	if hasPre {
		if pre == "" {
			return semver{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

// compareVersions orders two release versions; ok is false when either is not semver.
func compareVersions(a, b string) (cmp int, ok bool) {
	x, okA := parseSemver(a)
	y, okB := parseSemver(b)
	if !okA || !okB {
		return 0, false
	}
	for i := range x.nums {
		if x.nums[i] != y.nums[i] {
			return x.nums[i] - y.nums[i], true
		}
	}
	return comparePrerelease(x.pre, y.pre), true
}

// comparePrerelease follows semver: a release outranks any prerelease, numeric
// identifiers rank below alphanumeric ones.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < min(len(a), len(b)); i++ {
		if c := compareIdentifier(a[i], b[i]); c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}

func compareIdentifier(a, b string) int {
	na, errA := strconv.Atoi(a)
	nb, errB := strconv.Atoi(b)
	switch {
	case errA == nil && errB == nil:
		return na - nb
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}
