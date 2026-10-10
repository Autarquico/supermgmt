package systemd

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// SetupParams is everything node.setup needs to provision a node (ADR-0009).
type SetupParams struct {
	User          string // the dedicated account, normally "supermgmt"
	InstanceID    string // names the authorized key comment
	AuthorizedKey string // public half of secret://ssh/default
	SystemctlPath string // resolved on the node when empty
	Grants        []runtimes.UnitGrant
	LogsMode      runtimes.LogsMode
	DockerAccess  bool // explicit: the docker group is root-equivalent (spec §17)
	AdminIsRoot   bool // false: every privileged step runs as `sudo -n <argv>` (ADR-0009 c)
}

// Validate checks every parameter before anything touches the node.
func (p SetupParams) Validate() error {
	if err := templates.ValidateSystemUser(p.User); err != nil {
		return invalid("user: " + err.Error())
	}
	if _, err := AuthorizedKeys(p.User, p.AuthorizedKey, p.InstanceID); err != nil {
		return err
	}
	if p.LogsMode != runtimes.LogsJournalGroup && p.LogsMode != runtimes.LogsBroker {
		return invalid("logs mode must be journal-group or broker")
	}
	if p.SystemctlPath != "" {
		if err := templates.ValidateSystemctlPath(p.SystemctlPath); err != nil {
			return invalid("systemctl path: " + err.Error())
		}
	}
	_, err := SudoCommands("/usr/bin/systemctl", p.Grants, p.LogsMode)
	return err
}

// SetupOutcome is what the job records in the node.setup capability metadata.
type SetupOutcome struct{ SystemctlPath string }

// Setup runs the ensure steps of ADR-0009 (f) 1-7 through ex, which runs as
// admin_user. Every step is idempotent and files are installed through a
// staging name, so an interrupted run leaves the old or the new file. Verify
// (step 8) is separate: it needs a session as the dedicated user.
func Setup(ctx context.Context, ex transport.Executor, p SetupParams) (SetupOutcome, error) {
	if err := p.Validate(); err != nil {
		return SetupOutcome{}, err
	}
	s := stepper{ex: ex, sudo: !p.AdminIsRoot}
	systemctl, err := s.systemctlPath(ctx, p)
	if err != nil {
		return SetupOutcome{}, err
	}
	for _, g := range p.Grants {
		if err := CheckTrust(ctx, ex, g.Unit); err != nil {
			return SetupOutcome{}, err
		}
	}
	files, err := renderFiles(p, systemctl)
	if err != nil {
		return SetupOutcome{}, err
	}
	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"user", func(ctx context.Context) error { return s.ensureUser(ctx, p.User) }},
		{"directories", func(ctx context.Context) error { return s.ensureDirectories(ctx, p.User) }},
		{"authorized_keys", func(ctx context.Context) error {
			return s.installFile(ctx, templates.AuthorizedKeysPath, "0600", p.User, p.User, files.authorizedKeys, nil)
		}},
		{"groups", func(ctx context.Context) error { return s.ensureGroups(ctx, p) }},
		{"tmpfiles", func(ctx context.Context) error { return s.ensureTmpfiles(ctx, files.tmpfiles) }},
		{"broker", func(ctx context.Context) error { return s.ensureBroker(ctx, p, files) }},
		{"sudoers", func(ctx context.Context) error {
			return s.installFile(ctx, templates.SudoersPath, "0440", "root", "root", files.sudoers, s.checkSudoers)
		}},
	}
	for _, step := range steps {
		if err := step.run(ctx); err != nil {
			return SetupOutcome{}, fmt.Errorf("node.setup step %s: %w", step.name, err)
		}
	}
	return SetupOutcome{SystemctlPath: systemctl}, nil
}

type renderedFiles struct{ authorizedKeys, sudoers, tmpfiles, allowedUnits string }

func renderFiles(p SetupParams, systemctl string) (renderedFiles, error) {
	var (
		f   renderedFiles
		err error
	)
	if f.authorizedKeys, err = AuthorizedKeys(p.User, p.AuthorizedKey, p.InstanceID); err != nil {
		return f, err
	}
	if f.sudoers, err = Sudoers(p.User, systemctl, p.Grants, p.LogsMode); err != nil {
		return f, err
	}
	if f.tmpfiles, err = Tmpfiles(p.User); err != nil {
		return f, err
	}
	f.allowedUnits, err = AllowedUnits(p.Grants)
	return f, err
}

// stepper runs setup templates, as is or through sudo.
type stepper struct {
	ex   transport.Executor
	sudo bool
}

func (s stepper) name(base string) string {
	if s.sudo {
		return base + templates.SudoVariantSuffix
	}
	return base
}

// do runs a privileged setup step and requires exit status 0.
func (s stepper) do(ctx context.Context, base string, args map[string]string, stdin []byte) error {
	c, err := templates.RenderSetup(s.name(base), args, stdin)
	if err != nil {
		return err
	}
	res, err := s.ex.Run(ctx, c)
	if err != nil {
		return fmt.Errorf("%s: %w", base, err)
	}
	if res.ExitStatus != 0 {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("%s failed (exit %d): %s", base, res.ExitStatus, firstLine(res.Stderr)))
	}
	return nil
}

func firstLine(b []byte) string {
	lines := splitLines(b)
	if len(lines) == 0 {
		return "no output"
	}
	return truncate(lines[0], 200)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

func (s stepper) systemctlPath(ctx context.Context, p SetupParams) (string, error) {
	if p.SystemctlPath != "" {
		return p.SystemctlPath, nil
	}
	out, err := succeeded(ctx, s.ex, "setup.systemctl_path", nil)
	if err != nil {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "systemctl was not found on the node")
	}
	path := strings.TrimSpace(out)
	if err := templates.ValidateSystemctlPath(path); err != nil {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "systemctl path is not usable in sudoers: "+err.Error())
	}
	return path, nil
}

// maxSystemUID separates system from login accounts (login.defs UID_MIN).
const maxSystemUID = 999

// ensureUser creates the dedicated account, keeps one that is exactly ours and
// refuses any other (CONFLICT): an existing account is never hijacked.
func (s stepper) ensureUser(ctx context.Context, user string) error {
	res, err := read(ctx, s.ex, "setup.user_entry", map[string]string{"user": user})
	if err != nil {
		return err
	}
	switch res.ExitStatus {
	case 0:
		return checkOwnAccount(user, string(res.Stdout))
	case 2:
		if err := s.do(ctx, "setup.user_add", map[string]string{"user": user}, nil); err != nil {
			return err
		}
		return s.do(ctx, "setup.user_unlock", map[string]string{"user": user}, nil)
	}
	return smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("looking up %s failed (exit %d)", user, res.ExitStatus))
}

// checkOwnAccount accepts a passwd entry with our home, shell and a system UID.
func checkOwnAccount(user, entry string) error {
	fields := strings.Split(strings.TrimSpace(entry), ":")
	uid, err := strconv.Atoi(fieldAt(fields, 2))
	ours := len(fields) == 7 && fields[0] == user && err == nil && uid >= 0 && uid <= maxSystemUID &&
		fields[5] == templates.HomeDir && fields[6] == "/bin/sh"
	if !ours {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("account %s already exists and is not the SuperMgmt service account", user))
	}
	return nil
}

func fieldAt(fields []string, i int) string {
	if i < len(fields) {
		return fields[i]
	}
	return ""
}

func (s stepper) ensureDirectories(ctx context.Context, user string) error {
	for _, d := range []struct{ mode, path string }{
		{"0750", templates.HomeDir}, {"0700", templates.MarkerDir}, {"0700", templates.SSHDir},
	} {
		if err := s.ensureDir(ctx, d.mode, user, user, d.path); err != nil {
			return err
		}
	}
	return nil
}

func (s stepper) ensureDir(ctx context.Context, mode, owner, group, path string) error {
	return s.do(ctx, "setup.dir", map[string]string{"mode": mode, "owner": owner, "group": group, "path": path}, nil)
}

// installFile writes content to a staging name, validates it, and moves it
// over destination: the node holds the old file or the new one, never a part.
func (s stepper) installFile(ctx context.Context, destination, mode, owner, group, content string, validate func(context.Context, string) error) error {
	staged := templates.StagingPath(destination)
	err := s.do(ctx, "setup.file_stage", map[string]string{"mode": mode, "owner": owner, "group": group, "path": staged}, []byte(content))
	if err == nil && validate != nil {
		err = validate(ctx, staged)
	}
	if err != nil {
		_ = s.do(context.WithoutCancel(ctx), "setup.file_discard", map[string]string{"path": staged}, nil)
		return err
	}
	return s.do(ctx, "setup.file_commit", map[string]string{"from": staged, "to": destination}, nil)
}

func (s stepper) checkSudoers(ctx context.Context, staged string) error {
	return s.do(ctx, "setup.sudoers_check", map[string]string{"path": staged}, nil)
}

// managedGroups are the groups whose membership node.setup decides.
var managedGroups = []string{"systemd-journal", "adm", "docker"}

// ensureGroups makes the account's membership of managedGroups equal to what
// the parameters ask for: the journal group in journal-group mode (systemd-
// journal, else adm), docker only with docker_access.
func (s stepper) ensureGroups(ctx context.Context, p SetupParams) error {
	wanted, err := s.wantedGroups(ctx, p)
	if err != nil {
		return err
	}
	out, err := succeeded(ctx, s.ex, "setup.user_groups", map[string]string{"user": p.User})
	if err != nil {
		return err
	}
	member := strings.Fields(out)
	for _, group := range managedGroups {
		args := map[string]string{"user": p.User, "group": group}
		switch isMember, want := slices.Contains(member, group), slices.Contains(wanted, group); {
		case want && !isMember:
			err = s.do(ctx, "setup.group_add", args, nil)
		case !want && isMember:
			err = s.do(ctx, "setup.group_remove", args, nil)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s stepper) wantedGroups(ctx context.Context, p SetupParams) ([]string, error) {
	var wanted []string
	if p.LogsMode == runtimes.LogsJournalGroup {
		group, err := s.journalGroup(ctx)
		if err != nil {
			return nil, err
		}
		wanted = append(wanted, group)
	}
	if p.DockerAccess {
		if !s.groupExists(ctx, "docker") {
			return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "docker_access was requested but the node has no docker group")
		}
		wanted = append(wanted, "docker")
	}
	return wanted, nil
}

func (s stepper) journalGroup(ctx context.Context) (string, error) {
	for _, group := range []string{"systemd-journal", "adm"} {
		if s.groupExists(ctx, group) {
			return group, nil
		}
	}
	return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "the node has neither a systemd-journal nor an adm group")
}

func (s stepper) groupExists(ctx context.Context, group string) bool {
	res, err := read(ctx, s.ex, "setup.group_entry", map[string]string{"group": group})
	return err == nil && res.ExitStatus == 0
}

func (s stepper) ensureTmpfiles(ctx context.Context, content string) error {
	if err := s.installFile(ctx, templates.TmpfilesPath, "0644", "root", "root", content, nil); err != nil {
		return err
	}
	return s.do(ctx, "setup.tmpfiles_apply", nil, nil)
}

func (s stepper) ensureBroker(ctx context.Context, p SetupParams, f renderedFiles) error {
	if p.LogsMode != runtimes.LogsBroker {
		return nil
	}
	for _, dir := range []string{templates.BrokerDir, templates.BrokerConfigDir} {
		if err := s.ensureDir(ctx, "0755", "root", "root", dir); err != nil {
			return err
		}
	}
	if err := s.installFile(ctx, templates.BrokerUnitsPath, "0644", "root", "root", f.allowedUnits, nil); err != nil {
		return err
	}
	return s.installFile(ctx, templates.BrokerPath, "0755", "root", "root", BrokerScript, nil)
}
