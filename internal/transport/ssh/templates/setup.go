package templates

import (
	"fmt"
	"regexp"
	"slices"
)

// Paths node.setup manages on a node (ADR-0009 d). Steps may touch only these:
// the setup templates validate every path against the sets below.
const (
	HomeDir            = "/var/lib/supermgmt"
	SSHDir             = HomeDir + "/.ssh"
	AuthorizedKeysPath = SSHDir + "/authorized_keys"
	SudoersPath        = "/etc/sudoers.d/supermgmt"
	TmpfilesPath       = "/etc/tmpfiles.d/supermgmt.conf"
	BrokerDir          = "/usr/local/libexec/supermgmt"
	BrokerConfigDir    = "/etc/supermgmt"
	BrokerUnitsPath    = BrokerConfigDir + "/allowed-units"
)

// StagingSuffix names the temporary file a setup file is written to before it
// is validated and moved over its destination. sudo and tmpfiles ignore names
// with a dot, so a staged file is inert.
const StagingSuffix = ".new"

// SudoVariantSuffix names the variant of a setup template that runs through
// `sudo -n` (admin_user is not root, ADR-0009 c).
const SudoVariantSuffix = ".sudo"

// rootPath is the PATH extension the root variants add: non-login ssh sessions
// often lack the sbin directories that useradd and visudo live in.
const rootPath = `PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin" `

var (
	setupDirectories = []string{HomeDir, HomeDir + "/markers", SSHDir, BrokerDir, BrokerConfigDir}
	setupFiles       = []string{AuthorizedKeysPath, SudoersPath, TmpfilesPath, BrokerPath, BrokerUnitsPath}
	setupGroups      = []string{"systemd-journal", "adm", "docker"}
	modeRE           = regexp.MustCompile(`^0[0-7]{3}$`)
)

// StagingPath returns the staging file of a managed destination.
func StagingPath(destination string) string { return destination + StagingSuffix }

func oneOf(what string, allowed []string) func(string) error {
	return func(s string) error {
		if !slices.Contains(allowed, s) {
			return fmt.Errorf("not a %s node.setup manages", what)
		}
		return nil
	}
}

func stagingPaths() []string {
	staged := make([]string, len(setupFiles))
	for i, f := range setupFiles {
		staged[i] = StagingPath(f)
	}
	return staged
}

var (
	paramUser      = Param{Name: "user", Validate: ValidateSystemUser}
	paramOwner     = Param{Name: "owner", Validate: ValidateSystemUser}
	paramOwnGroup  = Param{Name: "group", Validate: ValidateSystemUser}
	paramMode      = Param{Name: "mode", Validate: Matching(modeRE)}
	paramDir       = Param{Name: "path", Validate: oneOf("directory", setupDirectories)}
	paramStaged    = Param{Name: "path", Validate: oneOf("staging file", stagingPaths())}
	paramFrom      = Param{Name: "from", Validate: oneOf("staging file", stagingPaths())}
	paramTo        = Param{Name: "to", Validate: oneOf("destination", setupFiles)}
	paramPlatGroup = Param{Name: "group", Validate: oneOf("group", setupGroups)}
)

// privilegedStep is one node.setup command that needs root. It is registered
// twice: as is for admin_user = root, and as a `sudo -n` variant otherwise.
type privilegedStep struct {
	name   string
	body   string
	params []Param
}

var privilegedSteps = []privilegedStep{
	{
		"setup.user_add",
		"useradd --system --user-group --home-dir " + HomeDir + " --create-home --shell /bin/sh {{user}}",
		[]Param{paramUser},
	},
	{"setup.user_unlock", "usermod -p '*' {{user}}", []Param{paramUser}},
	{
		"setup.dir",
		"install -d -m {{mode}} -o {{owner}} -g {{group}} {{path}}",
		[]Param{paramMode, paramOwner, paramOwnGroup, paramDir},
	},
	{
		// The content arrives on stdin and is written to a staging path.
		"setup.file_stage",
		"install -m {{mode}} -o {{owner}} -g {{group}} /dev/stdin {{path}}",
		[]Param{paramMode, paramOwner, paramOwnGroup, paramStaged},
	},
	{"setup.file_commit", "mv -f {{from}} {{to}}", []Param{paramFrom, paramTo}},
	{"setup.file_discard", "rm -f {{path}}", []Param{paramStaged}},
	{"setup.sudoers_check", "visudo -cf {{path}}", []Param{paramStaged}},
	{"setup.group_add", "usermod -aG {{group}} {{user}}", []Param{paramPlatGroup, paramUser}},
	{"setup.group_remove", "gpasswd -d {{user}} {{group}}", []Param{paramUser, paramPlatGroup}},
	{"setup.tmpfiles_apply", "systemd-tmpfiles --create " + TmpfilesPath, nil},
}

// setupReads are the unprivileged reads node.setup decides on and verifies
// with. The verify_* templates run as the dedicated user (ADR-0009 f step 8).
var setupReads = []Template{
	{Name: "setup.user_entry", Params: []Param{paramUser}, Body: "getent passwd {{user}}", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.group_entry", Params: []Param{paramPlatGroup}, Body: "getent group {{group}}", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.user_groups", Params: []Param{paramUser}, Body: "id -nG {{user}}", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.systemctl_path", Body: "command -v systemctl", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.verify_id", Body: "id -un", MaxBytes: 1 << 10, MaxLines: 2},
	{
		Name: "setup.verify_markers", MaxBytes: 1 << 10, MaxLines: 2,
		Body: "[ -d " + MarkerDir + " ] && [ -w " + MarkerDir + " ] && echo writable",
	},
	{Name: "setup.verify_sudo", Body: "sudo -n -l", MaxBytes: 256 << 10, MaxLines: 5000},
}

var setupTemplates = buildSetupTemplates()

func buildSetupTemplates() []Template {
	all := slices.Clone(setupReads)
	for _, s := range privilegedSteps {
		all = append(all,
			Template{Name: s.name, Body: rootPath + s.body, Params: s.params, Setup: true, MaxBytes: 64 << 10, MaxLines: 500},
			Template{Name: s.name + SudoVariantSuffix, Body: "sudo -n " + s.body, Params: s.params, Setup: true, MaxBytes: 64 << 10, MaxLines: 500},
		)
	}
	return all
}
