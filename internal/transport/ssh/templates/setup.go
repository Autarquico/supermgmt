package templates

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
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

// DefaultDeployRoot is where deployments live unless the plan says otherwise
// (ADR-0030).
const DefaultDeployRoot = "/srv/supermgmt"

const maxDeployRootLength = 200

var deployRootRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// ValidateDeployRoot accepts an absolute, clean path outside the dedicated
// user's home, below which root never acts (ADR-0009 d), and not the
// filesystem root.
func ValidateDeployRoot(p string) error {
	switch {
	case p == "" || len(p) > maxDeployRootLength:
		return fmt.Errorf("deploy_root must be 1 to %d characters", maxDeployRootLength)
	case !deployRootRE.MatchString(p):
		return errors.New("deploy_root may contain only letters, digits and . _ / -")
	case !path.IsAbs(p) || path.Clean(p) != p:
		return errors.New("deploy_root must be an absolute, clean path")
	case p == "/":
		return errors.New("deploy_root must not be the filesystem root")
	case p == HomeDir || strings.HasPrefix(p, HomeDir+"/"):
		return fmt.Errorf("deploy_root must be outside %s", HomeDir)
	}
	return nil
}

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

// Everything below the home directory is controlled by the dedicated user and
// may be replaced by a symlink at any time. Root therefore never touches it:
// ownDirectories and ownFiles are written as the dedicated user itself, so a
// planted symlink can only redirect that user's own privileges.
var (
	rootDirectories = []string{HomeDir, BrokerDir, BrokerConfigDir}
	rootFiles       = []string{SudoersPath, TmpfilesPath, BrokerPath, BrokerUnitsPath}
	ownDirectories  = []string{MarkerDir, SSHDir, BackupDir}
	ownFiles        = []string{AuthorizedKeysPath}
	setupGroups     = []string{"systemd-journal", "adm", "docker"}
	modeRE          = regexp.MustCompile(`^0[0-7]{3}$`)
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

func staged(files []string) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = StagingPath(f)
	}
	return out
}

var (
	paramUser      = Param{Name: "user", Validate: ValidateSystemUser}
	paramOwner     = Param{Name: "owner", Validate: ValidateSystemUser}
	paramOwnGroup  = Param{Name: "group", Validate: ValidateSystemUser}
	paramMode      = Param{Name: "mode", Validate: Matching(modeRE)}
	paramDir       = Param{Name: "path", Validate: oneOf("directory", rootDirectories)}
	paramOwnDir    = Param{Name: "path", Validate: oneOf("directory", ownDirectories)}
	paramStaged    = Param{Name: "path", Validate: oneOf("staging file", staged(rootFiles))}
	paramFrom      = Param{Name: "from", Validate: oneOf("staging file", staged(rootFiles))}
	paramTo        = Param{Name: "to", Validate: oneOf("destination", rootFiles)}
	paramOwnStaged = Param{Name: "path", Validate: oneOf("staging file", staged(ownFiles))}
	paramOwnFrom   = Param{Name: "from", Validate: oneOf("staging file", staged(ownFiles))}
	paramOwnTo     = Param{Name: "to", Validate: oneOf("destination", ownFiles)}
	paramDeployDir = Param{Name: "path", Validate: ValidateDeployRoot}
	paramPlatGroup = Param{Name: "group", Validate: oneOf("group", setupGroups)}
)

// privilegedStep is one node.setup command. It is registered twice: as is for
// admin_user = root, and as a `sudo -n` variant otherwise. In a body, @ROOT@
// runs the following command as root and @AS@ as the dedicated user.
type privilegedStep struct {
	name   string
	body   string
	params []Param
}

var privilegedSteps = []privilegedStep{
	{
		"setup.user_add",
		"@ROOT@useradd --system --user-group --home-dir " + HomeDir + " --create-home --shell /bin/sh {{user}}",
		[]Param{paramUser},
	},
	{"setup.user_unlock", "@ROOT@usermod -p '*' {{user}}", []Param{paramUser}},
	{
		// Root-controlled paths only (their parent is root-owned); a symlink is refused.
		"setup.dir",
		"@ROOT@test ! -L {{path}} && @ROOT@install -d -m {{mode}} -o {{owner}} -g {{group}} {{path}}",
		[]Param{paramMode, paramOwner, paramOwnGroup, paramDir},
	},
	{
		// deploy_root (ADR-0030): root-owned, 0755, never through a symlink.
		"setup.deploy_root",
		"@ROOT@test ! -L {{path}} && @ROOT@install -d -m 0755 -o root -g root {{path}}",
		[]Param{paramDeployDir},
	},
	{
		"setup.own_dir",
		`@AS@sh -c 'test ! -L "$1" && install -d -m "$2" -- "$1"' sh {{path}} {{mode}}`,
		[]Param{paramUser, paramOwnDir, paramMode},
	},
	{
		// cat first: the pipe is the dedicated user's own, so /dev/stdin can be reopened.
		"setup.own_file_stage",
		`@AS@sh -c 'cat | install -m "$2" /dev/stdin "$1"' sh {{path}} {{mode}}`,
		[]Param{paramUser, paramMode, paramOwnStaged},
	},
	{"setup.own_file_commit", "@AS@mv -f {{from}} {{to}}", []Param{paramUser, paramOwnFrom, paramOwnTo}},
	{"setup.own_file_discard", "@AS@rm -f {{path}}", []Param{paramUser, paramOwnStaged}},
	{
		// The content arrives on stdin and is written to a staging path.
		"setup.file_stage",
		"@ROOT@install -m {{mode}} -o {{owner}} -g {{group}} /dev/stdin {{path}}",
		[]Param{paramMode, paramOwner, paramOwnGroup, paramStaged},
	},
	{"setup.file_commit", "@ROOT@mv -f {{from}} {{to}}", []Param{paramFrom, paramTo}},
	{"setup.file_discard", "@ROOT@rm -f {{path}}", []Param{paramStaged}},
	{"setup.sudoers_check", "@ROOT@visudo -cf {{path}}", []Param{paramStaged}},
	{"setup.group_add", "@ROOT@usermod -aG {{group}} {{user}}", []Param{paramPlatGroup, paramUser}},
	{"setup.group_remove", "@ROOT@gpasswd -d {{user}} {{group}}", []Param{paramUser, paramPlatGroup}},
	{"setup.tmpfiles_apply", "@ROOT@systemd-tmpfiles --create " + TmpfilesPath, nil},
}

// setupReads are the unprivileged reads node.setup decides on and verifies
// with. The verify_* templates run as the dedicated user (ADR-0009 f step 8).
var setupReads = []Template{
	{Name: "setup.user_entry", Params: []Param{paramUser}, Body: "getent passwd {{user}}", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.group_entry", Params: []Param{paramPlatGroup}, Body: "getent group {{group}}", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.user_groups", Params: []Param{paramUser}, Body: "id -nG {{user}}", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.user_primary_group", Params: []Param{paramUser}, Body: "id -gn {{user}}", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.jq_path", Body: "command -v jq", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.systemctl_path", Body: "command -v systemctl", MaxBytes: 4 << 10, MaxLines: 5},
	{Name: "setup.verify_groups", Body: "id -nG", MaxBytes: 4 << 10, MaxLines: 5},
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
			setupTemplate(s.name, s, rootPath, rootPath+"runuser -u {{user}} -- "),
			setupTemplate(s.name+SudoVariantSuffix, s, "sudo -n ", "sudo -n runuser -u {{user}} -- "),
		)
	}
	return all
}

func setupTemplate(name string, s privilegedStep, root, as string) Template {
	body := strings.ReplaceAll(strings.ReplaceAll(s.body, "@ROOT@", root), "@AS@", as)
	return Template{Name: name, Body: body, Params: s.params, Setup: true, MaxBytes: 64 << 10, MaxLines: 500}
}
