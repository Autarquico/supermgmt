package templates

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/autarquico/supermgmt/internal/pveid"
)

// RelayTemplate is the name of the Proxmox API relay.
const RelayTemplate = "proxmox.api.relay"

// relayPathPattern admits socat only in the system binary directories.
var relayPathPattern = regexp.MustCompile(`^/(usr/bin|bin|usr/local/bin)/socat$`)

// ValidateRelayPath accepts the absolute path of socat in /usr/bin, /bin or
// /usr/local/bin and nothing else.
func ValidateRelayPath(s string) error {
	if !relayPathPattern.MatchString(s) {
		return fmt.Errorf("not socat in /usr/bin, /bin or /usr/local/bin")
	}
	return nil
}

// proxmoxTemplates holds the relay to the local Proxmox API. The destination is
// part of the body: no caller can name another one, and the only parameter is
// where socat lives. The command streams until the session ends, so MaxBytes
// only satisfies the catalog's structural rule.
var proxmoxTemplates = []Template{
	{
		Name: RelayTemplate, MaxBytes: 1,
		Params: []Param{{Name: "socat", Validate: ValidateRelayPath}},
		Body:   "{{socat}} STDIO TCP:127.0.0.1:8006",
	},
}

// Relay is the one command the dedicated account runs to reach the Proxmox API
// on its own node: socat bridging the session's stdio to 127.0.0.1:8006.
type Relay struct {
	// SocatPath is the path setup recorded for socat on the node.
	SocatPath string
}

// Command renders the relay command line.
func (r Relay) Command() (Command, error) {
	return Render(RelayTemplate, map[string]string{"socat": r.SocatPath})
}

// Proxmox tools run by absolute path in an empty environment plus these two
// variables, so neither PATH nor the caller's locale can reshape them (ADR-0026).
const (
	pveVersionTool = "/usr/bin/pveversion"
	pveumTool      = "/usr/sbin/pveum"

	// PVERootCAPath is the cluster CA the API certificate chains to.
	PVERootCAPath = "/etc/pve/pve-root-ca.pem"

	pveEnv = "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "
)

// Setup templates the Proxmox step runs (node.setup --proxmox). They are
// privileged steps like the others: a root and a `sudo -n` variant each.
const (
	PVEVersionStep      = "setup.pve_version"
	PVEUserListStep     = "setup.pve_user_list"
	PVEUserAddStep      = "setup.pve_user_add"
	PVERoleListStep     = "setup.pve_role_list"
	PVERoleAddStep      = "setup.pve_role_add"
	PVEACLAddUserStep   = "setup.pve_acl_add_user"
	PVEACLAddTokenStep  = "setup.pve_acl_add_token"
	PVETokenListStep    = "setup.pve_token_list"
	PVETokenAddStep     = "setup.pve_token_add"
	PVETokenRemoveStep  = "setup.pve_token_remove"
	PVERootCAStep       = "setup.pve_root_ca"
	AptInstallSocatStep = "setup.apt_install_socat"

	// HostnameRead and SocatPathRead are unprivileged reads.
	HostnameRead  = "setup.hostname"
	SocatPathRead = "setup.socat_path"
)

// secretOutputSteps are the setup steps whose stdout is a secret.
var secretOutputSteps = map[string]bool{PVETokenAddStep: true}

const maxPrivileges = 32

// validPrivilegeList accepts a comma-separated list of Proxmox privileges.
func validPrivilegeList(s string) error {
	list := strings.Split(s, ",")
	if len(list) > maxPrivileges {
		return fmt.Errorf("more than %d privileges", maxPrivileges)
	}
	return pveid.ValidPrivileges(list)
}

var (
	paramPVEUser    = Param{Name: "user", Validate: pveid.ValidUserID}
	paramPVERole    = Param{Name: "role", Validate: func(s string) error { return pveid.ValidName("role", s) }}
	paramPVEPrivs   = Param{Name: "privs", Validate: validPrivilegeList}
	paramPVEComment = Param{Name: "comment", Validate: func(s string) error { return pveid.ValidText("comment", s) }}
	paramPVEPath    = Param{Name: "path", Validate: pveid.ValidACLPath}
	paramPVEToken   = Param{Name: "token", Validate: pveid.ValidTokenName}
	paramPVETokenID = Param{Name: "id", Validate: func(s string) error { return pveid.ValidName("token id", s) }}
)

func pveum(args string) string { return "@ROOT@" + pveEnv + pveumTool + " " + args }

// proxmoxSteps are the pveversion and pveum commands the identity is created
// through, one fixed shape each (the installer's argument vectors, ADR-0026).
var proxmoxSteps = []privilegedStep{
	{PVEVersionStep, "@ROOT@" + pveEnv + pveVersionTool, nil},
	{PVEUserListStep, pveum("user list --output-format json"), nil},
	{PVEUserAddStep, pveum("user add {{user}} --comment {{comment}}"), []Param{paramPVEUser, paramPVEComment}},
	{PVERoleListStep, pveum("role list --output-format json"), nil},
	{PVERoleAddStep, pveum("role add {{role}} --privs {{privs}}"), []Param{paramPVERole, paramPVEPrivs}},
	{PVEACLAddUserStep, pveum("acl modify {{path}} --roles {{role}} --users {{user}}"), []Param{paramPVEPath, paramPVERole, paramPVEUser}},
	{PVEACLAddTokenStep, pveum("acl modify {{path}} --roles {{role}} --tokens {{token}}"), []Param{paramPVEPath, paramPVERole, paramPVEToken}},
	{PVETokenListStep, pveum("user token list {{user}} --output-format json"), []Param{paramPVEUser}},
	{
		// The answer carries the token secret: see secretOutputSteps.
		PVETokenAddStep,
		pveum("user token add {{user}} {{id}} --privsep 1 --comment {{comment}} --output-format json"),
		[]Param{paramPVEUser, paramPVETokenID, paramPVEComment},
	},
	{PVETokenRemoveStep, pveum("user token remove {{user}} {{id}}"), []Param{paramPVEUser, paramPVETokenID}},
	{PVERootCAStep, "@ROOT@cat " + PVERootCAPath, nil},
	{AptInstallSocatStep, "@ROOT@" + aptEnv + "apt-get install -y --no-install-recommends" + aptLockWait + " socat", nil},
}

// proxmoxSetupReads are the unprivileged reads of the Proxmox step.
var proxmoxSetupReads = []Template{
	{Name: HostnameRead, Body: "hostname -s", MaxBytes: 1 << 10, MaxLines: 2},
	{
		// The first socat in the system binary directories, as ValidateRelayPath
		// accepts it; exit 1 when there is none.
		Name: SocatPathRead, MaxBytes: 1 << 10, MaxLines: 2,
		Body: `for d in /usr/bin /bin /usr/local/bin; do [ -x "$d/socat" ] && { echo "$d/socat"; exit 0; }; done; exit 1`,
	},
}
