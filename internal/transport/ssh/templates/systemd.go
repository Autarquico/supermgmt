package templates

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ActionDeadline is the deadline of every service action (plan Q12).
const ActionDeadline = 2 * time.Minute

// BrokerPath is the root-owned log broker of `ssh.logs_mode: broker` (spec §16).
const BrokerPath = "/usr/local/libexec/supermgmt/unit-logs"

// MaxLogLines is the most lines one log read asks for (spec §16).
const MaxLogLines = 10000

var (
	unitRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]*\.service$`)
	systemUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	absPathRE    = regexp.MustCompile(`^(/[A-Za-z0-9._@+:=,~-]+)+$`)
	systemctlRE  = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*/systemctl$`)
)

// ValidateUnit is the unit-name allowlist of ADR-0015. It admits no ':' and no
// '\', so a unit that needs systemd escaping is refused rather than granted.
func ValidateUnit(s string) error {
	if !unitRE.MatchString(s) {
		return fmt.Errorf("not an eligible service unit name")
	}
	return nil
}

// ValidateSystemUser is the account-name allowlist of ADR-0015.
func ValidateSystemUser(s string) error {
	if !systemUserRE.MatchString(s) {
		return fmt.Errorf("not a valid account name")
	}
	return nil
}

// ValidateSystemctlPath accepts an absolute path to a binary named systemctl,
// without dot segments, so the sudoers line and the argv cannot diverge.
func ValidateSystemctlPath(s string) error {
	if !systemctlRE.MatchString(s) {
		return fmt.Errorf("not an absolute path to systemctl")
	}
	for _, segment := range strings.Split(s, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("contains a dot segment")
		}
	}
	return nil
}

// ValidateAbsolutePath accepts plain absolute paths: no spaces, quotes, '%' or
// '$', nothing a shell or a systemd specifier would reinterpret.
func ValidateAbsolutePath(s string) error {
	if !absPathRE.MatchString(s) {
		return fmt.Errorf("not a plain absolute path")
	}
	return nil
}

// ValidateLines accepts a log line count in 1..MaxLogLines.
func ValidateLines(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > MaxLogLines || strconv.Itoa(n) != s {
		return fmt.Errorf("not a line count in 1..%d", MaxLogLines)
	}
	return nil
}

const (
	pagerOff = "SYSTEMD_PAGER= PAGER=cat "
	// trustProperties are the properties the unit trust profile reads (spec §16).
	trustProperties = "LoadState,FragmentPath,DropInPaths,ExecStartPre,ExecStart,ExecStartPost,ExecReload,ExecStop,ExecStopPost,EnvironmentFiles,WorkingDirectory,User"
)

var (
	paramUnit      = Param{Name: "unit", Validate: ValidateUnit}
	paramSystemctl = Param{Name: "systemctl", Validate: ValidateSystemctlPath}
	paramPath      = Param{Name: "path", Validate: ValidateAbsolutePath}
	paramLines     = Param{Name: "lines", Validate: ValidateLines}
)

func sudoAction(verb string) Template {
	return Template{
		Name: "systemd." + verb, Body: "sudo -n {{systemctl}} " + verb + " {{unit}}",
		Params: []Param{paramSystemctl, paramUnit}, Mutating: true, Sudo: true,
		Deadline: ActionDeadline, MaxBytes: 64 << 10,
	}
}

// systemdTemplates holds the systemd discovery, logs, trust profile and unit
// actions (spec §16). Reads put `--` before the unit; the three actions are
// sudo templates and equal their sudoers lines byte for byte.
var systemdTemplates = []Template{
	{Name: "systemd.version", Body: "systemctl --version", MaxBytes: 4 << 10, MaxLines: 20},
	{
		Name: "systemd.list_units", MaxBytes: 4 << 20, MaxLines: 50000,
		Body: pagerOff + "systemctl list-units --type=service --all --plain --no-legend --no-pager --full",
	},
	{
		Name: "systemd.list_jobs", MaxBytes: 256 << 10, MaxLines: 5000,
		Body: pagerOff + "systemctl list-jobs --no-pager --no-legend --plain",
	},
	{
		Name: "systemd.show", Params: []Param{paramUnit}, MaxBytes: 16 << 10, MaxLines: 50,
		Body: pagerOff + "systemctl show --no-pager -p Id,LoadState,ActiveState,SubState,InvocationID -- {{unit}}",
	},
	{
		Name: "systemd.trust_show", Params: []Param{paramUnit}, MaxBytes: 256 << 10, MaxLines: 500,
		Body: pagerOff + "systemctl show --no-pager -p " + trustProperties + " -- {{unit}}",
	},
	{
		// Prints "<uid> <mode> <path>" for the path and every parent up to /,
		// then again for the resolved path, so a symlink cannot hide a writable
		// directory (spec §16 trust profile).
		Name: "systemd.path_chain", Params: []Param{paramPath}, MaxBytes: 64 << 10, MaxLines: 1024,
		Body: `p={{path}}; r=$(readlink -f -- "$p") || exit 1; ` +
			`for q in "$p" "$r"; do while :; do stat -L -c '%u %a %n' -- "$q" || exit 1; ` +
			`[ "$q" = / ] && break; q=$(dirname -- "$q"); done; done`,
	},
	{Name: "systemd.file_magic", Params: []Param{paramPath}, Body: "head -c 2 -- {{path}}", MaxBytes: 16, MaxLines: 1},
	{
		Name: "systemd.logs_group", Params: []Param{paramUnit, paramLines}, MaxBytes: 4 << 20, MaxLines: MaxLogLines + 10,
		Body: pagerOff + "journalctl --no-pager --output=short-iso -u {{unit}} -n {{lines}}",
	},
	{
		Name: "systemd.logs_broker", Params: []Param{paramUnit, paramLines}, MaxBytes: 4 << 20, MaxLines: MaxLogLines + 10,
		Body: "sudo -n " + BrokerPath + " {{unit}} {{lines}}",
	},
	sudoAction("start"),
	sudoAction("stop"),
	sudoAction("restart"),
}
