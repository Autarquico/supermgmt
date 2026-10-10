package systemd

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The files node.setup installs (ADR-0009 d, spec §16). Every renderer is a
// pure function of validated parameters.

var (
	authorizedKeyRE = regexp.MustCompile(`^[a-z0-9@.-]+ [A-Za-z0-9+/]+={0,2}$`)
	instanceIDRE    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

func invalid(msg string) error { return smerr.New(smerr.CodeInvalidArgument, "", msg) }

// SudoersLine is the one sudoers line that grants verb on unit. The executed
// command is `sudo -n <systemctlPath> <verb> <unit>`: the same words, so the
// line and the argv cannot drift (ADR-0015). The grammars admit no sudoers
// metacharacter, so nothing here needs escaping.
func SudoersLine(user, systemctlPath string, verb domain.ServiceVerb, unit string) (string, error) {
	command, err := sudoCommand(systemctlPath, verb, unit)
	if err != nil {
		return "", err
	}
	if err := templates.ValidateSystemUser(user); err != nil {
		return "", invalid("user: " + err.Error())
	}
	return user + " ALL=(root) NOPASSWD: " + command, nil
}

func sudoCommand(systemctlPath string, verb domain.ServiceVerb, unit string) (string, error) {
	if err := templates.ValidateSystemctlPath(systemctlPath); err != nil {
		return "", invalid("systemctl path: " + err.Error())
	}
	if !verb.Valid() {
		return "", invalid("unknown service verb")
	}
	if err := templates.ValidateUnit(unit); err != nil {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible, "unit is not eligible: "+err.Error())
	}
	return systemctlPath + " " + string(verb) + " " + unit, nil
}

// SudoCommands lists, in file order, the commands the drop-in grants: one per
// unit and verb, then the broker in broker mode.
func SudoCommands(systemctlPath string, grants []runtimes.UnitGrant, mode runtimes.LogsMode) ([]string, error) {
	var commands []string
	for _, g := range canonicalGrants(grants) {
		for _, verb := range g.Verbs {
			c, err := sudoCommand(systemctlPath, verb, g.Unit)
			if err != nil {
				return nil, err
			}
			commands = append(commands, c)
		}
	}
	if mode == runtimes.LogsBroker {
		commands = append(commands, templates.BrokerPath)
	}
	return commands, nil
}

// canonicalGrants sorts units, merges repeats and orders verbs start, stop,
// restart, so equal grants always render equal files.
func canonicalGrants(grants []runtimes.UnitGrant) []runtimes.UnitGrant {
	verbs := map[string]map[domain.ServiceVerb]bool{}
	for _, g := range grants {
		if verbs[g.Unit] == nil {
			verbs[g.Unit] = map[domain.ServiceVerb]bool{}
		}
		for _, v := range g.Verbs {
			verbs[g.Unit][v] = true
		}
	}
	units := make([]string, 0, len(verbs))
	for u := range verbs {
		units = append(units, u)
	}
	slices.Sort(units)
	out := make([]runtimes.UnitGrant, 0, len(units))
	for _, u := range units {
		g := runtimes.UnitGrant{Unit: u}
		for _, v := range domain.AllServiceVerbs() {
			if verbs[u][v] {
				g.Verbs = append(g.Verbs, v)
			}
		}
		out = append(out, g)
	}
	return out
}

// Sudoers renders /etc/sudoers.d/supermgmt: exact lines, no wildcards.
func Sudoers(user, systemctlPath string, grants []runtimes.UnitGrant, mode runtimes.LogsMode) (string, error) {
	if err := templates.ValidateSystemUser(user); err != nil {
		return "", invalid("user: " + err.Error())
	}
	commands, err := SudoCommands(systemctlPath, grants, mode)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by SuperMgmt (node.setup). Changes are overwritten.\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "%s ALL=(root) NOPASSWD: %s\n", user, c)
	}
	return b.String(), nil
}

// AuthorizedKeys renders the fully managed authorized_keys: one restricted
// line (no pty, no forwarding, automated use only; ADR-0009 d).
func AuthorizedKeys(user, authorizedKey, instanceID string) (string, error) {
	key := strings.TrimSpace(authorizedKey)
	if !authorizedKeyRE.MatchString(key) {
		return "", invalid("authorized key is not a bare public key line")
	}
	if !instanceIDRE.MatchString(instanceID) {
		return "", invalid("instance id is not a plain identifier")
	}
	if err := templates.ValidateSystemUser(user); err != nil {
		return "", invalid("user: " + err.Error())
	}
	return fmt.Sprintf("restrict %s %s@%s\n", key, user, instanceID), nil
}

// Tmpfiles renders the tmpfiles.d entry for the node-side lock directory
// (spec §20.4 step 3).
func Tmpfiles(user string) (string, error) {
	if err := templates.ValidateSystemUser(user); err != nil {
		return "", invalid("user: " + err.Error())
	}
	return fmt.Sprintf("d /run/supermgmt/locks 0700 %[1]s %[1]s -\n", user), nil
}

// AllowedUnits renders /etc/supermgmt/allowed-units, one unit per line: the
// units the log broker may read.
func AllowedUnits(grants []runtimes.UnitGrant) (string, error) {
	var b strings.Builder
	for _, g := range canonicalGrants(grants) {
		if err := templates.ValidateUnit(g.Unit); err != nil {
			return "", smerr.New(smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible, "unit is not eligible: "+err.Error())
		}
		b.WriteString(g.Unit + "\n")
	}
	return b.String(), nil
}

// BrokerScript is the root-owned log broker (spec §16): it accepts exactly
// `<unit> <lines>`, checks the unit against the allow-list and the line count
// against 10000, and execs journalctl with a clean environment.
const BrokerScript = `#!/bin/sh
# Managed by SuperMgmt (node.setup). Changes are overwritten.
set -eu
[ "$#" -eq 2 ] || exit 64
unit=$1
lines=$2
case $lines in ''|*[!0-9]*) exit 64 ;; esac
[ "${#lines}" -le 5 ] && [ "$lines" -ge 1 ] && [ "$lines" -le 10000 ] || exit 64
grep -qxF -- "$unit" ` + templates.BrokerUnitsPath + ` || exit 65
exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin SYSTEMD_PAGER= PAGER=cat journalctl --no-pager --output=short-iso -u "$unit" -n "$lines"
`
