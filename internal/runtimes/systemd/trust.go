package systemd

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/textsafe"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// maxTrustTargets bounds the files one trust check stats.
const maxTrustTargets = 64

var (
	execProperties = []string{"ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"}
	execEntry      = regexp.MustCompile(`\{ path=(.*?) ; argv\[\]=(.*?) ; ignore_errors=`)
	envFileEntry   = regexp.MustCompile(`(\S+) \(ignore_errors=(yes|no)\)`)
	interpreterRE  = regexp.MustCompile(`^(sh|bash|dash|python[0-9.]*|perl|ruby|node|php)$`)
	// safeOptions are the only options each interpreter family may be started
	// with. An option that is not listed is refused, never skipped: attached
	// values (-cCODE), assignments (--command=CODE) and combined flags (-lc)
	// all hide inline code from a denylist.
	safeOptions = map[string]*regexp.Regexp{
		"shell":  regexp.MustCompile(`^-[euxfv]+$`),
		"bash":   regexp.MustCompile(`^-[euxfv]+$|^--(norc|noprofile|posix)$`),
		"python": regexp.MustCompile(`^-[BsSuIOqRbE]+$`),
		"perl":   regexp.MustCompile(`^-[wWtTX]+$`),
		"ruby":   regexp.MustCompile(`^-w$|^-W[012]$`),
		"node":   regexp.MustCompile(`^--no-warnings$`),
		"php":    regexp.MustCompile(`^-[qn]+$`),
	}
)

// interpreterFamily maps an interpreter's file name to its safeOptions key.
func interpreterFamily(base string) string {
	switch {
	case base == "sh" || base == "dash":
		return "shell"
	case strings.HasPrefix(base, "python"):
		return "python"
	}
	return base
}

// CheckTrust applies the unit trust profile of spec §16: the unit file, every
// drop-in, every executable, every interpreter script, every EnvironmentFile
// and the WorkingDirectory must be root-owned and not group/other-writable, as
// must every parent directory up to /. Anything that cannot be resolved to a
// plain path makes the unit ineligible. It is a trust profile, not a proof.
func CheckTrust(ctx context.Context, ex transport.Executor, unit string) error {
	if err := templates.ValidateUnit(unit); err != nil {
		return notEligible(unit, "unit name", "", err.Error())
	}
	out, err := succeeded(ctx, ex, "systemd.trust_show", map[string]string{"unit": unit})
	if err != nil {
		return err
	}
	props := parseProps(out)
	if state := props.first("LoadState"); state != "loaded" {
		return notEligible(unit, "load state", "", "unit is not loaded")
	}
	targets, err := trustTargets(ctx, ex, unit, props)
	if err != nil {
		return err
	}
	if len(targets) > maxTrustTargets {
		return notEligible(unit, "files", "", "too many files to verify")
	}
	for _, t := range targets {
		if err := verifyChain(ctx, ex, unit, t); err != nil {
			return err
		}
	}
	return nil
}

// target is a file whose chain must be root-owned. When missingOK is set an
// absent file is acceptable (an ignored EnvironmentFile) and only its parent
// directories are checked.
type target struct {
	path      string
	missingOK bool
}

func trustTargets(ctx context.Context, ex transport.Executor, unit string, props properties) ([]target, error) {
	var targets []target
	add := func(p string, missingOK bool) {
		if !slices.Contains(targets, target{p, missingOK}) {
			targets = append(targets, target{p, missingOK})
		}
	}
	fragment := props.first("FragmentPath")
	if fragment == "" {
		return nil, notEligible(unit, "unit file", "", "unit has no unit file")
	}
	if err := plainPath(unit, "unit file", fragment); err != nil {
		return nil, err
	}
	add(fragment, false)
	for _, drop := range strings.Fields(props.first("DropInPaths")) {
		if err := plainPath(unit, "drop-in", drop); err != nil {
			return nil, err
		}
		add(drop, false)
	}
	if err := collectEnvironmentFiles(unit, props, add); err != nil {
		return nil, err
	}
	if dir := strings.TrimPrefix(props.first("WorkingDirectory"), "!"); dir != "" {
		if err := plainPath(unit, "working directory", dir); err != nil {
			return nil, err
		}
		add(dir, false)
	}
	for _, key := range execProperties {
		for _, value := range props.nonEmpty(key) {
			if err := collectExec(ctx, ex, unit, value, add); err != nil {
				return nil, err
			}
		}
	}
	return targets, nil
}

func collectEnvironmentFiles(unit string, props properties, add func(string, bool)) error {
	for _, value := range props.nonEmpty("EnvironmentFiles") {
		entries := envFileEntry.FindAllStringSubmatch(value, -1)
		if len(entries) == 0 {
			return notEligible(unit, "environment file", "", "cannot resolve EnvironmentFiles")
		}
		for _, e := range entries {
			if err := plainPath(unit, "environment file", e[1]); err != nil {
				return err
			}
			add(e[1], e[2] == "yes")
		}
	}
	return nil
}

// collectExec adds the program of one Exec* entry and, for interpreters and
// scripts, the script paths it runs.
func collectExec(ctx context.Context, ex transport.Executor, unit, value string, add func(string, bool)) error {
	entries := execEntry.FindAllStringSubmatch(value, -1)
	if len(entries) == 0 {
		return notEligible(unit, "command", "", "cannot parse an Exec line")
	}
	for _, e := range entries {
		program, argv := e[1], strings.Fields(e[2])
		if err := plainPath(unit, "executable", program); err != nil {
			return err
		}
		add(program, false)
		scripts, err := scriptPaths(ctx, ex, unit, program, argv)
		if err != nil {
			return err
		}
		for _, s := range scripts {
			add(s, false)
		}
	}
	return nil
}

// scriptPaths returns the files a program executes beyond itself. argv[0] is
// the program's own name and is skipped.
func scriptPaths(ctx context.Context, ex transport.Executor, unit, program string, argv []string) ([]string, error) {
	args := argv
	if len(args) > 0 {
		args = args[1:]
	}
	base := path.Base(program)
	if base == "env" {
		return nil, notEligible(unit, "executable", program, "env hides the program it runs")
	}
	if interpreterRE.MatchString(base) {
		return interpreterScripts(unit, program, args)
	}
	script, err := hasShebang(ctx, ex, unit, program)
	if err != nil || !script {
		return nil, err
	}
	return absoluteArguments(unit, args)
}

// interpreterScripts resolves `interpreter [options] script [args]`: inline
// code is refused and the script must be a plain absolute path.
func interpreterScripts(unit, program string, args []string) ([]string, error) {
	safe := safeOptions[interpreterFamily(path.Base(program))]
	script := -1
	for i, a := range args {
		if a == "--" {
			if i+1 < len(args) {
				script = i + 1
			}
			break
		}
		if !strings.HasPrefix(a, "-") {
			script = i
			break
		}
		if safe == nil || !safe.MatchString(a) {
			return nil, notEligible(unit, "executable", program, "interpreter option is not allowed (inline code, modules and unknown options are refused)")
		}
	}
	if script < 0 {
		return nil, notEligible(unit, "executable", program, "interpreter has no script path")
	}
	if err := plainPath(unit, "script", args[script]); err != nil {
		return nil, err
	}
	rest, err := absoluteArguments(unit, args[script+1:])
	return append([]string{args[script]}, rest...), err
}

// absoluteArguments returns the arguments that are paths; they are held to the
// same rule as the script itself.
func absoluteArguments(unit string, args []string) ([]string, error) {
	var paths []string
	for _, a := range args {
		if !strings.HasPrefix(a, "/") {
			continue
		}
		if err := plainPath(unit, "script argument", a); err != nil {
			return nil, err
		}
		paths = append(paths, a)
	}
	return paths, nil
}

func hasShebang(ctx context.Context, ex transport.Executor, unit, program string) (bool, error) {
	res, err := read(ctx, ex, "systemd.file_magic", map[string]string{"path": program})
	if err != nil {
		return false, err
	}
	if res.ExitStatus != 0 {
		return false, notEligible(unit, "executable", program, "cannot read the executable")
	}
	return string(res.Stdout) == "#!", nil
}

// verifyChain stats the path and every parent (and the resolved path's chain).
func verifyChain(ctx context.Context, ex transport.Executor, unit string, t target) error {
	bad, readable, err := chainFault(ctx, ex, t.path)
	if err != nil {
		return err
	}
	if !readable && t.missingOK {
		return verifyChain(ctx, ex, unit, target{path: path.Dir(t.path)})
	}
	if !readable {
		return notEligible(unit, "file", t.path, "cannot be inspected")
	}
	if bad != "" {
		return notEligible(unit, "file", bad, "must be root-owned and not group/other-writable")
	}
	return nil
}

// chainFault walks the path, every parent and the resolved path's chain. It
// returns the first entry that is not root-owned or is group/other-writable,
// or readable=false when the chain cannot be inspected.
func chainFault(ctx context.Context, ex transport.Executor, p string) (bad string, readable bool, err error) {
	res, err := read(ctx, ex, "systemd.path_chain", map[string]string{"path": p})
	if err != nil {
		return "", false, err
	}
	if res.ExitStatus != 0 || res.Truncated {
		return "", false, nil
	}
	for _, line := range splitLines(res.Stdout) {
		if bad := untrustedEntry(line); bad != "" {
			return bad, true, nil
		}
	}
	return "", true, nil
}

// CheckSystemctlTrust requires the systemctl binary sudoers will grant, its
// resolved path and every parent directory to be root-owned and not
// group/other-writable. The path comes from the administrator's session and
// is never taken on trust: a service-user-writable systemctl would be root
// code execution through the granted line.
func CheckSystemctlTrust(ctx context.Context, ex transport.Executor, systemctlPath string) error {
	if err := templates.ValidateSystemctlPath(systemctlPath); err != nil {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "systemctl path: "+err.Error())
	}
	bad, readable, err := chainFault(ctx, ex, systemctlPath)
	switch {
	case err != nil:
		return err
	case !readable:
		return smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("systemctl %q cannot be inspected", textsafe.Line(systemctlPath)))
	case bad != "":
		return smerr.New(smerr.CodeCapabilityUnavailable, "",
			fmt.Sprintf("systemctl is not trusted: %q must be root-owned and not group/other-writable", textsafe.Line(bad)))
	}
	return nil
}

// untrustedEntry parses one "<uid> <mode> <path>" line and returns its path
// when the entry is not root-owned or is group/other-writable.
func untrustedEntry(line string) string {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return line
	}
	mode, err := strconv.ParseUint(parts[1], 8, 32)
	if err != nil || parts[0] != "0" || mode&0o022 != 0 {
		return parts[2]
	}
	return ""
}

// plainPath requires an absolute path a shell and systemd would not reinterpret.
func plainPath(unit, what, p string) error {
	if err := templates.ValidateAbsolutePath(p); err != nil {
		return notEligible(unit, what, p, "cannot be resolved to a plain path")
	}
	return nil
}

func notEligible(unit, what, file, why string) error {
	msg := fmt.Sprintf("unit %s is not eligible: %s: %s", textsafe.Line(unit), what, why)
	if file != "" {
		msg += fmt.Sprintf(" (%q)", textsafe.Line(file))
	}
	return smerr.New(smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible, msg)
}
