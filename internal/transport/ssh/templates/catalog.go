// Package templates is the closed catalog of remote commands (spec §12,
// ADR-0015). A remote command line exists only as a rendered Template: every
// argument passes its parameter's allowlist validator and is then POSIX
// single-quoted, so no caller ever concatenates a command.
//
// The catalog is assembled from one slice per file: probe.go and marker.go
// (reads), systemd.go and docker.go (runtime actions), setup.go (node.setup
// steps, ADR-0009 f), and the deployment groups of M4 (ADR-0029):
// compose_stage.go, compose_run.go and health.go.
package templates

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// MarkerDir is the node-side directory of intent markers (spec §20.4). It is
// created by node.setup, never by a template.
const MarkerDir = "/var/lib/supermgmt/markers"

// KillAfter is the grace `timeout` gives a mutating command after its
// deadline before SIGKILL (spec §20.4 "timeout --kill-after=10s").
const KillAfter = 10 * time.Second

// Param is one named argument of a template. Validate is an allowlist check;
// it runs before quoting and must reject anything it does not positively know.
type Param struct {
	Name     string
	Validate func(string) error
}

// Template is one catalog entry. Body is a POSIX shell command line whose
// arguments appear as {{name}} placeholders, each bound to a Param.
//
//   - Mutating templates change node state; they render only through
//     RenderMutating, which adds the marker wrapper, and need a Deadline.
//   - Sudo templates start with "sudo -n " and must render to exactly the
//     sudoers line they are granted by, so they never contain " -- ".
//   - Setup templates are the node.setup steps; they render only through
//     RenderSetup and are the only mutating commands without a marker.
//   - Sensitive templates (mutating) read secret content from stdin; they
//     render only through RenderMutatingInput with non-empty stdin.
//   - Locked templates (mutating) run under the node-side project flock; they
//     render only through RenderMutatingInput with the project name.
//
// MaxBytes (required) and MaxLines (0 = unlimited) bound what is read back.
type Template struct {
	Name     string
	Body     string
	Params   []Param
	Mutating bool
	Sudo     bool
	Setup    bool
	// Sensitive and Locked are described above.
	Sensitive bool
	Locked    bool
	Deadline  time.Duration
	MaxBytes  int
	MaxLines  int
}

// Command is a rendered, ready-to-run command. Line goes to the remote login
// shell as is; Stdin carries content (setup files, secrets) that must never
// appear on the command line. Sensitive marks a command whose stdin and
// stdout must never be logged or persisted. A zero Deadline means the
// transport's command timeout.
type Command struct {
	Template  string
	Line      string
	Stdin     []byte
	Sensitive bool
	Mutating  bool
	Deadline  time.Duration
	MaxBytes  int
	MaxLines  int
}

// Matching returns a validator that accepts exactly the strings re matches.
// Anchor re (^…$): the validator does not add anchors.
func Matching(re *regexp.Regexp) func(string) error {
	return func(s string) error {
		if !re.MatchString(s) {
			return fmt.Errorf("does not match %s", re)
		}
		return nil
	}
}

// Render renders a read-only template.
func Render(name string, args map[string]string) (Command, error) {
	r, err := catalog()
	if err != nil {
		return Command{}, err
	}
	return r.render(name, args)
}

// RenderMutating renders a mutating template inside the marker wrapper
// (ADR-0015): the marker file is created first, the command runs under
// `timeout`, and its exit status is written atomically to <marker>.done.
func RenderMutating(name, marker string, args map[string]string) (Command, error) {
	r, err := catalog()
	if err != nil {
		return Command{}, err
	}
	return r.renderMutating(name, marker, args)
}

// RenderMutatingInput renders a mutating template that takes stdin (Sensitive
// templates: stdin required) and/or runs under the node-side project flock
// (Locked templates: flockProject required). The flock wraps the whole marker
// command, so the lock is held from the marker's creation to its .done.
func RenderMutatingInput(name, marker string, args map[string]string, stdin []byte, flockProject string) (Command, error) {
	r, err := catalog()
	if err != nil {
		return Command{}, err
	}
	return r.renderMutatingInput(name, marker, args, stdin, flockProject)
}

// RenderSetup renders a node.setup step. stdin is passed through untouched.
func RenderSetup(name string, args map[string]string, stdin []byte) (Command, error) {
	r, err := catalog()
	if err != nil {
		return Command{}, err
	}
	return r.renderSetup(name, args, stdin)
}

// Templates returns the whole catalog sorted by name, for tests that must hold
// for every template (fuzzing, sudoers grammar).
func Templates() ([]Template, error) {
	r, err := catalog()
	if err != nil {
		return nil, err
	}
	all := make([]Template, 0, len(r))
	for _, t := range r {
		all = append(all, t)
	}
	slices.SortFunc(all, func(a, b Template) int { return strings.Compare(a.Name, b.Name) })
	return all, nil
}

var catalog = sync.OnceValues(func() (registry, error) {
	return newRegistry(
		probeTemplates, markerTemplates, systemdTemplates, dockerTemplates, setupTemplates,
		composeStageTemplates, composeRunTemplates, healthTemplates,
	)
})

type registry map[string]Template

var (
	placeholderPattern = regexp.MustCompile(`\{\{([a-z_][a-z0-9_]*)\}\}`)
	markerPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

func newRegistry(groups ...[]Template) (registry, error) {
	r := registry{}
	for _, group := range groups {
		for _, t := range group {
			if _, dup := r[t.Name]; dup {
				return nil, catalogError(t.Name, "duplicate template")
			}
			if err := t.check(); err != nil {
				return nil, err
			}
			r[t.Name] = t
		}
	}
	return r, nil
}

// check enforces the structural rules every template must satisfy.
func (t Template) check() error {
	problem := ""
	switch {
	case t.Name == "":
		problem = "empty name"
	case t.Mutating && t.Setup:
		problem = "a template is either mutating or setup"
	case (t.Sensitive || t.Locked) && !t.Mutating:
		problem = "only a mutating template can be sensitive or locked"
	case t.Mutating && t.Deadline <= 0:
		problem = "mutating template needs a deadline"
	case t.Sudo && (!strings.HasPrefix(t.Body, "sudo -n ") || strings.Contains(t.Body, " -- ")):
		problem = `sudo template must start with "sudo -n " and contain no " -- "`
	case t.MaxBytes <= 0:
		problem = "MaxBytes must be positive"
	case t.MaxLines < 0:
		problem = "MaxLines must not be negative"
	}
	if problem != "" {
		return catalogError(t.Name, problem)
	}
	return t.checkParams()
}

// checkParams requires the placeholders in Body and the declared Params to be
// the same set, each Param with a validator.
func (t Template) checkParams() error {
	declared := map[string]bool{}
	for _, p := range t.Params {
		if declared[p.Name] || p.Validate == nil {
			return catalogError(t.Name, fmt.Sprintf("parameter %q is duplicated or has no validator", p.Name))
		}
		declared[p.Name] = true
	}
	used := map[string]bool{}
	for _, m := range placeholderPattern.FindAllStringSubmatch(t.Body, -1) {
		if !declared[m[1]] {
			return catalogError(t.Name, fmt.Sprintf("placeholder {{%s}} has no parameter", m[1]))
		}
		used[m[1]] = true
	}
	if len(used) != len(declared) {
		return catalogError(t.Name, "a declared parameter is not used in the body")
	}
	if rest := placeholderPattern.ReplaceAllString(t.Body, ""); strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
		return catalogError(t.Name, "malformed placeholder")
	}
	return nil
}

func (r registry) render(name string, args map[string]string) (Command, error) {
	t, err := r.lookup(name)
	if err != nil {
		return Command{}, err
	}
	if t.Mutating || t.Setup {
		return Command{}, renderError(name, "not a read-only template")
	}
	return t.bind(args)
}

func (r registry) renderMutating(name, marker string, args map[string]string) (Command, error) {
	return r.renderMutatingInput(name, marker, args, nil, "")
}

func (r registry) renderMutatingInput(name, marker string, args map[string]string, stdin []byte, flockProject string) (Command, error) {
	t, err := r.lookup(name)
	if err != nil {
		return Command{}, err
	}
	if !t.Mutating {
		return Command{}, renderError(name, "not a mutating template")
	}
	if !markerPattern.MatchString(marker) {
		return Command{}, renderError(name, "invalid marker")
	}
	if err := t.checkInputs(stdin, flockProject); err != nil {
		return Command{}, err
	}
	c, err := t.bind(args)
	if err != nil {
		return Command{}, err
	}
	c.Line = wrapMutating(c.Line, marker, t.Deadline)
	if t.Locked {
		c.Line = underFlock(flockProject, c.Line)
	}
	c.Stdin, c.Sensitive = stdin, t.Sensitive
	return c, nil
}

// checkInputs requires stdin exactly when the template is Sensitive and a
// project exactly when it is Locked.
func (t Template) checkInputs(stdin []byte, flockProject string) error {
	switch {
	case t.Sensitive != (len(stdin) > 0):
		return renderError(t.Name, "stdin is required by sensitive templates and refused by the others")
	case t.Locked != (flockProject != ""):
		return renderError(t.Name, "a project is required by locked templates and refused by the others")
	case t.Locked && !projectPattern.MatchString(flockProject):
		return renderError(t.Name, "invalid project")
	}
	return nil
}

func (r registry) renderSetup(name string, args map[string]string, stdin []byte) (Command, error) {
	t, err := r.lookup(name)
	if err != nil {
		return Command{}, err
	}
	if !t.Setup {
		return Command{}, renderError(name, "not a setup template")
	}
	c, err := t.bind(args)
	if err != nil {
		return Command{}, err
	}
	c.Stdin = stdin
	return c, nil
}

func (r registry) lookup(name string) (Template, error) {
	t, ok := r[name]
	if !ok {
		return Template{}, renderError(name, "unknown template")
	}
	return t, nil
}

// bind validates args against the template's parameters (exactly the declared
// set) and substitutes each placeholder with the quoted value.
func (t Template) bind(args map[string]string) (Command, error) {
	if len(args) != len(t.Params) {
		return Command{}, renderError(t.Name, fmt.Sprintf("want %d arguments, got %d", len(t.Params), len(args)))
	}
	quoted := make(map[string]string, len(t.Params))
	for _, p := range t.Params {
		value, ok := args[p.Name]
		if !ok {
			return Command{}, renderError(t.Name, "missing argument "+p.Name)
		}
		if err := admissible(value); err != nil {
			return Command{}, renderError(t.Name, fmt.Sprintf("argument %s: %v", p.Name, err))
		}
		if err := p.Validate(value); err != nil {
			return Command{}, renderError(t.Name, fmt.Sprintf("argument %s: %v", p.Name, err))
		}
		quoted[p.Name] = Quote(value)
	}
	line := placeholderPattern.ReplaceAllStringFunc(t.Body, func(ph string) string {
		return quoted[placeholderPattern.FindStringSubmatch(ph)[1]]
	})
	return Command{
		Template: t.Name, Line: line, Mutating: t.Mutating,
		Deadline: t.Deadline, MaxBytes: t.MaxBytes, MaxLines: t.MaxLines,
	}, nil
}

// admissible holds for every argument of every template, before its own
// validator: non-empty valid UTF-8 without NUL, and no leading "-", so no
// value can ever be read as an option (ADR-0015).
func admissible(value string) error {
	switch {
	case value == "":
		return fmt.Errorf("empty")
	case !utf8.ValidString(value) || strings.ContainsRune(value, 0):
		return fmt.Errorf("not valid UTF-8 text")
	case strings.HasPrefix(value, "-"):
		return fmt.Errorf("starts with '-'")
	}
	return nil
}

// Quote returns s as one POSIX shell word: single-quoted, each embedded single
// quote written as close-quote, escaped quote, reopen-quote.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// wrapMutating is the ADR-0015 marker wrapper. The marker is created before
// anything else and fails when the markers directory is missing; .done is
// written through a temporary file so it is either absent or complete.
func wrapMutating(line, marker string, deadline time.Duration) string {
	m := MarkerDir + "/" + marker
	return fmt.Sprintf(
		`: > %[1]s && { timeout --kill-after=%[2]s %[3]s %[4]s; rc=$?; printf '%%d\n' "$rc" > %[1]s.done.tmp && mv -f %[1]s.done.tmp %[1]s.done; exit "$rc"; }`,
		m, seconds(KillAfter), seconds(deadline), line)
}

// LockDir is the node-side directory of project locks; node.setup's tmpfiles
// entry creates it (ADR-0030).
const LockDir = "/run/supermgmt/locks"

// LockConflictExit is the exit status of a Locked command that found the
// project lock held and therefore never started.
const LockConflictExit = 75

// LockPath is the flock file of a Compose project.
func LockPath(project string) string { return LockDir + "/" + project + ".lock" }

// underFlock runs the marker command line holding the project lock, failing
// at once with LockConflictExit when the lock is taken (spec §20.4).
func underFlock(project, markerLine string) string {
	return fmt.Sprintf("flock --nonblock --conflict-exit-code %d %s sh -c %s",
		LockConflictExit, Quote(LockPath(project)), Quote(markerLine))
}

// seconds formats d for timeout(1), rounding up to whole seconds.
func seconds(d time.Duration) string {
	return fmt.Sprintf("%ds", (d+time.Second-1)/time.Second)
}

func catalogError(name, problem string) error {
	return smerr.New(smerr.CodeInternal, "", fmt.Sprintf("template catalog: %s: %s", name, problem))
}

func renderError(name, problem string) error {
	return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("template %s: %s", name, problem))
}
