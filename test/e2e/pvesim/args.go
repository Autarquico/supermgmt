package pvesim

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// toolError is a failed tool run: what it prints on stderr and its exit status. PVE's perl tools
// die with 255 on every usage or API error.
type toolError struct {
	code int
	msg  string
}

func (e *toolError) Error() string { return e.msg }

func die(format string, args ...any) error {
	return &toolError{code: 255, msg: fmt.Sprintf(format, args...)}
}

// check validates one option or positional value.
type check func(value string) error

type pattern struct {
	re    *regexp.Regexp
	check check
}

// command is the grammar of one tool subcommand: its positional arguments and the options it
// accepts. Anything else is refused.
type command struct {
	positional []string // names, all required
	opts       map[string]check
	patterns   []pattern // options by name pattern, e.g. net0, net1
	required   []string  // options that must be present
}

type parsed struct {
	pos  []string
	opts map[string]string
}

func (p parsed) has(name string) bool { _, ok := p.opts[name]; return ok }

func (p parsed) boolOpt(name string, def bool) bool {
	if v, ok := p.opts[name]; ok {
		return v == "1"
	}
	return def
}

func (c command) optionCheck(name string) (check, bool) {
	if chk, ok := c.opts[name]; ok {
		return chk, true
	}
	for _, p := range c.patterns {
		if p.re.MatchString(name) {
			return p.check, true
		}
	}
	return nil, false
}

// parse reads args the way PVE's Getopt-based tools do: --name value or --name=value, options
// anywhere, "--" ends the options.
func (c command) parse(args []string) (parsed, error) {
	out := parsed{opts: map[string]string{}}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			out.pos = append(out.pos, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
			chk, ok := c.optionCheck(name)
			if !strings.HasPrefix(arg, "--") || !ok {
				return out, die("Unknown option: %s\n400 unable to parse option", name)
			}
			if !hasValue {
				if i+1 >= len(args) {
					return out, die("Option %s requires an argument\n400 unable to parse option", name)
				}
				i++
				value = args[i]
			}
			if err := chk(value); err != nil {
				return out, die("400 Parameter verification failed.\n%s: %v", name, err)
			}
			if _, dup := out.opts[name]; dup {
				return out, die("Option %s given more than once\n400 unable to parse option", name)
			}
			out.opts[name] = value
		default:
			out.pos = append(out.pos, arg)
		}
	}
	return out, c.checkShape(out)
}

func (c command) checkShape(p parsed) error {
	switch {
	case len(p.pos) < len(c.positional):
		return die("400 not enough arguments (missing %s)", strings.Join(c.positional[len(p.pos):], ", "))
	case len(p.pos) > len(c.positional):
		return die("400 too many arguments")
	}
	for _, name := range c.required {
		if !p.has(name) {
			return die("400 Parameter verification failed.\n%s: property is missing and it is not optional", name)
		}
	}
	return nil
}

// ---- value checks ----

func anyText(v string) error {
	if v == "" {
		return fmt.Errorf("value is empty")
	}
	return nil
}

func integer(lo, hi int) check {
	return func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("value '%s' is not a valid integer", v)
		}
		if n < lo || n > hi {
			return fmt.Errorf("value does not have a value in the range %d - %d", lo, hi)
		}
		return nil
	}
}

func boolean(v string) error {
	switch v {
	case "0", "1", "yes", "no", "on", "off", "true", "false":
		return nil
	}
	return fmt.Errorf("type check ('boolean') failed - got '%s'", v)
}

func oneOf(values ...string) check {
	return func(v string) error {
		for _, ok := range values {
			if v == ok {
				return nil
			}
		}
		return fmt.Errorf("value '%s' does not have a value in the enumeration '%s'", v, strings.Join(values, ", "))
	}
}

func matching(what string, re *regexp.Regexp) check {
	return func(v string) error {
		if !re.MatchString(v) {
			return fmt.Errorf("value '%s' is not a valid %s", v, what)
		}
		return nil
	}
}

func optionNames(names ...string) map[string]check {
	m := make(map[string]check, len(names))
	for _, n := range names {
		m[n] = anyText
	}
	return m
}

func merge(maps ...map[string]check) map[string]check {
	out := map[string]check{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// outputFormat is the option every pvesh and pveum command takes.
var outputFormat = map[string]check{"output-format": oneOf("text", "json", "json-pretty", "yaml")}

func (p parsed) wantsJSON() bool {
	f := p.opts["output-format"]
	return f == "json" || f == "json-pretty"
}

// requireJSON refuses the table formats the shims do not draw.
func (p parsed) requireJSON() error {
	if !p.wantsJSON() {
		return die("pvesim: only --output-format json is implemented for this command")
	}
	return nil
}
