package docs_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/autarquico/supermgmt/internal/cli"
	"github.com/autarquico/supermgmt/internal/version"
)

// commandPages are the pages whose `sm ...` commands are checked against the real command tree.
var commandPages = []string{"docs/getting-started.md", "docs/tui.md", "README.md", "docs/mcp.md"}

// ---- finding commands in a page ----------------------------------------------------------------

type quotedCommand struct {
	line   int
	text   string // the command without the leading "sm" and "$ "
	inline bool   // quoted in a code span, where "a|b" means alternatives
}

var shellOperator = regexp.MustCompile(`\s(\||>|>>|&&|;|2>)\s`)

// commandsIn returns every command a page shows: lines of fenced code that start with "sm" and
// code spans that start with "sm ". Palette input (`/ ssh web1`, `setup <node>`) never starts with
// "sm" and is not returned.
func commandsIn(page string) []quotedCommand {
	var found []quotedCommand
	inFence := false
	pending := ""
	for i, line := range strings.Split(page, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			for _, span := range backtickSpan.FindAllStringSubmatch(line, -1) {
				if text, ok := strings.CutPrefix(strings.ReplaceAll(span[1], `\|`, "|"), "sm "); ok {
					found = append(found, quotedCommand{i + 1, text, true})
				}
			}
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "$ ")
		if pending != "" {
			trimmed = pending + " " + trimmed
			pending = ""
		}
		if text, ok := strings.CutSuffix(trimmed, `\`); ok {
			pending = strings.TrimSpace(text)
			continue
		}
		if text, ok := strings.CutPrefix(trimmed, "sm "); ok {
			found = append(found, quotedCommand{i + 1, text, false})
		}
	}
	return found
}

// ---- checking one command against the tree -----------------------------------------------------

// checkCommand walks the words of a command down the tree and checks every flag against the command
// it ends on. It returns "" when the command is valid.
func checkCommand(root *cobra.Command, c quotedCommand) string {
	text := shellOperator.Split(strings.SplitN(c.text, " #", 2)[0], 2)[0]
	words := strings.Fields(text)
	cur := root
	descending := true
	for i := 0; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			return ""
		case strings.HasPrefix(word, "-"):
			consumesValue, problem := checkFlag(cur, word)
			if problem != "" {
				return problem
			}
			if consumesValue {
				i++
			}
		case !descending:
		case c.inline && strings.Contains(word, "|"):
			return checkAlternatives(cur, word)
		default:
			sub := subcommand(cur, word)
			switch {
			case sub != nil:
				cur = sub
			case acceptsOnlySubcommands(cur):
				return fmt.Sprintf("%q is not a subcommand of %q", word, cur.CommandPath())
			default:
				descending = false
			}
		}
	}
	return ""
}

func subcommand(parent *cobra.Command, name string) *cobra.Command {
	for _, sub := range parent.Commands() {
		if sub.Name() == name || sub.HasAlias(name) {
			return sub
		}
	}
	return nil
}

// acceptsOnlySubcommands is true for a command that groups others and takes no arguments of its
// own: a word that is no subcommand is then a mistake, not an argument.
func acceptsOnlySubcommands(cmd *cobra.Command) bool {
	return cmd.HasSubCommands() && (cmd.Args == nil || cmd.Args(cmd, []string{"x"}) != nil)
}

func checkAlternatives(parent *cobra.Command, word string) string {
	if !parent.HasSubCommands() {
		return ""
	}
	for _, alt := range strings.Split(word, "|") {
		if subcommand(parent, alt) == nil {
			return fmt.Sprintf("%q is not a subcommand of %q", alt, parent.CommandPath())
		}
	}
	return ""
}

// checkFlag validates one flag word against cmd and says whether the next word is its value.
func checkFlag(cmd *cobra.Command, word string) (consumesValue bool, problem string) {
	cmd.InheritedFlags() // merges the parents' persistent flags into cmd.Flags()
	var flag *pflag.Flag
	hasValue := strings.Contains(word, "=")
	if name, ok := strings.CutPrefix(word, "--"); ok {
		name, _, _ = strings.Cut(name, "=")
		if name == "help" {
			return false, ""
		}
		flag = cmd.Flags().Lookup(name)
	} else {
		short := word[1:2]
		if short == "h" {
			return false, ""
		}
		flag = cmd.Flags().ShorthandLookup(short)
	}
	if flag == nil {
		return false, fmt.Sprintf("%s is not a flag of %q", word, cmd.CommandPath())
	}
	return !hasValue && flag.NoOptDefVal == "", ""
}

// ---- the tests ---------------------------------------------------------------------------------

func newTree() *cobra.Command {
	return cli.NewRootCommand(version.Build{})
}

func TestEveryCommandShownInTheGuidesExistsInTheCommandTree(t *testing.T) {
	root := newTree()
	for _, pagePath := range commandPages {
		commands := commandsIn(readRepoFile(t, pagePath))
		if len(commands) == 0 {
			t.Errorf("%s shows no `sm` command; the list of checked pages is stale", pagePath)
		}
		for _, c := range commands {
			if problem := checkCommand(root, c); problem != "" {
				t.Errorf("%s:%d `sm %s`: %s", pagePath, c.line, c.text, problem)
			}
		}
	}
}

func TestCommandCheckRejectsWhatItShould(t *testing.T) {
	root := newTree()
	tests := []struct{ name, command, want string }{
		{"unknown top-level command", "frobnicate", "not a subcommand"},
		{"unknown subcommand", "nodes frobnicate", "not a subcommand"},
		{"unknown flag", "nodes add --no-such-flag", "not a flag"},
		{"flag of another command", "version --host x", "not a flag"},
		{"unknown alternative", "mcp clients add|list|frobnicate", "not a subcommand"},
	}
	for _, tc := range tests {
		got := checkCommand(root, quotedCommand{text: tc.command, inline: true})
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: `sm %s` gave %q, want it to mention %q", tc.name, tc.command, got, tc.want)
		}
	}
}

func TestCommandCheckAcceptsWhatTheTreeAccepts(t *testing.T) {
	root := newTree()
	valid := []string{
		"version",
		"nodes add --local --yes",
		"nodes add --name web1 --host 203.0.113.10 --admin-user root",
		"--json nodes list",
		"--config examples/config.yaml doctor --offline",
		"nodes setup web1 --docker-access # a comment",
		"jobs approve <job-id> --plan-hash <hash>",
		"mcp clients add|list|remove",
		"nodes list --help",
	}
	for _, command := range valid {
		if got := checkCommand(root, quotedCommand{text: command, inline: true}); got != "" {
			t.Errorf("`sm %s` was rejected: %s", command, got)
		}
	}
}

func TestCommandsAreFoundInFencesAndSpansButPaletteInputIsNot(t *testing.T) {
	page := "Run `sm doctor --offline` or press `/` and type `ssh web1 btop`.\n\n" +
		"```\nsm version\n$ sm nodes list   # all\nsm nodes add \\\n  --local\nls -l | sm status\n```\n" +
		"```yaml\nname: sm things\n```\n"
	var got []string
	for _, c := range commandsIn(page) {
		got = append(got, c.text)
	}
	want := "doctor --offline|version|nodes list   # all|nodes add --local"
	if strings.Join(got, "|") != want {
		t.Errorf("commands found = %q, want %q", strings.Join(got, "|"), want)
	}
}

// ---- the TUI palette ---------------------------------------------------------------------------

var paletteRow = regexp.MustCompile("^\\| `([a-z]+)[ `]")

// TestEveryPaletteCommandInTheTUIGuideIsHandledByTheTUI keeps palette input apart from `sm`
// commands: the palette is not a shell, so its verbs are checked against the TUI source.
func TestEveryPaletteCommandInTheTUIGuideIsHandledByTheTUI(t *testing.T) {
	_, section, found := strings.Cut(readRepoFile(t, "docs/tui.md"), "\n## Command palette\n")
	if !found {
		t.Fatal("docs/tui.md has no \"Command palette\" section")
	}
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	source := readRepoFile(t, "internal/tui/action.go") + readRepoFile(t, "internal/tui/wizard.go")
	verbs := 0
	for _, line := range strings.Split(section, "\n") {
		if m := paletteRow.FindStringSubmatch(line); m != nil {
			verbs++
			if !strings.Contains(source, `"`+m[1]+`"`) {
				t.Errorf("docs/tui.md documents the palette command %q, which internal/tui does not handle", m[1])
			}
		}
	}
	if verbs == 0 {
		t.Error("docs/tui.md lists no palette commands")
	}
}
