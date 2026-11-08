package integration

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/cli"
	"github.com/autarquico/supermgmt/internal/version"
)

// The MCP coverage guard (spec mcp-tool-coverage): every `sm` command and every
// /api/v1 route is either served by a named MCP tool or listed with the reason
// it is not. A command or route that is new, or a mapping that outlived its tool
// or command, fails the test by name.

const mcpCoverageFile = "testdata/mcp_coverage.json"

// mcpCoverageEntry maps one command or route to exactly one of a tool or a
// reason. A reason starting with "pending: " names the spec that will close it.
type mcpCoverageEntry struct {
	Tool   string `json:"tool,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type mcpCoverageMap struct {
	Commands map[string]mcpCoverageEntry `json:"commands"`
	Routes   map[string]mcpCoverageEntry `json:"routes"`
}

func loadMCPCoverage(t *testing.T) mcpCoverageMap {
	t.Helper()
	raw, err := os.ReadFile(mcpCoverageFile)
	mcpRigMust(t, err)
	var doc mcpCoverageMap
	mcpRigMust(t, json.Unmarshal(raw, &doc))
	return doc
}

// cliCommands is the path of every command that does something, without "sm": the
// leaves and the parents that run by themselves. A parent without Run or RunE is
// skipped; a group whose RunE prints its help still needs an entry.
func cliCommands(cmd *cobra.Command) []string {
	var commands []string
	if len(cmd.Commands()) == 0 || cmd.Runnable() {
		commands = append(commands, strings.TrimPrefix(cmd.CommandPath(), "sm "))
	}
	for _, sub := range cmd.Commands() {
		commands = append(commands, cliCommands(sub)...)
	}
	return commands
}

// mcpCoverageProblems names everything the entries and the existing names
// disagree on.
func mcpCoverageProblems(kind string, existing []string, entries map[string]mcpCoverageEntry, tools map[string]bool) []string {
	var problems []string
	for _, name := range existing {
		if _, ok := entries[name]; !ok {
			problems = append(problems, kind+" "+name+" has no MCP tool and no exclusion")
		}
	}
	for name, entry := range entries {
		switch {
		case !slices.Contains(existing, name):
			problems = append(problems, kind+" "+name+" is mapped but no longer exists")
		case (entry.Tool == "") == (entry.Reason == ""):
			problems = append(problems, kind+" "+name+" must name a tool or give a reason, not both and not neither")
		case entry.Tool != "" && !tools[entry.Tool]:
			problems = append(problems, kind+" "+name+" is served by tool "+entry.Tool+", which the server does not register")
		}
	}
	slices.Sort(problems)
	return problems
}

func TestEveryCommandAndRouteHasAnMCPToolOrAnExplicitExclusion(t *testing.T) {
	rig := newMCPRig(t, false)
	covered := loadMCPCoverage(t)

	tools := map[string]bool{}
	for _, name := range mcpSecToolNames(t, mcpSecRigSession(t, rig, true)) {
		tools[name] = true
	}
	var routes []string
	for _, rt := range rig.server.Routes() {
		routes = append(routes, rt.Method+" "+rt.Pattern)
	}

	problems := mcpCoverageProblems("command", cliCommands(cli.NewRootCommand(version.Build{})), covered.Commands, tools)
	problems = append(problems, mcpCoverageProblems("route", routes, covered.Routes, tools)...)
	for _, problem := range problems {
		t.Errorf("%s: fix %s", problem, mcpCoverageFile)
	}
}

func TestTheCoverageGuardSeesARunnableParentButNotAHelpOnlyOne(t *testing.T) {
	noop := func(*cobra.Command, []string) {}
	root := &cobra.Command{Use: "sm", Run: noop}
	runnableParent := &cobra.Command{Use: "mcp", Run: noop}
	runnableParent.AddCommand(&cobra.Command{Use: "clients", Run: noop})
	helpOnlyParent := &cobra.Command{Use: "nodes"}
	helpOnlyParent.AddCommand(&cobra.Command{Use: "list", Run: noop})
	root.AddCommand(runnableParent, helpOnlyParent)

	got := cliCommands(root)

	for _, want := range []string{"sm", "mcp", "mcp clients", "nodes list"} {
		if !slices.Contains(got, want) {
			t.Errorf("commands %v lack %q", got, want)
		}
	}
	if slices.Contains(got, "nodes") {
		t.Errorf("help-only parent reported: %v", got)
	}
}

func TestTheCoverageGuardNamesWhatIsUnmappedStaleOrMisdeclared(t *testing.T) {
	tools := map[string]bool{"infra_list_nodes": true}
	entries := map[string]mcpCoverageEntry{
		"nodes list":  {Tool: "infra_list_nodes"},
		"gone":        {Reason: "removed command"},
		"both":        {Tool: "infra_list_nodes", Reason: "why"},
		"neither":     {},
		"ghost tool":  {Tool: "infra_missing"},
		"jobs cancel": {Reason: "excluded"},
	}
	existing := []string{"nodes list", "both", "neither", "ghost tool", "jobs cancel", "brand new"}

	got := strings.Join(mcpCoverageProblems("command", existing, entries, tools), "\n")

	for _, want := range []string{
		"command brand new has no MCP tool and no exclusion",
		"command gone is mapped but no longer exists",
		"command both must name a tool or give a reason",
		"command neither must name a tool or give a reason",
		"command ghost tool is served by tool infra_missing, which the server does not register",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("problems lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "command nodes list") || strings.Contains(got, "command jobs cancel") {
		t.Errorf("a valid entry was reported:\n%s", got)
	}
}
