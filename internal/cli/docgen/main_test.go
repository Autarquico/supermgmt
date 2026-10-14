package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/cli"
	"github.com/autarquico/supermgmt/internal/version"
)

func newRoot() *cobra.Command { return cli.NewRootCommand(version.Build{}) }

func TestRenderIsDeterministic(t *testing.T) {
	if render(newRoot()) != render(newRoot()) {
		t.Fatal("two renders of the same tree differ")
	}
}

func TestRenderListsEveryAvailableCommandOnce(t *testing.T) {
	reference := render(newRoot())
	walkAvailable(newRoot(), func(c *cobra.Command) {
		heading := "\n" + strings.Repeat("#", min(depth(c)+2, maxHeadingLevel)) + " " + c.CommandPath() + "\n"
		if n := strings.Count(reference, heading); n != 1 {
			t.Errorf("%q appears %d times, want 1", heading, n)
		}
	})
}

func TestRenderOmitsHiddenCommands(t *testing.T) {
	root := newRoot()
	root.AddCommand(&cobra.Command{Use: "internal-only", Short: "not for users", Hidden: true, Run: func(*cobra.Command, []string) {}})

	if strings.Contains(render(root), "internal-only") {
		t.Fatal("hidden command is documented")
	}
}

func TestRenderDocumentsCommandsAndFlags(t *testing.T) {
	reference := render(newRoot())
	for _, want := range []string{
		"## sm\n",
		"### sm nodes\n",
		"- `--json` (bool): machine-readable JSON output",
		"- `--log-level` (string, default `info`)",
		"Also accepts the global flags `--config`, `--json`, `--log-level`.",
	} {
		if !strings.Contains(reference, want) {
			t.Errorf("reference lacks %q", want)
		}
	}
}

func TestCommittedReferenceMatchesTheCommandTree(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "cli.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(committed) != render(newRoot()) {
		t.Fatal("docs/cli.md is stale; run `make generate`")
	}
}

func walkAvailable(c *cobra.Command, visit func(*cobra.Command)) {
	visit(c)
	for _, sub := range c.Commands() {
		if sub.IsAvailableCommand() {
			walkAvailable(sub, visit)
		}
	}
}

func depth(c *cobra.Command) int {
	n := 0
	for p := c.Parent(); p != nil; p = p.Parent() {
		n++
	}
	return n
}
