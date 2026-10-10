// Command gen writes the environment-override table into docs/configuration.md
// between the generated-table markers.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/autarquico/supermgmt/internal/config"
)

func main() {
	out := flag.String("out", "docs/configuration.md", "markdown file holding the generated table markers")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	doc, err := os.ReadFile(path) //nolint:gosec // path is a developer-supplied flag of a generator
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	updated, err := config.ReplaceEnvTable(string(doc))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil { //nolint:gosec // documentation file, world-readable by design
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
