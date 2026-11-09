package docs_test

import (
	"strings"
	"testing"
)

// Spec retire-deployments, scenario "the deployment surfaces are gone": the
// command, tool and TUI guides show none of them. `sm apps list|show|logs` are the unrelated reads of the app
// panels, so only the retired subcommands are guarded.
func TestTheGuidesShowNoDeploymentSurface(t *testing.T) {
	retired := map[string][]string{
		"docs/cli.md": {"sm deploy", "sm rollback", "sm deployments", "sm apps expose", "sm apps move"},
		"docs/mcp.md": {"infra_create_deployment", "infra_rollback_deployment", "infra_list_deployments", "infra_get_deployment"},
		"docs/tui.md": {"/ deploy", "/ rollback", "Deployment timeline"},
	}
	for page, names := range retired {
		text := readRepoFile(t, page)
		for _, name := range names {
			if strings.Contains(text, name) {
				t.Errorf("%s still shows %q", page, name)
			}
		}
	}
}
