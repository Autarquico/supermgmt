package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/cli"
	"github.com/autarquico/supermgmt/internal/version"
)

// A node whose session user cannot reach Docker says so and names the command a person runs. The command is
// checked against the real CLI tree, so the hint cannot name a command that does not exist.
func TestANodeWithoutDockerAccessNamesTheCommandThatGrantsIt(t *testing.T) {
	rig := newMCPRig(t, false)
	rig.runtime.commands.Store(0)

	out, fail := mcpSecCall(t, mcpSecRigSession(t, rig, false), "infra_list_apps", map[string]any{"node": "dev-1"})

	if fail != nil {
		t.Fatalf("infra_list_apps: %+v", fail)
	}
	raw := fmt.Sprint(out)
	const command = "sm nodes setup dev-1 --docker-access"
	if !strings.Contains(raw, "docker_unavailable") || !strings.Contains(raw, command) {
		t.Errorf("answer = %s; want problem docker_unavailable and the hint %q", raw, command)
	}
	if n := rig.runtime.commands.Load(); n != 0 {
		t.Errorf("%d commands reached the node; want none, reading the apps of a node without access changes nothing", n)
	}

	setup, _, err := cli.NewRootCommand(version.Build{}).Find([]string{"nodes", "setup"})
	if err != nil || setup.Flags().Lookup("docker-access") == nil {
		t.Errorf("`sm nodes setup` has no --docker-access flag (err %v): the hint names a command that does not exist", err)
	}
}
