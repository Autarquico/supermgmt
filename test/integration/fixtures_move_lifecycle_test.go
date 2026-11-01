//go:build fixtures

package integration

import (
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The reads and lifecycle commands of an app move against a real Docker daemon: what preflight, the reconcile
// evidence and compensation decide from must decode, and the commands must leave what the evidence looks for.
// The job itself is not driven here: its handler needs the app package's database world, so the job is covered by
// the two-fake-node tests in internal/app.

func (n *deployNode) containerStates(t *testing.T) []string {
	t.Helper()
	res := n.readTemplate(t, "compose.ps_state", map[string]string{"project": moveProject})
	if res.ExitStatus != 0 {
		t.Fatalf("compose.ps_state: %s", stderrOf(res))
	}
	containers, err := templates.ParsePsState(res.Stdout, moveProject)
	if err != nil {
		t.Fatalf("ParsePsState(%q): %v", res.Stdout, err)
	}
	var states []string
	for _, c := range containers {
		states = append(states, c.Service+"="+c.State)
	}
	return states
}

func (n *deployNode) existingVolumes(t *testing.T, names ...string) []string {
	t.Helper()
	res := n.readTemplate(t, "docker.volume_inspect_many", map[string]string{"volumes": joinComma(names)})
	if res.ExitStatus != 0 {
		t.Fatalf("docker.volume_inspect_many: %s", stderrOf(res))
	}
	volumes, err := templates.ParseVolumeInspectMany(res.Stdout)
	if err != nil {
		t.Fatalf("ParseVolumeInspectMany(%q): %v", res.Stdout, err)
	}
	var found []string
	for _, v := range volumes {
		found = append(found, v.Name)
	}
	slices.Sort(found)
	return found
}

func joinComma(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ","
		}
		out += n
	}
	return out
}

func TestFixtures_MoveReadsAndLifecycleCommandsLeaveWhatTheEvidenceLooksFor(t *testing.T) {
	n := startDeployNode(t)
	n.shell(t, moveSeedScript)
	n.adoptProject(t, moveProject)
	if res := n.materialize(t, deployDirArgs(moveProject, moveDeployment), composeOnly(moveCompose)); res.ExitStatus != 0 {
		t.Fatalf("materialize: %s", stderrOf(res))
	}
	data, state := moveProject+"_data", moveProject+"_state"

	t.Run("a node reports its CPUs and memory", func(t *testing.T) {
		res := n.readTemplate(t, "docker.info_resources", nil)
		got, err := templates.ParseInfoResources(res.Stdout)
		if err != nil || got.NCPU <= 0 || got.MemTotal <= 0 {
			t.Fatalf("ParseInfoResources(%q) = %+v, %v", res.Stdout, got, err)
		}
	})

	t.Run("before compose create there is nothing of the project", func(t *testing.T) {
		if got := n.containerStates(t); len(got) != 0 {
			t.Errorf("containers = %v", got)
		}
		if got := n.existingVolumes(t, data, state); len(got) != 0 {
			t.Errorf("volumes = %v, want none: absent must read as an empty array, not an error", got)
		}
	})

	n.composeCreate(t)

	t.Run("compose create leaves a created container and the volumes", func(t *testing.T) {
		if got := n.containerStates(t); !slices.Equal(got, []string{"web=created"}) {
			t.Errorf("containers = %v", got)
		}
		if got := n.existingVolumes(t, data, state, moveProject+"_nope"); !slices.Equal(got, []string{data, state}) {
			t.Errorf("volumes = %v, want %s and %s without the one that does not exist", got, data, state)
		}
	})

	t.Run("volume sizes cover the volume and round up", func(t *testing.T) {
		n.volumeShell(t, "head -c 2000000 /dev/urandom > /data/blob")
		res := n.readTemplate(t, "docker.volume_sizes", nil)
		sizes, err := templates.ParseVolumeSizes(res.Stdout)
		if err != nil {
			t.Fatalf("ParseVolumeSizes(%.300q): %v", res.Stdout, err)
		}
		if got, ok := sizes[data]; !ok || got < 2_000_000 {
			t.Errorf("size of %s = %d (listed %v), want at least the 2000000 bytes written", data, got, ok)
		}
	})

	t.Run("start, stop and down leave what the evidence judges", func(t *testing.T) {
		for _, step := range []struct {
			verb string
			want []string
		}{
			{"start", []string{"web=running"}},
			{"stop", []string{"web=exited"}},
			{"start", []string{"web=running"}},
			{"stop", []string{"web=exited"}},
			{"stop", []string{"web=exited"}}, // stopping a stopped project succeeds again: a retry is safe
			{"down", nil},
		} {
			n.compose(t, step.verb)
			if got := n.containerStates(t); !slices.Equal(got, step.want) {
				t.Fatalf("after compose.%s containers = %v, want %v", step.verb, got, step.want)
			}
		}
		if got := n.existingVolumes(t, data, state); !slices.Equal(got, []string{data, state}) {
			t.Errorf("volumes after down = %v, down must keep them", got)
		}
	})

	t.Run("volume removal takes one volume, and a second removal fails", func(t *testing.T) {
		if res, _ := n.mutate(t, "docker.volume_rm", map[string]string{"volume": data}, nil, ""); res.ExitStatus != 0 {
			t.Fatalf("docker.volume_rm: %s", stderrOf(res))
		}
		if got := n.existingVolumes(t, data, state); !slices.Equal(got, []string{state}) {
			t.Errorf("volumes = %v, want only %s", got, state)
		}
		if res, _ := n.mutate(t, "docker.volume_rm", map[string]string{"volume": data}, nil, ""); res.ExitStatus == 0 {
			t.Error("removing an absent volume succeeded: a retry would read as done without proof")
		}
	})

	t.Run("a volume in use by a container is not removed", func(t *testing.T) {
		n.composeCreate(t)
		if res, _ := n.mutate(t, "docker.volume_rm", map[string]string{"volume": state}, nil, ""); res.ExitStatus == 0 {
			t.Error("docker.volume_rm removed a volume a container still uses")
		}
		if got := n.existingVolumes(t, state); !slices.Equal(got, []string{state}) {
			t.Errorf("volumes = %v, want %s kept", got, state)
		}
	})
}
