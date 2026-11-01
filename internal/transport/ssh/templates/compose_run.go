package templates

import (
	"fmt"
	"time"
)

const (
	upDeadline   = 10 * time.Minute
	downDeadline = 5 * time.Minute
	// createDeadline covers creating containers and volumes, nothing is started.
	createDeadline = 5 * time.Minute
)

// composeCommand is `docker compose` on the materialized deployment directory
// under `env -i`: the same environment compose.verify resolved the model in,
// so what runs is what was verified.
func composeCommand(verb string) string {
	return composeEnv + "docker compose -f " + deployDirectory + "/compose.yaml -p {{project}}" +
		" --project-directory " + deployDirectory + " " + verb
}

// composeRunTemplates holds the commands that change or inspect the running
// project (spec §20.4). Images are pulled beforehand and never rebuilt, and
// volumes are never removed.
var composeRunTemplates = []Template{
	{
		Name: "compose.up", Params: deployDirectoryParams, Mutating: true, Locked: true,
		Deadline: upDeadline, MaxBytes: 256 << 10, MaxLines: 2000,
		Body: composeCommand("up --detach --pull never --no-build --remove-orphans"),
	},
	{
		Name: "compose.down", Params: deployDirectoryParams, Mutating: true, Locked: true,
		Deadline: downDeadline, MaxBytes: 256 << 10, MaxLines: 2000,
		Body: composeCommand("down --remove-orphans"),
	},
	{
		// Creates the containers and their volumes without starting anything
		// (app move: B is prepared while A keeps serving).
		Name: "compose.create", Params: deployDirectoryParams, Mutating: true, Locked: true,
		Deadline: createDeadline, MaxBytes: 256 << 10, MaxLines: 2000,
		Body: composeCommand("create --pull never --no-build"),
	},
	{
		Name: "compose.start", Params: deployDirectoryParams, Mutating: true, Locked: true,
		Deadline: upDeadline, MaxBytes: 256 << 10, MaxLines: 2000,
		Body: composeCommand("start"),
	},
	{
		Name: "compose.stop", Params: deployDirectoryParams, Mutating: true, Locked: true,
		Deadline: downDeadline, MaxBytes: 256 << 10, MaxLines: 2000,
		Body: composeCommand("stop"),
	},
	{
		// One JSON object per line for each container of the project: its ID,
		// names, state and labels.
		Name: "compose.ps_state", Params: []Param{paramProject}, MaxBytes: 4 << 20,
		Body: "docker ps --all --no-trunc --filter label=com.docker.compose.project={{project}} --format json",
	},
	{
		Name: "compose.ps", Params: deployDirectoryParams, MaxBytes: 4 << 20,
		Body: composeCommand("ps --all --format json"),
	},
	{
		// Exit 0: the lock was free (and released again). LockConflictExit: a
		// compose command of this project still holds it.
		Name: "compose.lock_probe", Params: []Param{paramProject}, MaxBytes: 1 << 10, MaxLines: 5,
		Body: fmt.Sprintf("flock --nonblock --conflict-exit-code %d %s/{{project}}.lock true", LockConflictExit, LockDir),
	},
}
