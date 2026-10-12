package templates

import (
	"fmt"
	"time"
)

const (
	upDeadline   = 10 * time.Minute
	downDeadline = 5 * time.Minute
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
