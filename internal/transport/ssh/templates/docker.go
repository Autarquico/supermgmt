package templates

import (
	"fmt"
	"regexp"
	"strings"
)

var containerRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// ValidateContainer accepts a container name or ID as Docker itself allows it.
func ValidateContainer(s string) error {
	if !containerRE.MatchString(s) {
		return fmt.Errorf("not a container name or ID")
	}
	return nil
}

// ValidateRestartPolicy accepts the restart policies a Compose model can set.
func ValidateRestartPolicy(s string) error {
	switch s {
	case "no", "always", "on-failure", "unless-stopped":
		return nil
	}
	return fmt.Errorf("not a restart policy")
}

var (
	paramContainer = Param{Name: "container", Validate: ValidateContainer}
	paramRestart   = Param{Name: "policy", Validate: ValidateRestartPolicy}
	paramVolume    = Param{Name: "volume", Validate: ValidateVolume}
)

// MaxInspectedVolumes is the most names one docker.volume_inspect_many takes.
const MaxInspectedVolumes = 64

// validateVolumeList accepts comma-separated volume names, at most
// MaxInspectedVolumes.
func validateVolumeList(s string) error {
	names := strings.Split(s, ",")
	if len(names) > MaxInspectedVolumes {
		return fmt.Errorf("more than %d volumes", MaxInspectedVolumes)
	}
	for _, n := range names {
		if err := ValidateVolume(n); err != nil {
			return err
		}
	}
	return nil
}

const volumeInspectManyScript = `set -f
all=$(docker volume ls --quiet) || exit 1
IFS=,
found=
for v in $1; do
  printf '%s\n' "$all" | grep -qxF -- "$v" && found="$found $v"
done
unset IFS
[ -n "$found" ] || { echo '[]'; exit 0; }
exec docker volume inspect -- $found
`

func containerAction(verb string) Template {
	return Template{
		Name: "docker." + verb, Body: "docker " + verb + " -- {{container}}",
		Params: []Param{paramContainer}, Mutating: true,
		Deadline: ActionDeadline, MaxBytes: 64 << 10,
	}
}

// dockerTemplates holds the Docker discovery, logs and container actions
// (spec §17). Output formats avoid Go templates ('{{' is reserved for
// parameters): `docker inspect` already prints JSON.
var dockerTemplates = []Template{
	{Name: "docker.version", Body: "docker version", MaxBytes: 16 << 10, MaxLines: 200},
	{Name: "docker.compose_version", Body: "docker compose version --short", MaxBytes: 1 << 10, MaxLines: 5},
	{
		Name: "docker.inspect_all", MaxBytes: 8 << 20,
		Body: `ids=$(docker ps -aq --no-trunc) && { [ -z "$ids" ] || docker inspect --type container $ids; }`,
	},
	{
		Name: "docker.inspect", Params: []Param{paramContainer}, MaxBytes: 1 << 20,
		Body: "docker inspect --type container -- {{container}}",
	},
	{
		Name: "docker.logs", Params: []Param{paramContainer, paramLines}, MaxBytes: 4 << 20, MaxLines: MaxLogLines + 10,
		Body: "docker logs --timestamps --tail {{lines}} -- {{container}} 2>&1",
	},
	{
		// The volume is only removed when no container uses it; there is no force.
		Name: "docker.volume_rm", Params: []Param{paramVolume}, Mutating: true,
		Deadline: ActionDeadline, MaxBytes: 64 << 10,
		Body: "docker volume rm -- {{volume}}",
	},
	{
		// Sets the restart policy of one container, so a container stopped on purpose does not come back with the
		// Docker daemon.
		Name: "docker.update_restart", Params: []Param{paramContainer, paramRestart}, Mutating: true,
		Deadline: ActionDeadline, MaxBytes: 64 << 10,
		Body: "docker update --restart {{policy}} -- {{container}}",
	},
	{
		Name: "docker.info_resources", MaxBytes: 1 << 10, MaxLines: 5,
		Body: "docker info --format " + goTemplateArg(`{"NCPU":{{json .NCPU}},"MemTotal":{{json .MemTotal}}}`),
	},
	{
		Name: "docker.volume_sizes", MaxBytes: 8 << 20,
		Body: "docker system df --verbose --format json",
	},
	{
		// A JSON array of the listed volumes that exist, in any order; a daemon
		// that cannot list its volumes is a failure, never an empty array.
		Name: "docker.volume_inspect_many", Params: []Param{{Name: "volumes", Validate: validateVolumeList}}, MaxBytes: 4 << 20,
		Body: shellScript("sh", volumeInspectManyScript, "volumes"),
	},
	containerAction("start"),
	containerAction("stop"),
	containerAction("restart"),
}
