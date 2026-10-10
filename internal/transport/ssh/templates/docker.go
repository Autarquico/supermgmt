package templates

import (
	"fmt"
	"regexp"
)

var containerRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// ValidateContainer accepts a container name or ID as Docker itself allows it.
func ValidateContainer(s string) error {
	if !containerRE.MatchString(s) {
		return fmt.Errorf("not a container name or ID")
	}
	return nil
}

var paramContainer = Param{Name: "container", Validate: ValidateContainer}

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
	containerAction("start"),
	containerAction("stop"),
	containerAction("restart"),
}
