package health

import (
	"fmt"
	"strconv"
)

// Template names of the node-scope checks (templates/health.go).
const (
	templateHTTP   = "health.http"
	templateTCP    = "health.tcp"
	templateDocker = "health.docker"
)

// NodeInvocation names the SSH template that runs a validated node-scope
// check and its arguments. d must come from ValidateManifest or
// ValidateControlPlane. docker-health carries no arguments here: the caller
// adds "container" for the service it inspects.
func NodeInvocation(c Check, d Destination) (string, map[string]string, error) {
	if c.Scope != ScopeNode {
		return "", nil, fmt.Errorf("health: scope %q has no node invocation", c.Scope)
	}
	if err := checkTimeout(c.Timeout); err != nil {
		return "", nil, err
	}
	if c.Type == TypeDockerHealth {
		return templateDocker, map[string]string{}, nil
	}
	if !d.Addr.IsValid() || d.Port == 0 {
		return "", nil, fmt.Errorf("health: %s needs a validated destination", c.Type)
	}
	args := map[string]string{
		"addr":    d.Addr.String(),
		"port":    strconv.Itoa(int(d.Port)),
		"timeout": strconv.Itoa(int(c.Timeout.Seconds())),
	}
	switch c.Type {
	case TypeHTTP:
		args["path"] = c.Path
		return templateHTTP, args, nil
	case TypeTCP:
		return templateTCP, args, nil
	}
	return "", nil, fmt.Errorf("health: node-scope type %q is not supported", c.Type)
}
