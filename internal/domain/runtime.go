package domain

import "slices"

// RuntimeType names a service manager or container runtime on a node (spec §16, §17).
type RuntimeType string

const (
	RuntimeSystemd RuntimeType = "systemd"
	RuntimeDocker  RuntimeType = "docker"
)

func AllRuntimeTypes() []RuntimeType { return []RuntimeType{RuntimeSystemd, RuntimeDocker} }
func ParseRuntimeType(s string) (RuntimeType, error) {
	return parseEnum("runtime type", AllRuntimeTypes(), s)
}
func (v RuntimeType) Valid() bool { return slices.Contains(AllRuntimeTypes(), v) }

// ServiceKind is the closed set of service kinds (services.kind). SQLite cannot
// add a CHECK to the existing column, so the domain and the repository enforce it.
type ServiceKind string

const (
	ServiceSystemdUnit     ServiceKind = "systemd_unit"
	ServiceDockerContainer ServiceKind = "docker_container"
)

func AllServiceKinds() []ServiceKind {
	return []ServiceKind{ServiceSystemdUnit, ServiceDockerContainer}
}

func ParseServiceKind(s string) (ServiceKind, error) {
	return parseEnum("service kind", AllServiceKinds(), s)
}
func (v ServiceKind) Valid() bool { return slices.Contains(AllServiceKinds(), v) }

// Runtime is the runtime that manages services of this kind; "" for an invalid kind.
func (v ServiceKind) Runtime() RuntimeType {
	switch v {
	case ServiceSystemdUnit:
		return RuntimeSystemd
	case ServiceDockerContainer:
		return RuntimeDocker
	}
	return ""
}

// ServiceVerb is a service action (spec §11.2 service.start|stop|restart).
type ServiceVerb string

const (
	VerbStart   ServiceVerb = "start"
	VerbStop    ServiceVerb = "stop"
	VerbRestart ServiceVerb = "restart"
)

func AllServiceVerbs() []ServiceVerb { return []ServiceVerb{VerbStart, VerbStop, VerbRestart} }
func ParseServiceVerb(s string) (ServiceVerb, error) {
	return parseEnum("service verb", AllServiceVerbs(), s)
}
func (v ServiceVerb) Valid() bool { return slices.Contains(AllServiceVerbs(), v) }

// Action is the catalog action that performs this verb, e.g. "service.restart".
func (v ServiceVerb) Action() string { return "service." + string(v) }
