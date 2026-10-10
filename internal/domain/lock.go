package domain

import "fmt"

// LockSpec names a lock to acquire when a job is claimed (spec §20.5).
type LockSpec struct {
	Key  string
	Mode LockMode
}

// ResourceLock locks a single resource: "<resource_type>:<id>".
func ResourceLock(ref ResourceRef, mode LockMode) LockSpec {
	return LockSpec{Key: fmt.Sprintf("%s:%s", ref.Type, ref.ID), Mode: mode}
}

// ComposeProjectLock locks a Compose project on a node: "compose_project:<node>:<project>".
func ComposeProjectLock(node ID, project string, mode LockMode) LockSpec {
	return LockSpec{Key: fmt.Sprintf("compose_project:%s:%s", node, project), Mode: mode}
}

// PortLock locks a published host port on a node: "port:<node>:<addr>:<port>".
func PortLock(node ID, addr string, port int, mode LockMode) LockSpec {
	return LockSpec{Key: fmt.Sprintf("port:%s:%s:%d", node, addr, port), Mode: mode}
}
