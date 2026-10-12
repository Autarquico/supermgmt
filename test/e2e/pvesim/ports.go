package pvesim

import "context"

// ExecResult is a command run inside a container.
type ExecResult struct {
	Stdout, Stderr []byte
	Code           int
}

// ContainerSpec is what `pct create` asks of the container runtime.
type ContainerSpec struct {
	Hostname string
	IP       string // static IPv4 address without prefix; empty = dynamic
}

// Engine runs the guests: one container per LXC. The Docker implementation backs the e2e tests; a
// memory implementation backs the unit tests of the command grammar.
type Engine interface {
	Create(ctx context.Context, name string, spec ContainerSpec) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Remove(ctx context.Context, name string) error
	Exec(ctx context.Context, name string, argv []string, stdin []byte) (ExecResult, error)
}

// FakeGuest is a guest as the fake PVE API lists it.
type FakeGuest struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Status string `json:"status"` // running | stopped
}

// API is the administration side of the fake PVE API: the state the pve tools change.
type API interface {
	PutGuest(ctx context.Context, g FakeGuest) error
	RemoveGuest(ctx context.Context, vmid int) error
	SetRole(ctx context.Context, name string, privileges []string) error
	// AddToken creates the token and returns its secret.
	AddToken(ctx context.Context, user, id string, privsep bool) (secret string, err error)
	Grant(ctx context.Context, subject, path, role string, propagate bool) error
	Revoke(ctx context.Context, subject, path, role string) error
}

// Request is one tool run, as the shim sends it.
type Request struct {
	Tool  string   `json:"tool"`
	Args  []string `json:"args"`
	Stdin []byte   `json:"stdin,omitempty"`
}

// Response is its outcome.
type Response struct {
	Stdout []byte `json:"stdout"`
	Stderr []byte `json:"stderr"`
	Code   int    `json:"code"`
}
