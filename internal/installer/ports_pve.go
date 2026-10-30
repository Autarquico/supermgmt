package installer

import (
	"context"
	"io"
	"io/fs"
	"net/netip"

	"github.com/autarquico/supermgmt/internal/pveid"
)

// GuestNetwork is the container's single interface on Bridge.
type GuestNetwork struct {
	Bridge  string
	DHCP    bool
	Address netip.Prefix // static only
	Gateway netip.Addr   // static only
	DNS     []netip.Addr // static only; empty keeps the host's resolver settings
}

// GuestSpec is everything `pct create` receives (ADR-0026 "Container shape").
// The fixed flags (--unprivileged 1, --features nesting=0,keyctl=0, --onboot 1)
// are not fields: the implementation always passes them.
type GuestSpec struct {
	VMID        int
	Hostname    string
	Template    string // volume id, e.g. local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst
	Storage     string // rootfs storage
	DiskGiB     int
	Cores       int
	MemoryMiB   int
	SwapMiB     int
	Network     GuestNetwork
	Tags        []string
	Description string
}

// GuestConfig is the `pct config` readback the installer checks after create.
type GuestConfig struct {
	Unprivileged bool
	Features     map[string]string
	Mounts       []string // mpN keys present
	RawLXC       []string // lxc.* keys present
	Tags         []string
	Description  string
	Lock         string
}

// GuestState is `pct status` plus whether the VMID exists at all.
type GuestState struct {
	Exists bool
	Status string // running | stopped
	Lock   string // e.g. "create" while a create task holds it
}

// PVEStorage is a storage as `pvesm status` reports it.
type PVEStorage struct {
	ID      string
	Type    string
	Content []string // rootdir, vztmpl, images, …
	Active  bool
}

// ACL is one access-control entry; exactly one of User and Token is set.
type ACL = pveid.ACL

// PVE is the Proxmox host tooling the appliance installer uses (pct, pveam,
// pvesh, pveum, pveversion), always by absolute path with a clean environment
// and fixed argument vectors (ADR-0026). Implementations validate every name
// they put on a command line; a fake is used in tests (ADR-0023 fidelity).
type PVE interface {
	// Version is the pve-manager version, e.g. "9.0.3".
	Version(ctx context.Context) (string, error)
	NextID(ctx context.Context, from int) (int, error)
	Storages(ctx context.Context) ([]PVEStorage, error)
	Bridges(ctx context.Context) ([]string, error)
	// BridgeAddress is the host's own address on bridge, where the container
	// reaches the Proxmox API when no endpoint is given.
	BridgeAddress(ctx context.Context, bridge string) (netip.Addr, error)
	// Templates lists the vztmpl volumes on storage; AvailableTemplates the
	// names `pveam available --section system` offers.
	Templates(ctx context.Context, storage string) ([]string, error)
	AvailableTemplates(ctx context.Context) ([]string, error)
	DownloadTemplate(ctx context.Context, storage, name string) error

	Create(ctx context.Context, spec GuestSpec) error
	Config(ctx context.Context, vmid int) (GuestConfig, error)
	State(ctx context.Context, vmid int) (GuestState, error)
	Start(ctx context.Context, vmid int) error
	Stop(ctx context.Context, vmid int) error
	Destroy(ctx context.Context, vmid int) error
	// Exec runs argv inside the container as user ("" = root), never through a shell.
	Exec(ctx context.Context, vmid int, user string, argv []string, stdin io.Reader, sensitive bool) ([]byte, error)
	// Push copies a host file into the container with owner and mode.
	Push(ctx context.Context, vmid int, src, dst string, owner Owner, mode fs.FileMode) error

	pveid.Host
	// The removals and the ACL listing are the installer's alone: node setup
	// never deletes a user, a role or an ACL.
	RemoveUser(ctx context.Context, user string) error
	RemoveRole(ctx context.Context, role string) error
	ACLs(ctx context.Context) ([]ACL, error)
	RemoveACL(ctx context.Context, acl ACL) error
}
