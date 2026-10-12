package proxmox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// number decodes a JSON number or a numeric string: PVE uses both for the
// same field across versions and endpoints.
type number float64

func (n *number) UnmarshalJSON(b []byte) error {
	b = bytes.Trim(bytes.TrimSpace(b), `"`)
	if len(b) == 0 || string(b) == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("proxmox: %q is not a number", b)
	}
	*n = number(f)
	return nil
}

func (n number) int64() int64 { return int64(n) }
func (n number) int() int     { return int(n) }
func (n number) flag() bool   { return n != 0 }

type envelope struct {
	Data  json.RawMessage `json:"data"`
	Total number          `json:"total"`
}

type resourceWire struct {
	Type     string `json:"type"`
	Node     string `json:"node"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Pool     string `json:"pool"`
	Storage  string `json:"storage"`
	Plugin   string `json:"plugin"`
	Content  string `json:"content"`
	VMID     number `json:"vmid"`
	Template number `json:"template"`
	Shared   number `json:"shared"`
	MaxCPU   number `json:"maxcpu"`
	MaxMem   number `json:"maxmem"`
	MaxDisk  number `json:"maxdisk"`
	CPU      number `json:"cpu"`
	Mem      number `json:"mem"`
	Disk     number `json:"disk"`
	Uptime   number `json:"uptime"`
}

func decodeInventory(data []byte) (Inventory, error) {
	var rows []resourceWire
	if err := json.Unmarshal(data, &rows); err != nil {
		return Inventory{}, fmt.Errorf("proxmox: decode cluster resources: %w", err)
	}
	var inv Inventory
	for i, r := range rows {
		switch r.Type {
		case "node":
			if !nodeNamePattern.MatchString(r.Node) {
				return Inventory{}, fmt.Errorf("proxmox: cluster resource %d: invalid node name %q", i, r.Node)
			}
			inv.Nodes = append(inv.Nodes, ClusterNode{
				Name: r.Node, Status: r.Status, MaxCPU: r.MaxCPU.int(), MaxMem: r.MaxMem.int64(),
				CPU: float64(r.CPU), Mem: r.Mem.int64(), Uptime: r.Uptime.int64(),
			})
		case string(GuestQEMU), string(GuestLXC):
			if r.VMID <= 0 || !nodeNamePattern.MatchString(r.Node) {
				return Inventory{}, fmt.Errorf("proxmox: cluster resource %d: guest without vmid or node", i)
			}
			inv.Guests = append(inv.Guests, Guest{
				Ref:  GuestRef{Node: r.Node, Type: GuestType(r.Type), VMID: r.VMID.int()},
				Name: r.Name, Status: r.Status, Template: r.Template.flag(), Pool: r.Pool,
				MaxCPU: r.MaxCPU.int(), MaxMem: r.MaxMem.int64(), MaxDisk: r.MaxDisk.int64(),
				CPU: float64(r.CPU), Mem: r.Mem.int64(), Disk: r.Disk.int64(), Uptime: r.Uptime.int64(),
			})
		case "storage":
			if r.Storage == "" || r.Node == "" {
				return Inventory{}, fmt.Errorf("proxmox: cluster resource %d: storage without id or node", i)
			}
			inv.Storages = append(inv.Storages, Storage{
				ID: r.Storage, Node: r.Node, Plugin: r.Plugin, Content: splitList(r.Content),
				Total: r.MaxDisk.int64(), Used: r.Disk.int64(), Shared: r.Shared.flag(),
			})
		}
	}
	return inv, nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// decodePerms reads path -> privilege -> propagate flag. Only a privilege
// that propagates counts as granted, because Perms.Has lets every grant
// descend to child paths; reading a non-propagating one as granted would
// over-report. Under-reporting is the safe direction.
func decodePerms(data []byte) (Perms, error) {
	var raw map[string]map[string]number
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("proxmox: decode permissions: %w", err)
	}
	perms := make(Perms, len(raw))
	for path, privs := range raw {
		perms[path] = make(map[string]bool, len(privs))
		for priv, propagate := range privs {
			if propagate.flag() {
				perms[path][priv] = true
			}
		}
	}
	return perms, nil
}

type taskWire struct {
	UPID       string `json:"upid"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
}

// decodeTaskStatus reads GET /nodes/{node}/tasks/{upid}/status.
func decodeTaskStatus(u UPID, data []byte) (TaskStatus, error) {
	var w taskWire
	if err := json.Unmarshal(data, &w); err != nil {
		return TaskStatus{}, fmt.Errorf("proxmox: decode task status: %w", err)
	}
	switch {
	case w.Status == "running":
		return TaskStatus{UPID: u, Status: "running"}, nil
	case w.Status == "stopped" && w.ExitStatus != "":
		return TaskStatus{UPID: u, Status: "stopped", ExitStatus: w.ExitStatus}, nil
	}
	return TaskStatus{}, fmt.Errorf("proxmox: task %s reports status %q, exitstatus %q", u.Raw, w.Status, w.ExitStatus)
}

// decodeTaskList reads one page of GET /nodes/{node}/tasks. In a list the
// status field is the exit status of a finished task and absent while it runs.
// Entries whose UPID does not parse cannot be guest power tasks and are skipped.
func decodeTaskList(data []byte) ([]TaskStatus, int, error) {
	var rows []taskWire
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, 0, fmt.Errorf("proxmox: decode task list: %w", err)
	}
	var out []TaskStatus
	for _, r := range rows {
		u, err := ParseUPID(r.UPID)
		if err != nil {
			continue
		}
		t := TaskStatus{UPID: u, Status: "running"}
		if r.Status != "" {
			t.Status, t.ExitStatus = "stopped", r.Status
		}
		out = append(out, t)
	}
	return out, len(rows), nil
}
