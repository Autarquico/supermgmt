package pvesim

// Storage is a storage of the simulated node, as `pvesm status` reports it.
type Storage struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Content string `json:"content"` // comma-separated: rootdir,vztmpl,images,...
	Active  bool   `json:"active"`
	TotalGB int    `json:"total_gb"`
}

// Topology is the host the Sim pretends to be. The fake API container is started from the same
// document, so both sides agree on the node, its storages and its address.
type Topology struct {
	Node       string    `json:"node"`
	Version    string    `json:"version"`     // pve-manager version
	Bridge     string    `json:"bridge"`      // the one bridge, vmbr0
	APIAddress string    `json:"api_address"` // the host's address on the bridge: the fake API container
	Storages   []Storage `json:"storages"`
	Available  []string  `json:"available"` // templates `pveam available` offers
	Present    []string  `json:"present"`   // template volumes already downloaded: storage:vztmpl/name
}

// DefaultTopology is a single PVE 9.0 node with the stock storages and Debian templates on offer.
func DefaultTopology() Topology {
	return Topology{
		Node: "pve", Version: "9.0.3", Bridge: "vmbr0", APIAddress: "10.77.0.1",
		Storages: []Storage{
			{ID: "local", Type: "dir", Content: "iso,vztmpl,backup", Active: true, TotalGB: 100},
			{ID: "local-lvm", Type: "lvmthin", Content: "images,rootdir", Active: true, TotalGB: 200},
		},
		Available: []string{"debian-12-standard_12.7-1_amd64.tar.zst", "debian-13-standard_13.1-1_amd64.tar.zst"},
	}
}

func (t Topology) storage(id string) (Storage, bool) {
	for _, s := range t.Storages {
		if s.ID == id {
			return s, true
		}
	}
	return Storage{}, false
}
