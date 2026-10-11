package wire

// ---- admin socket (spec §23.1, ADR-0012) ------------------------------------
//
// Responses of the four admin-socket routes that the shared DTOs do not
// already cover (BootstrapCodeIssued and GrantRequest are in auth.go).

// RestoreCompleted is the answer to the admin-socket restore-complete route.
type RestoreCompleted struct {
	RestoreHold bool `json:"restore_hold"`
}

// DoctorCheck is one read-only check of the admin-socket doctor route.
type DoctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail,omitempty"`
}

// AdminDoctor is the answer to the admin-socket doctor route: what the daemon
// can tell about itself without touching a node.
type AdminDoctor struct {
	Mode        string        `json:"mode"`
	RestoreHold bool          `json:"restore_hold"`
	AdminBound  bool          `json:"admin_bound"`
	Checks      []DoctorCheck `json:"checks"`
}
