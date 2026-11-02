package wire

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- app moves between nodes (ADR-0041) --------------------------------------------------

// AppMoveVolume is one volume of a move's volume map. State is pending, importing, imported or verified;
// CreatedByMove says that the move created the volume on the destination, which is the only kind it may remove.
type AppMoveVolume struct {
	Name          string `json:"name"`
	Service       string `json:"service"`
	Mount         string `json:"mount"`
	State         string `json:"state"`
	Attempt       int    `json:"attempt"`
	CreatedByMove bool   `json:"created_by_move"`
}

// AppMoveRoute is one route frozen into a move (ADR-0042). FrozenPhase is the route's phase when the move began,
// active or waiting; State is where the route stands in the switch: pending, dest_included, dest_published,
// dns_switching, dns_switched, committed, source_cleaned, dns_restoring, dns_restored, dest_excluded or dest_withdrawn.
type AppMoveRoute struct {
	RouteID     domain.ID `json:"route_id"`
	Hostname    string    `json:"hostname"`
	Access      string    `json:"access"`
	FrozenPhase string    `json:"frozen_phase"`
	State       string    `json:"state"`
}

// AppMove is the record of one move of an app target from its source node to a destination node. Phase is
// preflight, staged, source_stopped, data_copied, started, verified, routes_dest_included, routes_switched, committed,
// routes_source_cleaned, source_parked, done, the compensating_* phases, rolled_back, or failed or conflict when halted; a halted move names the phase it holds in
// HaltedPhase and LastError says why it is not moving. Stateful moves stop the app while the data is copied.
type AppMove struct {
	ID           domain.ID       `json:"id"`
	AppTargetID  domain.ID       `json:"app_target_id"`
	SourceNodeID domain.ID       `json:"source_node_id"`
	DestNodeID   domain.ID       `json:"dest_node_id"`
	Phase        string          `json:"phase"`
	HaltedPhase  string          `json:"halted_phase,omitempty"`
	Stateful     bool            `json:"stateful"`
	Volumes      []AppMoveVolume `json:"volumes"`
	Routes       []AppMoveRoute  `json:"routes"`
	LastError    string          `json:"last_error,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// MoveAppRequest is POST /app-targets/{id}/moves (app_target.move).
type MoveAppRequest struct {
	ToNode domain.ID `json:"to_node"`
}

// AppMoveSubmission answers a move request: the move's record and the job that does the work, which waits for
// approval when policy asks. Resumed says that the request continued an open move whose job had ended.
type AppMoveSubmission struct {
	Move       AppMove    `json:"move"`
	Resumed    bool       `json:"resumed"`
	Submission Submission `json:"submission"`
}
