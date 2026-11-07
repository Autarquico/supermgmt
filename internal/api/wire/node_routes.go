package wire

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- node routes through the node's Cloudflare Tunnel (ADR-0043) ------------------------

// QueryIncludeRemoved asks the route lists to include removed routes, which carry the note that says why.
const QueryIncludeRemoved = "include_removed"

// NodeRoute is a port of a node published at Hostname through the node's tunnel. Phase is admitted, provisioning,
// ingress_ready, access_ready, active; removing, dns_removed, ingress_removed, removed; failed or conflict when
// halted. LastError says why a halted or removed route is not moving.
type NodeRoute struct {
	ID        domain.ID `json:"id"`
	NodeID    domain.ID `json:"node_id"`
	Hostname  string    `json:"hostname"`
	Port      int       `json:"port"`
	Access    string    `json:"access"` // public | owners
	Phase     string    `json:"phase"`
	LastError string    `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ExposeNodeRouteRequest is POST /nodes/{id}/routes (node_route.expose). An omitted Access is public.
type ExposeNodeRouteRequest struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	Access   string `json:"access,omitempty"`
}

// NodeRouteSubmission answers an expose or unexpose: the job that does the work and why it is queued or awaiting
// approval. Route is null while an expose awaits approval, because nothing is written before it.
type NodeRouteSubmission struct {
	Route      *NodeRoute `json:"route"`
	Submission Submission `json:"submission"`
}
