package wire

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- app routes through the node's Cloudflare Tunnel (ADR-0040) ------------------------

// AppRoute is a published service port of an app target, reachable at Hostname through the node's tunnel.
// Phase is waiting (no healthy deployment publishes the port yet), provisioning, ingress_ready, access_ready,
// active; removing, dns_removed, ingress_removed; failed or conflict when halted. LastError says why a halted
// route is not moving.
type AppRoute struct {
	ID          domain.ID `json:"id"`
	AppTargetID domain.ID `json:"app_target_id"`
	Hostname    string    `json:"hostname"`
	Service     string    `json:"service"`
	Port        int       `json:"port"`
	Access      string    `json:"access"` // public | owners
	Phase       string    `json:"phase"`
	LastError   string    `json:"last_error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// ExposeAppRouteRequest is POST /app-targets/{id}/routes (app_route.expose). An omitted Access is public.
type ExposeAppRouteRequest struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
	Port     int    `json:"port"`
	Access   string `json:"access,omitempty"`
}

// AppRouteSubmission answers an expose or unexpose: the job that does the work and why it is queued or awaiting
// approval. Route is null while an expose awaits approval, because nothing is written before it.
type AppRouteSubmission struct {
	Route      *AppRoute  `json:"route"`
	Submission Submission `json:"submission"`
}
