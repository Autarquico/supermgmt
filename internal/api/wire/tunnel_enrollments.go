package wire

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- nodes reached only through Cloudflare Tunnel (ADR-0039) -------------------------

// StartTunnelEnrollmentRequest is POST /nodes/ssh/tunnel-enrollments (node.add with tunnel=true).
// ExpiresIn is a Go duration ("90m"); empty is one hour and the maximum is 24 hours.
type StartTunnelEnrollmentRequest struct {
	Name        string   `json:"name"`
	Environment string   `json:"environment,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	ExpiresIn   string   `json:"expires_in,omitempty"`
}

// TunnelEnrollment is an enrollment before its node exists. It never carries the connector token: that
// is the one response of GET .../{name}/token. HostPublicKey and HostKeyFingerprint are set once the host
// key was scanned over the tunnel; Error says why a halted or ended enrollment is not moving.
type TunnelEnrollment struct {
	ID                 domain.ID `json:"id"`
	NodeID             domain.ID `json:"node_id"`
	Name               string    `json:"name"`
	Environment        string    `json:"environment,omitempty"`
	Tags               []string  `json:"tags"`
	Hostname           string    `json:"hostname"`
	Phase              string    `json:"phase"`
	ExpiresAt          time.Time `json:"expires_at"`
	JoinLine           string    `json:"join_line"`
	HostPublicKey      string    `json:"host_public_key,omitempty"`
	HostKeyFingerprint string    `json:"host_key_fingerprint,omitempty"`
	Error              string    `json:"error,omitempty"`
}

// ConfirmTunnelEnrollmentRequest is POST .../{name}/confirm. EnrollmentID is the enrollment the operator was
// shown: a request for any other enrollment of the name is a CONFLICT. HostPublicKey must be the key that
// enrollment scanned, the one the operator was shown; any other key ends the enrollment with
// SSH_HOST_KEY_MISMATCH.
type ConfirmTunnelEnrollmentRequest struct {
	EnrollmentID  domain.ID `json:"enrollment_id"`
	HostPublicKey string    `json:"host_public_key"`
}

// RefuseTunnelEnrollmentRequest is POST .../{name}/refuse: the enrollment and the key the operator refuses.
type RefuseTunnelEnrollmentRequest struct {
	EnrollmentID  domain.ID `json:"enrollment_id"`
	HostPublicKey string    `json:"host_public_key"`
}

// TunnelEnrollmentToken is the response of GET .../{name}/token and the only place the connector token
// is ever returned.
type TunnelEnrollmentToken struct {
	Token string `json:"token"`
}
