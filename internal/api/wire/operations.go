package wire

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- keys and secrets (spec §10, ADR-0021) ----------------------------------

// MasterKeyRotated is the answer to POST /secrets/master-key/rotate.
type MasterKeyRotated struct {
	ActiveKEKID   domain.ID `json:"active_kek_id"`
	PreviousKEKID domain.ID `json:"previous_kek_id"`
	Rewrapped     int       `json:"rewrapped"`
}

// RetireKeyRequest is POST /secrets/master-key/retire.
type RetireKeyRequest struct {
	KEKID                  domain.ID `json:"kek_id"`
	ExternalBackupsHandled bool      `json:"external_backups_handled"`
}

// ExportKeyRequest is POST /secrets/master-key/export, served on the
// local-mode Unix socket only (ADR-0021). The passphrase is read by the CLI
// from a TTY or stdin and is at least 12 characters.
type ExportKeyRequest struct {
	KEKID      domain.ID `json:"kek_id"`
	Passphrase string    `json:"passphrase"`
}

// ExportedKey is the SMKEY1 file (§10), passphrase-wrapped; base64 in JSON.
type ExportedKey struct {
	KEKID  domain.ID `json:"kek_id"`
	Export []byte    `json:"export"`
}

// ImportSecretRequest is POST /secrets: a new version of the named secret.
type ImportSecretRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SecretVersion names a stored secret version; the value is never returned.
type SecretVersion struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// ---- backups (spec §29.1, ADR-0020) -----------------------------------------

type Backup struct {
	Name          string      `json:"name"`
	SizeBytes     int64       `json:"size_bytes"`
	CreatedAt     time.Time   `json:"created_at"`
	SchemaVersion int         `json:"schema_version"`
	SMVersion     string      `json:"sm_version"`
	KEKIDs        []domain.ID `json:"kek_ids"`
}

// ---- enrollment (spec §13, ADR-0022) ----------------------------------------

// EnrollmentRequest is POST /enrollments. Empty constraints do not restrict.
type EnrollmentRequest struct {
	Tags        []string  `json:"tags"`
	MaxNodes    int       `json:"max_nodes"`
	SourceCIDRs []string  `json:"source_cidrs"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// EnrollmentIssued carries the join token exactly once.
type EnrollmentIssued struct {
	ID        domain.ID `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// EnrollRequest is POST /enroll, sent by `sm join` on the node.
type EnrollRequest struct {
	Token         string   `json:"token"`
	HostPublicKey string   `json:"host_public_key"`
	Hostname      string   `json:"hostname"`
	Addresses     []string `json:"addresses"`
	SSHPort       int      `json:"ssh_port"`
}

// Enrolled tells the node which key to authorize for the supermgmt user: the
// instance SSH identity (ADR-0016) at the version the node is pinned to.
type Enrolled struct {
	NodeID            domain.ID `json:"node_id"`
	InstanceID        domain.ID `json:"instance_id"`
	SSHUser           string    `json:"ssh_user"`
	AuthorizedKey     string    `json:"authorized_key"`
	KeyVersion        int       `json:"key_version"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
}

// ---- event stream (ADR-0017) --------------------------------------------------

// Server-sent events on GET /events/stream: every frame is one Event as JSON
// with "id: <seq>"; a reconnect sends Last-Event-ID to resume after it.
const (
	ContentTypeEventStream = "text/event-stream"
	HeaderLastEventID      = "Last-Event-ID"
)
