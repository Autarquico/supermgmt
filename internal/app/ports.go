package app

import (
	"context"
	"net/netip"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// The M2 services the API serves. Frozen in W0 so the transport (T7) and the
// services (T2, T4, T5, T6, T12) are built in parallel; each is implemented
// by one task. Credential-issuing methods never take an Idempotency-Key
// (ADR-0012): their callers leave Caller.Idempotency nil.

// Auth is login, bootstrap and API tokens (ADR-0017, ADR-0018).
type Auth interface {
	OIDCStart(ctx context.Context, r wire.OIDCStartRequest) (wire.OIDCStart, error)
	OIDCExchange(ctx context.Context, r wire.OIDCExchangeRequest) (wire.LoginSession, error)
	DeviceStart(ctx context.Context) (wire.DeviceStart, error)
	DevicePoll(ctx context.Context, r wire.DevicePollRequest) (wire.DevicePoll, error)
	// Bootstrap exchanges a one-time code (spec §11.5). session is the caller
	// of a completed OIDC login when OIDC is configured, nil otherwise.
	Bootstrap(ctx context.Context, session *Caller, r wire.BootstrapRequest) (wire.Bootstrapped, error)
	Logout(ctx context.Context, by Caller) error
	ListTokens(ctx context.Context, by Caller) ([]wire.Token, error)
	CreateToken(ctx context.Context, by Caller, r wire.CreateTokenRequest) (wire.TokenIssued, error)
	RevokeToken(ctx context.Context, by Caller, id domain.ID) error
}

// AdminSocket is what the server-mode admin socket serves besides doctor and
// restore-complete (spec §23.1). peerUID is the verified peer: root or the
// service user.
type AdminSocket interface {
	IssueBootstrapCode(ctx context.Context, peerUID int) (wire.BootstrapCodeIssued, error)
	Grant(ctx context.Context, peerUID int, r wire.GrantRequest) error
}

// Keys is master-key and secret management (spec §10, ADR-0021), action
// secret.write. The action is high risk, so each operation answers Pending (a
// control_plane.apply job awaiting approval) unless policy says otherwise.
// ExportKey is served on the local-mode socket only and takes two calls: one
// without a passphrase requests it, one with the passphrase executes it.
type Keys interface {
	RotateMasterKey(ctx context.Context, by Caller) (DirectResult[wire.MasterKeyRotated], error)
	RetireKey(ctx context.Context, by Caller, r wire.RetireKeyRequest) (DirectResult[struct{}], error)
	ExportKey(ctx context.Context, by Caller, r wire.ExportKeyRequest) (DirectResult[wire.ExportedKey], error)
	ImportSecret(ctx context.Context, by Caller, r wire.ImportSecretRequest) (DirectResult[wire.SecretVersion], error)
	RotateSSHIdentity(ctx context.Context, by Caller) (DirectResult[wire.SSHKey], error)
	// ListKeys describes the master keys: metadata, never key material.
	ListKeys(ctx context.Context, by Caller) ([]wire.MasterKey, error)
}

// Backups is backup.create (a job) and backup.read (spec §29.1, ADR-0020).
type Backups interface {
	Create(ctx context.Context, by Caller) (Submission, error)
	List(ctx context.Context, by Caller) ([]wire.Backup, error)
}

// Hold is the restore hold (spec §29.2 phase C, ADR-0020). Load runs at start
// before any worker; an error refuses the start. Guard is called by every
// shared write path and returns CONFLICT/RESTORE_HOLD unless the action is on
// the ADR-0020 exception list.
type Hold interface {
	Load(ctx context.Context) (bool, error)
	Guard(ctx context.Context, action string, by Caller) error
	Complete(ctx context.Context, peerUID int) error
}

// Enrollments is the join workflow (spec §13, ADR-0022).
type Enrollments interface {
	Create(ctx context.Context, by Caller, r wire.EnrollmentRequest) (wire.EnrollmentIssued, error)
	// Enroll consumes a join token. A retry with the same token and the same
	// request digest returns the first result; a different digest is CONFLICT.
	Enroll(ctx context.Context, source netip.Addr, r wire.EnrollRequest) (wire.Enrolled, error)
}
