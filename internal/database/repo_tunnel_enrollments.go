package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Phases only an enrollment walks, after the enable phases it shares with tunnel_operations. A halted
// enrollment uses PhaseFailed or PhaseConflict like an operation does.
const (
	PhaseScanned   TunnelPhase = "scanned"   // the host key was scanned over the tunnel and persisted
	PhaseConfirmed TunnelPhase = "confirmed" // the operator confirmed exactly that key
	PhaseRemoving  TunnelPhase = "removing"  // cleanup started; route_closed, access_removed, tunnel_deleted follow
	PhaseMismatch  TunnelPhase = "mismatch"  // the host key was refused; goes on to removing
	PhaseExpired   TunnelPhase = "expired"   // cleanup done after the expiry
	PhaseCancelled TunnelPhase = "cancelled" // cleanup done after a cancel or a refusal
)

// EnrollmentFinished reports whether the phase ends an enrollment and releases its name.
func EnrollmentFinished(p TunnelPhase) bool {
	return p == PhaseCommitted || p == PhaseExpired || p == PhaseCancelled
}

// EnrollmentIdentity is the SSH identity snapshot taken when the enrollment starts. Every proof and the
// commit use it, even after the instance's identity is rotated.
type EnrollmentIdentity struct {
	PublicKey     string
	Fingerprint   string
	CredentialRef string // versioned secret reference of the private key
}

// TunnelEnrollment is the record of a tunnel node that does not exist yet. ID is the node ID allocated
// for it.
type TunnelEnrollment struct {
	ID               domain.ID
	Name             string
	EnvironmentID    domain.ID // empty for none
	Tags             []string
	Phase            TunnelPhase
	HaltedPhase      TunnelPhase // the phase held when Phase is failed or conflict
	PhaseStartedAt   time.Time
	AccountID        string
	Zone             string
	InstanceID       string
	Hostname         string
	Objects          TunnelObjects
	ExpiresAt        time.Time
	Identity         EnrollmentIdentity
	ScannedHostKey   string
	ConfirmedHostKey string
	TokenRef         string // secret-store reference of the connector token, never the token
	TerminalReason   string
	LastError        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

const tunnelEnrollmentColumns = `id, name, environment_id, tags_json, phase, halted_phase, phase_started_at,
	account_id, zone, instance_id, hostname, tunnel_id, dns_record_id, access_app_id, expires_at,
	identity_public_key, identity_fingerprint, identity_credential_ref, scanned_host_key, confirmed_host_key,
	token_ref, terminal_reason, last_error, created_at, updated_at`

func scanTunnelEnrollment(s scanner) (TunnelEnrollment, error) {
	var (
		e                                          TunnelEnrollment
		env, halted                                sql.NullString
		tags                                       string
		startedMs, expiresMs, createdMs, updatedMs int64
	)
	err := s.Scan(&e.ID, &e.Name, &env, &tags, &e.Phase, &halted, &startedMs,
		&e.AccountID, &e.Zone, &e.InstanceID, &e.Hostname,
		&e.Objects.TunnelID, &e.Objects.DNSRecordID, &e.Objects.AccessAppID, &expiresMs,
		&e.Identity.PublicKey, &e.Identity.Fingerprint, &e.Identity.CredentialRef,
		&e.ScannedHostKey, &e.ConfirmedHostKey, &e.TokenRef, &e.TerminalReason, &e.LastError, &createdMs, &updatedMs)
	if err != nil {
		return TunnelEnrollment{}, err
	}
	if err := json.Unmarshal([]byte(tags), &e.Tags); err != nil {
		return TunnelEnrollment{}, fmt.Errorf("decode enrollment tags: %w", err)
	}
	e.EnvironmentID = domain.ID(env.String)
	e.HaltedPhase = TunnelPhase(halted.String)
	e.PhaseStartedAt = domain.FromUnixMillis(startedMs)
	e.ExpiresAt = domain.FromUnixMillis(expiresMs)
	e.CreatedAt = domain.FromUnixMillis(createdMs)
	e.UpdatedAt = domain.FromUnixMillis(updatedMs)
	return e, nil
}

// CreateTunnelEnrollment records the start of an enrollment. The phase is always started; ID, Name,
// EnvironmentID, Tags, AccountID, Zone, InstanceID, Hostname, ExpiresAt, Identity, TokenRef and CreatedAt of
// e are used. A name that already has an open enrollment yields CONFLICT.
func CreateTunnelEnrollment(ctx context.Context, q Querier, e TunnelEnrollment) (TunnelEnrollment, error) {
	tags, err := json.Marshal(append([]string{}, e.Tags...))
	if err != nil {
		return TunnelEnrollment{}, fmt.Errorf("encode enrollment tags: %w", err)
	}
	_, err = q.ExecContext(ctx, `
		INSERT INTO tunnel_enrollments (id, name, environment_id, tags_json, phase, phase_started_at,
			account_id, zone, instance_id, hostname, expires_at, identity_public_key, identity_fingerprint,
			identity_credential_ref, token_ref, created_at, updated_at)
		VALUES (?, ?, NULLIF(?, ''), ?, 'started', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Name, e.EnvironmentID, string(tags), millis(e.CreatedAt),
		e.AccountID, e.Zone, e.InstanceID, e.Hostname, millis(e.ExpiresAt),
		e.Identity.PublicKey, e.Identity.Fingerprint, e.Identity.CredentialRef, e.TokenRef,
		millis(e.CreatedAt), millis(e.CreatedAt))
	if err != nil {
		return TunnelEnrollment{}, conflictIfDuplicate(err, "open tunnel enrollment for name")
	}
	return GetTunnelEnrollment(ctx, q, e.ID)
}

// GetTunnelEnrollment returns the enrollment, or NOT_FOUND.
func GetTunnelEnrollment(ctx context.Context, q Querier, id domain.ID) (TunnelEnrollment, error) {
	e, err := scanTunnelEnrollment(q.QueryRowContext(ctx,
		`SELECT `+tunnelEnrollmentColumns+` FROM tunnel_enrollments WHERE id = ?`, id))
	if err != nil {
		return TunnelEnrollment{}, getErr(err, "tunnel enrollment")
	}
	return e, nil
}

// OpenTunnelEnrollmentByName returns the name's unfinished enrollment (halted ones included), or NOT_FOUND.
func OpenTunnelEnrollmentByName(ctx context.Context, q Querier, name string) (TunnelEnrollment, error) {
	e, err := scanTunnelEnrollment(q.QueryRowContext(ctx,
		`SELECT `+tunnelEnrollmentColumns+` FROM tunnel_enrollments
		 WHERE name = ? AND phase NOT IN ('committed', 'expired', 'cancelled')`, name))
	if err != nil {
		return TunnelEnrollment{}, getErr(err, "tunnel enrollment")
	}
	return e, nil
}

// ListOpenTunnelEnrollments returns every unfinished enrollment, oldest first.
func ListOpenTunnelEnrollments(ctx context.Context, q Querier) ([]TunnelEnrollment, error) {
	return list(ctx, q, "tunnel enrollments",
		`SELECT `+tunnelEnrollmentColumns+` FROM tunnel_enrollments
		 WHERE phase NOT IN ('committed', 'expired', 'cancelled') ORDER BY created_at, id`,
		scanTunnelEnrollment)
}

// AdvanceTunnelEnrollment moves the enrollment to next, recording any non-empty object IDs in the same
// statement, but only while the stored phase still equals expected. A halted enrollment resumes through
// here with expected set to failed or conflict. Otherwise CONFLICT (or NOT_FOUND) and nothing changes.
func AdvanceTunnelEnrollment(ctx context.Context, q Querier, id domain.ID,
	expected, next TunnelPhase, objects TunnelObjects, now time.Time,
) (TunnelEnrollment, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET phase = ?, halted_phase = NULL, phase_started_at = ?, updated_at = ?,
			last_error = '',
			tunnel_id = COALESCE(NULLIF(?, ''), tunnel_id),
			dns_record_id = COALESCE(NULLIF(?, ''), dns_record_id),
			access_app_id = COALESCE(NULLIF(?, ''), access_app_id)
		WHERE id = ? AND phase = ?`,
		next, millis(now), millis(now), objects.TunnelID, objects.DNSRecordID, objects.AccessAppID, id, expected)
	return finishEnrollmentUpdate(ctx, q, res, err, "advance", id, expected)
}

// ResumeHaltedTunnelEnrollment moves a halted enrollment back to the phase it held, keeping
// phase_started_at so the objects an earlier attempt created stay adoptable.
func ResumeHaltedTunnelEnrollment(ctx context.Context, q Querier, id domain.ID, halted TunnelPhase, now time.Time) (TunnelEnrollment, error) {
	if !halted.Halted() {
		return TunnelEnrollment{}, smerr.New(smerr.CodeInvalidArgument, "", "only a failed or conflict enrollment can be resumed")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET phase = halted_phase, halted_phase = NULL, last_error = '', updated_at = ?
		WHERE id = ? AND phase = ? AND halted_phase IS NOT NULL`, millis(now), id, halted)
	return finishEnrollmentUpdate(ctx, q, res, err, "resume", id, halted)
}

// HaltTunnelEnrollment marks the enrollment failed or conflict, keeping its phase as HaltedPhase, under
// the same expectation as AdvanceTunnelEnrollment. lastError must already be sanitized.
func HaltTunnelEnrollment(ctx context.Context, q Querier, id domain.ID,
	expected, halt TunnelPhase, lastError string, now time.Time,
) (TunnelEnrollment, error) {
	if !halt.Halted() || expected.Halted() || EnrollmentFinished(expected) {
		return TunnelEnrollment{}, smerr.New(smerr.CodeInvalidArgument, "", "halt phase must be failed or conflict, from a running phase")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET phase = ?, halted_phase = phase, last_error = ?, updated_at = ?
		WHERE id = ? AND phase = ?`, halt, lastError, millis(now), id, expected)
	return finishEnrollmentUpdate(ctx, q, res, err, "halt", id, expected)
}

// RecordScannedHostKey persists the key scanned over the tunnel and moves the enrollment to scanned. It
// holds while the enrollment waits (dns_created) or has an unconfirmed key (scanned): a later scan replaces
// the key, and a confirmation of the old one then fails its compare-and-swap.
func RecordScannedHostKey(ctx context.Context, q Querier, id domain.ID, hostKey string, now time.Time) (TunnelEnrollment, error) {
	if hostKey == "" {
		return TunnelEnrollment{}, smerr.New(smerr.CodeInvalidArgument, "", "a scanned host key is required")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET phase = 'scanned', scanned_host_key = ?, phase_started_at = ?, updated_at = ?
		WHERE id = ? AND phase IN ('dns_created', 'scanned')`, hostKey, millis(now), millis(now), id)
	return finishEnrollmentUpdate(ctx, q, res, err, "scan", id, PhaseDNSCreated)
}

// ConfirmTunnelEnrollment is the compare-and-swap of the operator's confirmation: it holds only while the
// enrollment is scanned and its scanned key is exactly hostKey. A cancel, an expiry or a different scan
// that got there first yields CONFLICT.
func ConfirmTunnelEnrollment(ctx context.Context, q Querier, id domain.ID, hostKey string, now time.Time) (TunnelEnrollment, error) {
	if hostKey == "" {
		return TunnelEnrollment{}, smerr.New(smerr.CodeInvalidArgument, "", "a host key to confirm is required")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET phase = 'confirmed', confirmed_host_key = scanned_host_key,
			phase_started_at = ?, updated_at = ?
		WHERE id = ? AND phase = 'scanned' AND scanned_host_key = ?`, millis(now), millis(now), id, hostKey)
	return finishEnrollmentUpdate(ctx, q, res, err, "confirm", id, PhaseScanned)
}

// SetTunnelEnrollmentTokenRef records where the connector token is stored. It is written once, while the
// enrollment is open.
func SetTunnelEnrollmentTokenRef(ctx context.Context, q Querier, id domain.ID, ref string, now time.Time) error {
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET token_ref = ?, updated_at = ?
		WHERE id = ? AND token_ref = '' AND phase NOT IN ('committed', 'expired', 'cancelled')`, ref, millis(now), id)
	_, err = finishEnrollmentUpdate(ctx, q, res, err, "set token of", id, PhaseStarted)
	return err
}

// StartTunnelEnrollmentRemoval moves the enrollment from expected to removing and records why. The
// objects are then taken down step by step with AdvanceTunnelEnrollment.
func StartTunnelEnrollmentRemoval(ctx context.Context, q Querier, id domain.ID, expected TunnelPhase, reason string, now time.Time) (TunnelEnrollment, error) {
	if EnrollmentFinished(expected) {
		return TunnelEnrollment{}, smerr.New(smerr.CodeInvalidArgument, "", "a finished enrollment has nothing to remove")
	}
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET phase = 'removing', halted_phase = NULL, terminal_reason = ?,
			phase_started_at = ?, updated_at = ?, last_error = ''
		WHERE id = ? AND phase = ?`, reason, millis(now), millis(now), id, expected)
	return finishEnrollmentUpdate(ctx, q, res, err, "remove", id, expected)
}

// EndTunnelEnrollment finishes the enrollment as committed, expired or cancelled, releasing its name.
func EndTunnelEnrollment(ctx context.Context, q Querier, id domain.ID, expected, end TunnelPhase, now time.Time) (TunnelEnrollment, error) {
	if !EnrollmentFinished(end) {
		return TunnelEnrollment{}, smerr.New(smerr.CodeInvalidArgument, "", "an enrollment ends as committed, expired or cancelled")
	}
	return AdvanceTunnelEnrollment(ctx, q, id, expected, end, TunnelObjects{}, now)
}

func finishEnrollmentUpdate(ctx context.Context, q Querier, res sql.Result, err error, verb string, id domain.ID, expected TunnelPhase) (TunnelEnrollment, error) {
	if err != nil {
		return TunnelEnrollment{}, fmt.Errorf("%s tunnel enrollment: %w", verb, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return TunnelEnrollment{}, fmt.Errorf("tunnel enrollment: %w", err)
	}
	current, getErr := GetTunnelEnrollment(ctx, q, id)
	if n > 0 {
		return current, getErr
	}
	if getErr != nil {
		return TunnelEnrollment{}, getErr
	}
	e := smerr.New(smerr.CodeConflict, "", "tunnel enrollment changed concurrently")
	e.Details = map[string]any{"expected_phase": string(expected), "current_phase": string(current.Phase)}
	return TunnelEnrollment{}, e
}

// GetLatestTunnelEnrollmentByName returns the newest enrollment of the name, finished ones included, or
// NOT_FOUND. A client that waits for a commit reads it after the name stopped being held.
func GetLatestTunnelEnrollmentByName(ctx context.Context, q Querier, name string) (TunnelEnrollment, error) {
	e, err := scanTunnelEnrollment(q.QueryRowContext(ctx,
		`SELECT `+tunnelEnrollmentColumns+` FROM tunnel_enrollments WHERE name = ? ORDER BY created_at DESC, id DESC LIMIT 1`, name))
	if err != nil {
		return TunnelEnrollment{}, getErr(err, "tunnel enrollment")
	}
	return e, nil
}

// RequestTunnelEnrollmentEnd records, without changing the phase, that the enrollment must be taken down
// for reason (a cancel). The job that tears it down starts the removal from the phase it finds, so the
// objects an interrupted step left unrecorded are still reconciled first. A confirmation or a commit that
// reads the reason refuses. It holds once: an enrollment that already has a reason, or is finished, yields
// CONFLICT.
func RequestTunnelEnrollmentEnd(ctx context.Context, q Querier, id domain.ID, reason string, now time.Time) (TunnelEnrollment, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET terminal_reason = ?, updated_at = ?
		WHERE id = ? AND terminal_reason = '' AND phase NOT IN ('committed', 'expired', 'cancelled')`, reason, millis(now), id)
	return finishEnrollmentUpdate(ctx, q, res, err, "cancel", id, PhaseStarted)
}

// NoteTunnelEnrollment records a sanitized note (what the node is still waited for) in last_error while the
// enrollment stays in expected. It changes nothing else.
func NoteTunnelEnrollment(ctx context.Context, q Querier, id domain.ID, expected TunnelPhase, note string, now time.Time) error {
	_, err := q.ExecContext(ctx, `
		UPDATE tunnel_enrollments SET last_error = ?, updated_at = ? WHERE id = ? AND phase = ?`, note, millis(now), id, expected)
	if err != nil {
		return fmt.Errorf("note tunnel enrollment: %w", err)
	}
	return nil
}
