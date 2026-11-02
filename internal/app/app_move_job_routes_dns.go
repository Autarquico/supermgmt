package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
)

// The record updates of a routed move (ADR-0042, spec §7.2, §7.3, §8). Every PATCH, forward or back, is a ledger
// intent before it is a call. An answer that is lost leaves the intent open and the outcome unknown: nothing opposite
// is sent, withdrawn or stopped until the intent's not-before time has passed, and then the record is read.

const (
	operationDNSUpdate = "cloudflare.dns_update"

	// dnsQuiescence is how long after dispatch a record update may still apply: the intent's not-before time.
	dnsQuiescence = 2 * time.Minute
	// maxDNSAttempts bounds the attempts of one leg of one route in a run.
	maxDNSAttempts = 3

	// proofDNSNotBefore names the proof of a record update, which has no marker: its not-before time has passed.
	proofDNSNotBefore = "dns_not_before"
)

type dnsDirection string

const (
	dnsForward dnsDirection = "forward"
	dnsReverse dnsDirection = "reverse"
)

// dnsLeg describes one direction of the repoint as a small state machine on the row: idle -> pending -> done, with
// pending settled by reading the record.
type dnsLeg struct {
	dir     dnsDirection
	idle    database.AppMoveRouteState
	pending database.AppMoveRouteState
	done    database.AppMoveRouteState
	event   string
	// access is checked before each dispatch of the leg.
	access bool
}

var (
	forwardLeg = dnsLeg{
		dir: dnsForward, idle: database.AppMoveRouteDestPublished, pending: database.AppMoveRouteDNSSwitching,
		done: database.AppMoveRouteDNSSwitched, event: eventAppMoveRouteSwitched, access: true,
	}
	reverseLeg = dnsLeg{
		dir: dnsReverse, idle: database.AppMoveRouteDNSSwitched, pending: database.AppMoveRouteDNSRestoring,
		done: database.AppMoveRouteDNSRestored, event: eventAppMoveRouteRestored,
	}
)

// content is the CNAME target the leg moves the record to; the other end is where it comes from.
func (l dnsLeg) content(row database.AppMoveRoute) string {
	if l.dir == dnsForward {
		return cloudflare.TunnelTarget(row.ToTunnelID)
	}
	return cloudflare.TunnelTarget(row.FromTunnelID)
}

// ---- the validator -----------------------------------------------------------------------------------------------

// recordFault is a record that is not what the move may touch: a sibling, a foreign marker, another type or target.
// The move never repairs it.
type recordFault struct{ inner *smerr.Error }

func (e *recordFault) Error() string { return e.inner.Error() }
func (e *recordFault) Unwrap() error { return e.inner }

func recordFaultf(format string, args ...any) error {
	return &recordFault{inner: smerr.New(smerr.CodeConflict, "", fmt.Sprintf(format, args...))}
}

// validateRecord is the one move-aware validator, used by the forward switch, by reconciliation and by restore. The
// hostname has exactly one record, with the frozen ID, the route's marker, type CNAME, proxied, and content at A's
// or B's frozen tunnel. Ownership is never inferred from the content alone. It returns the record read by ID.
func (r *moveRun) validateRecord(ctx context.Context, m moveRoute) (cloudflare.DNSRecord, error) {
	cf, err := r.cloudflare(ctx)
	if err != nil {
		return cloudflare.DNSRecord{}, err
	}
	host := m.route.Hostname
	records, err := cf.api.FindDNSRecords(ctx, cf.zoneID, host)
	if err != nil {
		return cloudflare.DNSRecord{}, err
	}
	if len(records) != 1 || records[0].ID != m.row.DNSRecordID {
		return cloudflare.DNSRecord{}, recordFaultf("the hostname %s has %d DNS records and the move froze record %s; it was left alone",
			host, len(records), m.row.DNSRecordID)
	}
	rec, err := cf.api.GetDNSRecord(ctx, cf.zoneID, m.row.DNSRecordID)
	if err != nil {
		return cloudflare.DNSRecord{}, err
	}
	switch {
	case rec.Comment != cloudflare.RouteDNSComment(cf.instanceID, m.route.ID.String()):
		return cloudflare.DNSRecord{}, recordFaultf("the DNS record of %s does not carry this route's marker; it was left alone", host)
	case rec.Type != "CNAME" || !rec.Proxied:
		return cloudflare.DNSRecord{}, recordFaultf("the DNS record of %s is not a proxied CNAME; it was left alone", host)
	case rec.Content != cloudflare.TunnelTarget(m.row.FromTunnelID) && rec.Content != cloudflare.TunnelTarget(m.row.ToTunnelID):
		return cloudflare.DNSRecord{}, recordFaultf("the DNS record of %s points at %s, neither the source nor the destination tunnel; it was left alone",
			host, rec.Content)
	}
	return rec, nil
}

// ---- intents -------------------------------------------------------------------------------------------------------

// dnsPreState is what an update intent records before dispatch.
type dnsPreState struct {
	Move      string       `json:"move"`
	Route     string       `json:"route"`
	Hostname  string       `json:"hostname"`
	Direction dnsDirection `json:"direction"`
	Seq       int          `json:"seq"`
	Intended  string       `json:"intended"`
}

// dnsIntent is a recorded update of a route's record.
type dnsIntent struct {
	ID         domain.ID
	JobID      domain.ID
	Settled    bool
	Outcome    string
	Dispatched bool
	NotBefore  time.Time
	dnsPreState
}

// lastDNSIntent is the newest update intent of the route's record, whichever job recorded it.
func (r *moveRun) lastDNSIntent(ctx context.Context, m moveRoute) (dnsIntent, bool, error) {
	rows, err := r.h.cfg.DB.Reader().QueryContext(ctx, `
		SELECT id, job_id, state, outcome, dispatched_at, deadline_at, pre_state_json FROM operation_intents
		WHERE operation = ? AND json_extract(pre_state_json, '$.move') = ? AND json_extract(pre_state_json, '$.route') = ?
		ORDER BY CAST(json_extract(pre_state_json, '$.seq') AS INTEGER) DESC LIMIT 1`,
		operationDNSUpdate, r.move.ID, m.row.RouteID)
	if err != nil {
		return dnsIntent{}, false, fmt.Errorf("read the record updates of route %s: %w", m.route.Hostname, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return dnsIntent{}, false, rows.Err()
	}
	var (
		in          dnsIntent
		pre, state  string
		outcome     *string
		dispatched  *int64
		notBeforeMs int64
	)
	if err := rows.Scan(&in.ID, &in.JobID, &state, &outcome, &dispatched, &notBeforeMs, &pre); err != nil {
		return dnsIntent{}, false, fmt.Errorf("read the record updates of route %s: %w", m.route.Hostname, err)
	}
	if err := json.Unmarshal([]byte(pre), &in.dnsPreState); err != nil {
		return dnsIntent{}, false, fmt.Errorf("a record update of route %s is unreadable: %w", m.route.Hostname, err)
	}
	in.Settled, in.Dispatched = state == string(jobs.IntentCompleted), dispatched != nil
	if outcome != nil {
		in.Outcome = *outcome
	}
	in.NotBefore = domain.FromUnixMillis(notBeforeMs)
	return in, true, nil
}

// errDNSUnknown says that an update was dispatched and its answer is lost: the intent stays open.
var errDNSUnknown = errors.New("the record update was dispatched and its outcome is unknown")

// dnsRefused is an update Cloudflare refused: nothing was applied.
type dnsRefused struct{ cause error }

func (e *dnsRefused) Error() string { return e.cause.Error() }
func (e *dnsRefused) Unwrap() error { return e.cause }

// updateRecord records the intent of a leg, dispatches the PATCH and closes the intent when the answer says what
// happened. It returns nil when the update applied, errDNSUnknown when its answer is lost, a *dnsRefused when it
// was refused, and any other error when nothing could be dispatched or the run is ending.
func (r *moveRun) updateRecord(ctx context.Context, l dnsLeg, m moveRoute) error {
	cf, err := r.cloudflare(ctx)
	if err != nil {
		return err
	}
	last, found, err := r.lastDNSIntent(ctx, m)
	if err != nil {
		return err
	}
	pre := dnsPreState{
		Move: r.move.ID.String(), Route: m.row.RouteID.String(), Hostname: m.route.Hostname, Direction: l.dir, Seq: 1, Intended: l.content(m.row),
	}
	if found {
		pre.Seq = last.Seq + 1
	}
	raw, err := json.Marshal(pre)
	if err != nil {
		return fmt.Errorf("encode the record update: %w", err)
	}
	ledger := deployLedger{h: *r.h.dep, lease: r.lease}
	intent, err := ledger.RecordIntent(ctx, jobs.NewIntent{
		Step: fmt.Sprintf("dns-%s-%s-%d", l.dir, m.row.RouteID, pre.Seq), Operation: operationDNSUpdate,
		TargetType: "dns_record", TargetID: m.row.DNSRecordID, PreState: raw, DeadlineAt: r.h.cfg.Clock.Now().Add(dnsQuiescence),
	})
	if err != nil {
		return err
	}
	if err := ledger.MarkDispatched(ctx, intent); err != nil {
		return err
	}
	_, err = cf.api.UpdateDNSRecord(ctx, cf.zoneID, m.row.DNSRecordID, pre.Intended)
	switch {
	case err == nil:
		return ledger.CompleteIntent(ctx, intent, jobs.OutcomeSucceeded, dnsEvidence(jobs.OutcomeSucceeded))
	case ctx.Err() != nil:
		return ctx.Err()
	case cloudflare.IsAmbiguous(err):
		return errDNSUnknown
	}
	if cerr := ledger.CompleteIntent(ctx, intent, jobs.OutcomeFailed, dnsEvidence(jobs.OutcomeFailed)); cerr != nil {
		return cerr
	}
	return &dnsRefused{cause: fmt.Errorf("repointing the record of %s: %w", m.route.Hostname, err)}
}

func dnsEvidence(outcome string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"outcome": outcome})
	return raw
}

// awaitNotBefore leaves an update of unknown outcome alone until its not-before time: until then it may still apply.
// A job that cannot wait that long ends with an unknown outcome.
func (r *moveRun) awaitNotBefore(ctx context.Context, m moveRoute, in dnsIntent) error {
	clock := r.h.cfg.Clock
	if wait := in.NotBefore.Sub(clock.Now()); wait > 0 {
		r.h.dep.sleep(ctx, wait)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if clock.Now().Before(in.NotBefore) {
		return fmt.Errorf("%w: the update of the record of %s may still apply until %s",
			jobs.ErrOutcomeUnknown, m.route.Hostname, in.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// settleUpdate decides, for a row whose leg is pending, whether its update applied. An intent that was never
// dispatched did not. One that completed says so. An open one is reconciled only after its not-before time, by
// reading the record through the validator: content at the leg's target means applied, at the other end not applied,
// and anything else is a recordFault. A read that fails leaves the outcome unknown.
func (r *moveRun) settleUpdate(ctx context.Context, l dnsLeg, m moveRoute) (bool, error) {
	in, found, err := r.lastDNSIntent(ctx, m)
	if err != nil {
		return false, err
	}
	sent := found && in.Direction == l.dir && in.Dispatched
	if sent && in.Settled {
		return in.Outcome == jobs.OutcomeSucceeded, nil
	}
	if sent {
		if err := r.awaitNotBefore(ctx, m, in); err != nil {
			return false, err
		}
	}
	rec, err := r.validateRecord(ctx, m)
	var fault *recordFault
	switch {
	case errors.As(err, &fault):
		return false, err
	case err != nil && ctx.Err() == nil:
		return false, fmt.Errorf("%w: the record of %s could not be read: %w", jobs.ErrOutcomeUnknown, m.route.Hostname, err)
	case err != nil:
		return false, err
	}
	applied := rec.Content == l.content(m.row)
	if sent && in.JobID == r.lease.JobID {
		outcome := jobs.OutcomeFailed
		if applied {
			outcome = jobs.OutcomeSucceeded
		}
		ledger := deployLedger{h: *r.h.dep, lease: r.lease}
		if err := ledger.CompleteIntent(ctx, in.ID, outcome, dnsEvidence(outcome)); err != nil {
			return false, err
		}
	}
	return applied, nil
}

// settlePending resolves a row whose leg is pending: applied rows are done, the others return to idle.
func (r *moveRun) settlePending(ctx context.Context, l dnsLeg, m moveRoute) (moveRoute, error) {
	applied, err := r.settleUpdate(ctx, l, m)
	if err != nil {
		return m, err
	}
	if applied {
		return r.advanceRoute(ctx, m, l.done, l.event)
	}
	return r.advanceRoute(ctx, m, l.idle, "")
}

// driveLeg takes the row of m through the leg to its done state: it dispatches the update from idle, settles it when
// it is pending, and tries again when it did not apply, up to maxDNSAttempts. all are the active routes of the move.
func (r *moveRun) driveLeg(ctx context.Context, l dnsLeg, m moveRoute, all []moveRoute) (moveRoute, error) {
	for attempts := 0; ; {
		var err error
		state := m.row.State
		if state == l.done {
			return m, nil
		}
		if state != l.pending && state != l.idle {
			return m, smerr.New(smerr.CodeInternal, "", fmt.Sprintf("the route %s is %s: the %s repoint has no work for it", m.route.Hostname, state, l.dir))
		}
		if state == l.pending {
			m, err = r.settlePending(ctx, l, m)
		} else {
			if attempts++; attempts > maxDNSAttempts {
				return m, fmt.Errorf("the record of %s did not take the update after %d attempts", m.route.Hostname, maxDNSAttempts)
			}
			m, err = r.dispatchLeg(ctx, l, m, all)
		}
		if err != nil {
			return m, err
		}
	}
}

// dispatchLeg runs one attempt of a leg. It leaves the row done, pending (the answer is lost) or idle (refused).
func (r *moveRun) dispatchLeg(ctx context.Context, l dnsLeg, m moveRoute, all []moveRoute) (moveRoute, error) {
	if l.access {
		if err := r.accessFirst(ctx, m, all); err != nil {
			return m, err
		}
	}
	rec, err := r.validateRecord(ctx, m)
	if err != nil {
		return m, err
	}
	if rec.Content == l.content(m.row) {
		if l.dir == dnsForward {
			return m, recordFaultf("the DNS record of %s already points at the destination although no update was recorded; it was left alone", m.route.Hostname)
		}
		return r.advanceRoute(ctx, m, l.done, l.event) // someone repointed it already
	}
	if m, err = r.advanceRoute(ctx, m, l.pending, ""); err != nil {
		return m, err
	}
	err = r.updateRecord(ctx, l, m)
	var refused *dnsRefused
	switch {
	case err == nil:
		return r.advanceRoute(ctx, m, l.done, l.event)
	case errors.Is(err, errDNSUnknown):
		return m, nil
	case errors.As(err, &refused):
		back, berr := r.advanceRoute(ctx, m, l.idle, "")
		return back, errors.Join(err, berr)
	}
	return m, err
}
