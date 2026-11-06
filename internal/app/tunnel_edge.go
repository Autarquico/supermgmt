package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// A hostname that SuperMgmt has just created is not dialled before Cloudflare's own resolver serves it: a
// caching resolver that is asked too early keeps its NXDOMAIN for the zone's negative TTL. The gate is
// derived from the persisted phase of the operation (an enrollment in dns_created, a setup before its
// tunnel verification), so a restart or a takeover applies it again.

const (
	// enrollmentPublicationBudget is how long one enrollment job waits for the hostname before it yields.
	enrollmentPublicationBudget = 20 * time.Second
	// setupStepBudget bounds the verification over the tunnel: the wait for the hostname and the retries.
	setupStepBudget = 3 * time.Minute
	// publicationPoll is the pause between two questions to Cloudflare's resolver.
	publicationPoll = 2 * time.Second
	// resolverFallbackWait is how long after the record's creation the first system lookup waits when
	// Cloudflare's resolver cannot be asked.
	resolverFallbackWait = time.Minute
	// persistedInstantResolution is how far a persisted instant (domain.UnixMillis) can lie before the
	// instant it stands for.
	persistedInstantResolution = time.Millisecond

	// fallbackCauseLength bounds the resolver failure quoted in a note or an error, so the explanation
	// before it is never cut by maxRecordedErrorLength.
	fallbackCauseLength = 150

	tunnelRetryBase  = 2 * time.Second
	tunnelRetryLimit = 15 * time.Second
)

// EdgePublication is Cloudflare's own resolver as the tunnel jobs use it. *cloudflare.PublicationChecker
// implements it.
type EdgePublication interface {
	// Published says whether host is served; an error that is cloudflare.ErrResolverUnavailable means the
	// resolver could not be asked.
	Published(ctx context.Context, host string) (bool, error)
	// DiagnoseNegativeCache names a likely cached negative answer when lookupErr is NXDOMAIN for a published
	// host, and returns lookupErr otherwise.
	DiagnoseNegativeCache(ctx context.Context, host string, lookupErr error) error
}

var _ EdgePublication = (*cloudflare.PublicationChecker)(nil)

// waitBudget is an amount of waiting that is spent by pausing, so a step has one deadline for all its waits.
type waitBudget struct {
	e    *tunnelEngine
	left time.Duration
	// fallback is why the resolver could not be asked, once the wait fell back to a fixed time.
	fallback error
}

func (b *waitBudget) spent() bool { return b.left <= 0 }

func (b *waitBudget) pause(ctx context.Context, d time.Duration) error {
	d = min(d, b.left)
	b.left -= d
	return b.e.opts.sleep(ctx, d)
}

// awaitPublication waits, within budget, until Cloudflare serves host. It returns an empty note when the
// first lookup may go ahead, else what the operation is waiting for. createdAt is when the DNS record was
// created; it is only asked when the resolver cannot be reached.
func (e *tunnelEngine) awaitPublication(ctx context.Context, host string, createdAt func(context.Context) time.Time, budget *waitBudget) (string, error) {
	if e.opts.Edge == nil {
		return "", nil
	}
	for {
		published, err := e.opts.Edge.Published(ctx, host)
		switch {
		case ctx.Err() != nil:
			return "", ctx.Err()
		case err != nil:
			return e.waitOutFallback(ctx, createdAt(ctx), err, budget)
		case published:
			return "", nil
		case budget.spent():
			return "waiting for Cloudflare to publish " + host, nil
		}
		if err := budget.pause(ctx, publicationPoll); err != nil {
			return "", err
		}
	}
}

// waitOutFallback is the wait when Cloudflare's resolver cannot be asked: a fixed time after the record's
// creation. The note says so, so it is not mistaken for an unpublished hostname. createdAt may be a
// persisted instant, which rounds down to the millisecond, so the wait counts from the latest instant it can
// stand for and never ends before resolverFallbackWait after the real creation.
func (e *tunnelEngine) waitOutFallback(ctx context.Context, createdAt time.Time, cause error, budget *waitBudget) (string, error) {
	budget.fallback = cause
	latestCreation := createdAt.Add(persistedInstantResolution)
	remaining := latestCreation.Add(resolverFallbackWait).Sub(e.cfg.Clock.Now())
	if remaining <= 0 {
		return "", nil
	}
	wait := min(remaining, budget.left)
	if err := budget.pause(ctx, wait); err != nil {
		return "", err
	}
	if wait < remaining {
		return fmt.Sprintf("Cloudflare's resolver cannot be asked, so the first lookup waits until %s after the DNS record was created: %s",
			resolverFallbackWait, resolverFailure(cause)), nil
	}
	return "", nil
}

// resolverFailure is the bounded text of why Cloudflare's resolver could not be asked, without the
// ErrResolverUnavailable text that the callers' own wording already says.
func resolverFailure(cause error) string {
	return sanitizedErrorUpTo(errors.New(strings.TrimPrefix(cause.Error(), cloudflare.ErrResolverUnavailable.Error()+": ")), fallbackCauseLength)
}

// withFallbackNote says on err that the verification did not know whether Cloudflare served the hostname.
func withFallbackNote(err error, fallback error) error {
	if err == nil || fallback == nil {
		return err
	}
	var coded *smerr.Error
	code, reason := smerr.CodeOf(err), smerr.Reason("")
	if errors.As(err, &coded) {
		reason = coded.Reason
	}
	return smerr.Wrap(err, code, reason, fmt.Sprintf("Cloudflare's resolver could not be asked (%s); the verification waited %s after the record's creation instead",
		resolverFailure(fallback), resolverFallbackWait))
}

// diagnose names a likely cached negative answer in a failed system lookup of host.
func (e *tunnelEngine) diagnose(ctx context.Context, host string, err error) error {
	if e.opts.Edge == nil {
		return err
	}
	return e.opts.Edge.DiagnoseNegativeCache(ctx, host, err)
}

// verifyWhenServed runs the verification over the tunnel (verify) once Cloudflare serves the hostname, and
// retries it with backoff until the step's deadline while the failure is a dial failure: edge and connector
// latency must not use up the job's attempts. Other failures end it at once.
func (r *tunnelRun) verifyWhenServed(ctx context.Context, verify func(context.Context) error) error {
	if phaseIndex(r.record().Phase()) >= phaseIndex(database.PhaseVerified) {
		return verify(ctx) // the hostname was served when it was verified
	}
	budget := &waitBudget{e: r.tunnelEngine, left: setupStepBudget}
	note, err := r.awaitPublication(ctx, r.hostname, r.dnsCreatedAt, budget)
	switch {
	case err != nil:
		return err
	case note != "":
		return smerr.New(smerr.CodeNodeUnreachable, "", fmt.Sprintf("%s: not published after %s", note, setupStepBudget))
	}
	backoff := tunnelRetryBase
	for {
		err = verify(ctx)
		if err == nil || !retryableDial(err) || ctx.Err() != nil || budget.spent() {
			break
		}
		if pauseErr := budget.pause(ctx, backoff); pauseErr != nil {
			return pauseErr
		}
		backoff = min(backoff*2, tunnelRetryLimit)
	}
	if err != nil {
		err = withFallbackNote(r.diagnose(ctx, r.hostname, err), budget.fallback)
	}
	return err
}

// retryableDial is a failure to reach the node that waiting can cure: not an SSH refusal of the keys, a
// host key mismatch or a failed check of what the node answered.
func retryableDial(err error) bool {
	code := smerr.CodeOf(err)
	if code == smerr.CodeNodeUnreachable {
		return !ssh.IsAuthRejected(err)
	}
	return code == smerr.CodeTimeout
}

// dnsCreatedAt is when Cloudflare created the node's DNS record, which the operation record no longer says
// once it has moved past that phase.
func (r *tunnelRun) dnsCreatedAt(ctx context.Context) time.Time {
	if id := r.known().DNSRecordID; id != "" {
		if record, err := r.api.GetDNSRecord(ctx, r.zoneID, id); err == nil && !record.CreatedOn.IsZero() {
			return record.CreatedOn
		}
	}
	return r.record().PhaseStartedAt()
}
