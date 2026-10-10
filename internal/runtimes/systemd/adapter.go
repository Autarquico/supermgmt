// Package systemd is the systemd runtime adapter (spec §16): unit discovery,
// bounded logs, the unit trust profile, sudoers-granted unit actions with
// their completion evidence, and the node.setup rendering of the dedicated
// user, sudoers drop-in and log broker (ADR-0009, ADR-0015).
package systemd

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Adapter implements runtimes.Adapter for systemd units. It holds no state.
type Adapter struct{}

var _ runtimes.Adapter = Adapter{}

// New returns the systemd adapter.
func New() Adapter { return Adapter{} }

func (Adapter) Type() domain.RuntimeType { return domain.RuntimeSystemd }

// Logs reads the last q.Lines journal lines of the unit: through the journal
// group, or through the root-owned broker when the node was set up with it.
func (Adapter) Logs(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef, q runtimes.LogQuery) (runtimes.LogChunk, error) {
	if err := checkUnit(s); err != nil {
		return runtimes.LogChunk{}, err
	}
	if q.Lines < 1 || q.Lines > runtimes.MaxLogLines {
		return runtimes.LogChunk{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("lines must be in 1..%d", runtimes.MaxLogLines))
	}
	template := "systemd.logs_group"
	if q.Mode == runtimes.LogsBroker {
		template = "systemd.logs_broker"
	}
	res, err := read(ctx, ex, template, map[string]string{"unit": s.NativeID, "lines": strconv.Itoa(q.Lines)})
	if err != nil {
		return runtimes.LogChunk{}, err
	}
	if res.ExitStatus != 0 {
		return runtimes.LogChunk{}, smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("logs of %s are unavailable (exit %d)", s.NativeID, res.ExitStatus))
	}
	return runtimes.LogChunk{Lines: splitLines(res.Stdout), Truncated: res.Truncated}, nil
}

// Preflight applies the unit trust profile (spec §16) to the unit.
func (Adapter) Preflight(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef) error {
	if err := checkUnit(s); err != nil {
		return err
	}
	return CheckTrust(ctx, ex, s.NativeID)
}

// PreState captures the unit's InvocationID and state before dispatch.
func (Adapter) PreState(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef) (json.RawMessage, error) {
	if err := checkUnit(s); err != nil {
		return nil, err
	}
	state, err := readUnitState(ctx, ex, s.NativeID)
	if err != nil {
		return nil, err
	}
	return state.marshal()
}

// Mutate renders the marker-wrapped `sudo -n <systemctl> <verb> <unit>`, which
// equals the sudoers line granted by node.setup. The verb must be granted.
func (Adapter) Mutate(s runtimes.ServiceRef, v domain.ServiceVerb, marker string, setup runtimes.SetupMeta) (templates.Command, error) {
	if err := checkUnit(s); err != nil {
		return templates.Command{}, err
	}
	if !v.Valid() {
		return templates.Command{}, smerr.New(smerr.CodeInvalidArgument, "", "unknown service verb")
	}
	if !setup.Granted(s.NativeID, v) {
		return templates.Command{}, smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("node.setup did not grant %s on %s", v, s.NativeID))
	}
	return templates.RenderMutating("systemd."+string(v), marker, map[string]string{"systemctl": setup.SystemctlPath, "unit": s.NativeID})
}

// Observe reports completion evidence for a dispatched verb (ADR-0015 table).
func (Adapter) Observe(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef, v domain.ServiceVerb, _ string,
	pre json.RawMessage, _ time.Time,
) (jobs.Evidence, error) {
	o, err := observe(ctx, ex, s, v, pre)
	if err != nil {
		return jobs.Evidence{}, err
	}
	return o.evidence(), nil
}

// checkUnit refuses refs that are not systemd units the grammar admits.
func checkUnit(s runtimes.ServiceRef) error {
	if s.Kind != domain.ServiceSystemdUnit {
		return smerr.New(smerr.CodeInvalidArgument, "", "not a systemd unit")
	}
	if err := templates.ValidateUnit(s.NativeID); err != nil {
		return smerr.New(smerr.CodeCapabilityUnavailable, smerr.ReasonUnitNotEligible, "unit name is not eligible: "+err.Error())
	}
	return nil
}
