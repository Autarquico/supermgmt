package systemd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
)

// ErrSettling means systemd still has a job queued for the unit: there is no
// completion proof yet, and the reconciler asks again later.
var ErrSettling = errors.New("systemd still has a job for the unit")

// ProofNoJobs is the completion proof of systemd actions (spec §20.4).
const ProofNoJobs = "systemd_no_jobs"

// unitState is both the pre-state recorded in the intent and the observed
// fingerprint: a pair of samples counts only when these are identical.
type unitState struct {
	InvocationID string `json:"invocation_id"`
	ActiveState  string `json:"active_state"`
	SubState     string `json:"sub_state"`
}

func (u unitState) marshal() (json.RawMessage, error) {
	b, err := json.Marshal(u)
	if err != nil {
		return nil, fmt.Errorf("encode unit state: %w", err)
	}
	return b, nil
}

func (u unitState) active() bool   { return u.ActiveState == "active" }
func (u unitState) inactive() bool { return u.ActiveState == "inactive" }

func readUnitState(ctx context.Context, ex transport.Executor, unit string) (unitState, error) {
	out, err := succeeded(ctx, ex, "systemd.show", map[string]string{"unit": unit})
	if err != nil {
		return unitState{}, err
	}
	props := parseProps(out)
	return unitState{
		InvocationID: sanitize(props.first("InvocationID")),
		ActiveState:  sanitize(props.first("ActiveState")),
		SubState:     sanitize(props.first("SubState")),
	}, nil
}

// observation is the adapter-side form of jobs.Evidence v2 (ADR-0015): the
// completion proof and the outcome are judged separately.
type observation struct {
	Proof          string
	Classification jobs.Classification
	Fingerprint    json.RawMessage
	Pre            json.RawMessage
}

func observe(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef, v domain.ServiceVerb, pre json.RawMessage) (observation, error) {
	var before unitState
	if err := json.Unmarshal(pre, &before); err != nil {
		return observation{}, fmt.Errorf("decode pre-state: %w", err)
	}
	if err := requireNoJobs(ctx, ex, s.NativeID); err != nil {
		return observation{}, err
	}
	after, err := readUnitState(ctx, ex, s.NativeID)
	if err != nil {
		return observation{}, err
	}
	fingerprint, err := after.marshal()
	if err != nil {
		return observation{}, err
	}
	return observation{Proof: ProofNoJobs, Classification: classify(v, before, after), Fingerprint: fingerprint, Pre: pre}, nil
}

// requireNoJobs fails with ErrSettling while systemd lists a job for the unit.
func requireNoJobs(ctx context.Context, ex transport.Executor, unit string) error {
	out, err := succeeded(ctx, ex, "systemd.list_jobs", nil)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[1] == unit {
			return ErrSettling
		}
	}
	return nil
}

// classify judges the outcome once completion is proven (ADR-0015 table).
func classify(v domain.ServiceVerb, before, after unitState) jobs.Classification {
	switch v {
	case domain.VerbRestart, domain.VerbStart:
		switch {
		case after.InvocationID == before.InvocationID:
			return jobs.ClassNotStarted
		case after.active():
			return jobs.ClassComplete
		}
	case domain.VerbStop:
		switch {
		case after.inactive():
			return jobs.ClassComplete
		case after.active():
			return jobs.ClassNotStarted
		}
	}
	return jobs.ClassUnknown
}

// evidence converts the observation to the job engine's Evidence v2. The
// fingerprint is never empty: an empty one would pair in jobs.confirm.
func (o observation) evidence() jobs.Evidence {
	return jobs.Evidence{
		Done: true, ExitStatus: 0, Proof: o.Proof, Classification: o.Classification,
		Fingerprint: o.Fingerprint, Pre: o.Pre,
	}
}
