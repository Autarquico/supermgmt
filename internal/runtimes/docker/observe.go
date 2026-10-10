package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// ErrNoCompletionProof means the marker's .done file is missing or records a
// nonzero exit status. Docker has no other completion signal, so the job is
// held for human resolution (spec §20.4 fixed fallback).
var ErrNoCompletionProof = errors.New("no .done file with exit status 0")

// ProofDoneFile is the completion proof of Docker actions (ADR-0015).
const ProofDoneFile = "done_file"

// observation is the adapter-side form of jobs.Evidence v2 (ADR-0015).
type observation struct {
	Proof          string
	Classification jobs.Classification
	Fingerprint    json.RawMessage
	Pre            json.RawMessage
}

func observe(ctx context.Context, ex transport.Executor, s runtimes.ServiceRef, v domain.ServiceVerb, marker string,
	pre json.RawMessage, dispatchedAt time.Time,
) (observation, error) {
	if !json.Valid(pre) {
		return observation{}, fmt.Errorf("decode pre-state: not JSON")
	}
	if err := requireDoneFile(ctx, ex, marker); err != nil {
		return observation{}, err
	}
	after, err := inspect(ctx, ex, s.NativeID)
	if err != nil {
		return observation{}, err
	}
	fingerprint, err := after.marshal()
	if err != nil {
		return observation{}, err
	}
	return observation{Proof: ProofDoneFile, Classification: classify(v, after, dispatchedAt), Fingerprint: fingerprint, Pre: pre}, nil
}

// requireDoneFile succeeds only when the marker's .done file holds exit 0.
func requireDoneFile(ctx context.Context, ex transport.Executor, marker string) error {
	res, err := read(ctx, ex, "marker.state", map[string]string{"marker": marker})
	if err != nil {
		return err
	}
	state, err := templates.ParseMarkerState(res.Stdout)
	if err != nil || !state.CompletionProof() {
		return ErrNoCompletionProof
	}
	return nil
}

// classify judges the outcome once completion is proven (ADR-0015 table).
func classify(v domain.ServiceVerb, after containerState, dispatchedAt time.Time) jobs.Classification {
	switch v {
	case domain.VerbStart, domain.VerbRestart:
		if after.Running && after.startedAfter(dispatchedAt) {
			return jobs.ClassComplete
		}
	case domain.VerbStop:
		if !after.Running {
			return jobs.ClassComplete
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
