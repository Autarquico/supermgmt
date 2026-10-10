package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// fakeAdapter is a runtime adapter whose answers the test scripts.
type fakeAdapter struct {
	typ domain.RuntimeType

	mu           sync.Mutex
	discovered   runtimes.Discovered
	discoverErr  error
	preflightErr error
	pre          json.RawMessage
	mutated      []templates.Command
	observe      func(call int) (jobs.Evidence, error)
	observeCalls int
	logs         runtimes.LogChunk
}

var _ runtimes.Adapter = (*fakeAdapter)(nil)

func newFakeAdapter(typ domain.RuntimeType) *fakeAdapter {
	return &fakeAdapter{typ: typ, pre: json.RawMessage(`{"invocation_id":"before"}`)}
}

func (a *fakeAdapter) Type() domain.RuntimeType { return a.typ }

func (a *fakeAdapter) Discover(context.Context, transport.Executor, runtimes.Filter) (runtimes.Discovered, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.discovered, a.discoverErr
}

func (a *fakeAdapter) Logs(context.Context, transport.Executor, runtimes.ServiceRef, runtimes.LogQuery) (runtimes.LogChunk, error) {
	return a.logs, nil
}

func (a *fakeAdapter) Preflight(context.Context, transport.Executor, runtimes.ServiceRef) error {
	return a.preflightErr
}

func (a *fakeAdapter) PreState(context.Context, transport.Executor, runtimes.ServiceRef) (json.RawMessage, error) {
	return a.pre, nil
}

func (a *fakeAdapter) Mutate(s runtimes.ServiceRef, v domain.ServiceVerb, marker string, setup runtimes.SetupMeta) (templates.Command, error) {
	if !setup.Granted(s.NativeID, v) && !setup.DockerAccess {
		return templates.Command{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "not granted")
	}
	c := templates.Command{
		Template: "fake." + string(v), Line: "fake " + string(v) + " " + marker, Mutating: true,
		Deadline: templates.ActionDeadline, MaxBytes: 1024,
	}
	a.mu.Lock()
	a.mutated = append(a.mutated, c)
	a.mu.Unlock()
	return c, nil
}

func (a *fakeAdapter) Observe(context.Context, transport.Executor, runtimes.ServiceRef, domain.ServiceVerb, string, json.RawMessage, time.Time) (jobs.Evidence, error) {
	a.mu.Lock()
	a.observeCalls++
	call := a.observeCalls
	observe := a.observe
	a.mu.Unlock()
	if observe == nil {
		return jobs.Evidence{}, errors.New("no evidence scripted")
	}
	return observe(call)
}

func (a *fakeAdapter) dispatches() []templates.Command {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]templates.Command(nil), a.mutated...)
}

// complete is evidence of a finished action with the given classification.
func complete(class jobs.Classification) jobs.Evidence {
	return jobs.Evidence{
		Done: true, Proof: jobs.ProofSystemdNoJobs, Classification: class,
		Fingerprint: json.RawMessage(`{"invocation_id":"after","active_state":"active"}`),
	}
}

func fakeAdapters(systemdAdapter, dockerAdapter *fakeAdapter) Adapters {
	return Adapters{domain.RuntimeSystemd: systemdAdapter, domain.RuntimeDocker: dockerAdapter}
}

func unit(name string) runtimes.DiscoveredService {
	return runtimes.DiscoveredService{Kind: domain.ServiceSystemdUnit, NativeID: name, Name: strings.TrimSuffix(name, ".service"), Status: "running"}
}
