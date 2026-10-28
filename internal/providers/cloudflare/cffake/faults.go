package cffake

import "slices"

// Fault is what the fake does to a request instead of serving it normally.
type Fault int

const (
	// NoFault serves the request normally.
	NoFault Fault = iota
	// FailBefore answers 500 and applies nothing.
	FailBefore
	// LostResponse applies the mutation, then drops the connection without
	// answering: the caller cannot tell whether it happened. On a request that
	// changes nothing (a read, a refused mutation) it serves normally.
	LostResponse
	// Forbidden answers 403, as a token without the permission would.
	Forbidden
	// RateLimited answers 429 with Retry-After.
	RateLimited
)

// Mutation identifies one mutating request attempt. Seq counts every mutating
// request the fake received, from 1, whatever its outcome.
type Mutation struct {
	Seq    int
	Op     Op
	Method string
	Path   string
}

// Applied is a Mutation with what the fake did with it.
type Applied struct {
	Mutation
	Fault     Fault
	Status    int
	Committed bool
}

type faultQueue struct {
	fault Fault
	left  int // negative: every call
}

// Inject makes the next times requests of op suffer fault; a negative times
// means every request from now on.
func (f *Fake) Inject(op Op, fault Fault, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults[op] = &faultQueue{fault: fault, left: times}
}

// Plan decides the fault of every mutating request. It replaces nothing
// Inject set: a plan answering NoFault leaves the queue in charge. Pass nil to
// remove it. A matrix test runs a scenario once per Seq with
//
//	fake.Plan(func(m cffake.Mutation) cffake.Fault { if m.Seq == k { return cffake.LostResponse }; return cffake.NoFault })
func (f *Fake) Plan(plan func(Mutation) Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plan = plan
}

// ClearFaults removes every injected fault and the plan.
func (f *Fake) ClearFaults() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = map[Op]*faultQueue{}
	f.plan = nil
}

// Mutations is the log of mutating requests, in order.
func (f *Fake) Mutations() []Applied {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.mutations)
}

// CommittedMutations counts the mutations that changed state.
func (f *Fake) CommittedMutations() int {
	n := 0
	for _, m := range f.Mutations() {
		if m.Committed {
			n++
		}
	}
	return n
}

func (f *Fake) faultFor(m Mutation, mutation bool) Fault {
	if mutation && f.plan != nil {
		if fault := f.plan(m); fault != NoFault {
			return fault
		}
	}
	q := f.faults[m.Op]
	if q == nil || q.left == 0 {
		return NoFault
	}
	if q.left > 0 {
		q.left--
	}
	return q.fault
}
