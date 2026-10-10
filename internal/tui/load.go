package tui

import (
	"context"
	"errors"
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// loadKey names one kind of data the screens show. Each key has its own
// generation counter, so a reply to a superseded request is dropped.
type loadKey string

const (
	keyMe        loadKey = "me"
	keyNodes     loadKey = "nodes"
	keyNode      loadKey = "node"
	keyServices  loadKey = "services"
	keyService   loadKey = "service"
	keyLogs      loadKey = "logs"
	keyJobs      loadKey = "jobs"
	keyJob       loadKey = "job"
	keyApprovals loadKey = "approvals"
	keyEvents    loadKey = "events"
)

type loadState struct {
	gen     uint64
	loading bool
	loaded  bool
	err     error
}

// loadedMsg is the reply of one load. It is applied only if its generation is
// still the latest issued for the key.
type loadedMsg struct {
	key   loadKey
	gen   uint64
	err   error
	apply func(*Model)
}

// timeoutError means the daemon did not answer within the per-call timeout.
type timeoutError struct{ after time.Duration }

func (e timeoutError) Error() string { return fmt.Sprintf("no answer within %s", e.after) }

// within runs call on its own goroutine and returns when it answers or when
// timeout passes, whichever is first, so a call that ignores its context can
// never hold the caller (the goroutine ends when the call does).
func within[T any](parent context.Context, timeout time.Duration, call func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	type outcome struct {
		value T
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		value, err := call(ctx)
		done <- outcome{value, err}
	}()
	var zero T
	select {
	case o := <-done:
		if o.err != nil && errors.Is(o.err, context.DeadlineExceeded) && parent.Err() == nil {
			return zero, timeoutError{timeout}
		}
		return o.value, o.err
	case <-ctx.Done():
		if parent.Err() != nil {
			return zero, parent.Err()
		}
		return zero, timeoutError{timeout}
	}
}

func (m *Model) state(key loadKey) *loadState {
	st := m.loads[key]
	if st == nil {
		st = &loadState{}
		m.loads[key] = st
	}
	return st
}

// load issues one API read as a command. Nothing here blocks Update or View.
func load[T any](m *Model, key loadKey, call func(context.Context) (T, error), apply func(*Model, T)) tea.Cmd {
	st := m.state(key)
	st.gen++
	st.loading = true
	gen, timeout, parent := st.gen, m.opts.Timeout, m.ctx
	return func() tea.Msg {
		value, err := within(parent, timeout, call)
		return loadedMsg{key: key, gen: gen, err: err, apply: func(m *Model) { apply(m, value) }}
	}
}

func (m *Model) onLoaded(msg loadedMsg) {
	st := m.state(msg.key)
	if msg.gen != st.gen {
		return
	}
	st.loading = false
	if msg.err != nil {
		st.err = msg.err
		return
	}
	st.err, st.loaded = nil, true
	msg.apply(m)
}

// loader pairs a key with the command that reloads it.
type loader struct {
	key loadKey
	run func() tea.Cmd
}

// reload runs the loaders; unless force is set it skips keys whose previous
// request is still in flight, so periodic refresh never piles up on a slow node.
func (m *Model) reload(force bool, loaders ...loader) tea.Cmd {
	var cmds []tea.Cmd
	for _, l := range loaders {
		if force || !m.state(l.key).loading {
			cmds = append(cmds, l.run())
		}
	}
	return tea.Batch(cmds...)
}

// detailCorrelationID is the smerr.Error.Details key under which the client
// puts a failed request's correlation ID (internal/client cannot be imported
// here: it imports this package).
const detailCorrelationID = "correlation_id"

func correlationID(err error) string {
	var typed *smerr.Error
	if !errors.As(err, &typed) {
		return ""
	}
	id, _ := typed.Details[detailCorrelationID].(string)
	return textsafe.Line(id)
}

// describe is the short actionable text for an error, with its correlation ID.
func describe(err error) string {
	var text string
	var typed *smerr.Error
	switch {
	case errors.As(err, &typed) && typed.Message != "":
		text = string(typed.Code) + ": " + typed.Message
	case errors.As(err, &typed):
		text = string(typed.Code)
	default:
		text = err.Error()
	}
	text = textsafe.Line(text)
	if id := correlationID(err); id != "" {
		text += " (correlation id " + id + ")"
	}
	return text
}
