package systemd

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// fakeNode answers rendered templates by name, like a node would. Every call is
// recorded; a template with no handler fails the test.
type fakeNode struct {
	t        *testing.T
	handlers map[string]func(templates.Command) transport.Result
	calls    []templates.Command
}

func newFakeNode(t *testing.T) *fakeNode {
	return &fakeNode{t: t, handlers: map[string]func(templates.Command) transport.Result{}}
}

func (f *fakeNode) on(template string, h func(templates.Command) transport.Result) *fakeNode {
	f.handlers[template] = h
	return f
}

func (f *fakeNode) reply(template, stdout string) *fakeNode {
	return f.on(template, func(templates.Command) transport.Result { return transport.Result{Stdout: []byte(stdout)} })
}

func (f *fakeNode) fail(template string, status int) *fakeNode {
	return f.on(template, func(templates.Command) transport.Result { return transport.Result{ExitStatus: status} })
}

func (f *fakeNode) Run(_ context.Context, c templates.Command) (transport.Result, error) {
	f.calls = append(f.calls, c)
	h, ok := f.handlers[c.Template]
	if !ok {
		f.t.Fatalf("unexpected template %s (line %q)", c.Template, c.Line)
	}
	return h(c), nil
}

// ran lists the template names run so far, in order.
func (f *fakeNode) ran() []string {
	names := make([]string, len(f.calls))
	for i, c := range f.calls {
		names[i] = c.Template
	}
	return names
}

func (f *fakeNode) count(template string) int {
	n := 0
	for _, c := range f.calls {
		if c.Template == template {
			n++
		}
	}
	return n
}

func (f *fakeNode) lines() string {
	var b strings.Builder
	for _, c := range f.calls {
		fmt.Fprintln(&b, c.Line)
	}
	return b.String()
}
