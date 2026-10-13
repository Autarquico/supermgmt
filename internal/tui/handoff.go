package tui

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	lazydockerInstall   = "https://github.com/jesseduffield/lazydocker#installation"
	exitCommandNotFound = 127
	exitSignaled        = 255
)

// errHandoffAbandoned ends a session whose command was never started.
var errHandoffAbandoned = errors.New("the terminal handoff was abandoned before it started")

type handoffOpenedMsg struct {
	node wire.Node
	tool wire.Tool
	h    Handoff
	err  error
}

type handoffReturnedMsg struct {
	node wire.Node
	tool wire.Tool
	h    Handoff
	err  error
}

type handoffEndedMsg struct{}

func hasCapability(n wire.Node, name string) bool {
	for _, c := range n.Capabilities {
		if c.Name == name && c.Available {
			return true
		}
	}
	return false
}

// startHandoff issues an interactive session for the node and tool. The TUI
// ignores input from here until the session has ended, so quitting can never
// strand an issued session or its temporary known_hosts.
func (m *Model) startHandoff(n wire.Node, tool wire.Tool) tea.Cmd {
	if !knownTool(tool) {
		m.notice = notice{text: fmt.Sprintf("unknown tool %q: use shell, lazydocker, btop or tmux", tool), isErr: true}
		return nil
	}
	if !hasCapability(n, "node.ssh") {
		m.notice = notice{text: n.Name + " cannot be reached over SSH (no node.ssh capability)", isErr: true}
		return nil
	}
	if tool == wire.ToolLazydocker && !hasCapability(n, "docker.read") {
		m.notice = notice{text: "Docker is not available on " + n.Name, isErr: true}
		return nil
	}
	if tool == wire.ToolLazydocker && !hasCapability(n, "tool.lazydocker") {
		m.notice = notice{text: "lazydocker is not installed on " + n.Name + "; SuperMgmt never installs it, see " + lazydockerInstall}
		return nil
	}
	m.handingOff = true
	m.say("opening %s on %s…", tool, textsafe.Line(n.Name))
	api, timeout, parent := m.api, m.opts.Timeout, m.ctx
	return func() tea.Msg {
		h, err := openSession(parent, timeout, api, n, tool)
		return handoffOpenedMsg{node: n, tool: tool, h: h, err: err}
	}
}

func knownTool(t wire.Tool) bool {
	for _, known := range wire.AllTools() {
		if t == known {
			return true
		}
	}
	return false
}

// openSession bounds OpenSession by the timeout. A session that is issued
// after the timeout is closed as soon as it arrives, so it never leaks.
func openSession(parent context.Context, timeout time.Duration, api API, n wire.Node, tool wire.Tool) (Handoff, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	type opened struct {
		h   Handoff
		err error
	}
	done := make(chan opened, 1)
	go func() {
		h, err := api.OpenSession(ctx, n.ID, string(tool))
		done <- opened{h, err}
	}()
	select {
	case o := <-done:
		return o.h, o.err
	case <-ctx.Done():
		go func() {
			if o := <-done; o.err == nil && o.h.Done != nil {
				o.h.Done(0, errHandoffAbandoned)
			}
		}()
		return Handoff{}, timeoutError{timeout}
	}
}

func (m *Model) onHandoffOpened(msg handoffOpenedMsg) tea.Cmd {
	if msg.err != nil {
		m.handingOff = false
		m.failure("cannot open a session", msg.err)
		return nil
	}
	h := msg.h
	returned := func(err error) tea.Msg {
		return handoffReturnedMsg{node: msg.node, tool: msg.tool, h: h, err: err}
	}
	if h.Cmd.Err != nil {
		// A command that cannot start (program not on PATH) must not go through
		// tea.ExecProcess: bubbletea releases and restores the terminal back to
		// back, and its stale renderer goroutine then stops the restarted
		// ticker, so nothing is ever painted again.
		return func() tea.Msg { return returned(h.Cmd.Err) }
	}
	return tea.ExecProcess(h.Cmd, returned)
}

// exitOutcome maps the ExecProcess error to Handoff.Done's arguments.
func exitOutcome(err error) (code int, launchErr error) {
	var exited *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exited):
		if code := exited.ExitCode(); code >= 0 {
			return code, nil
		}
		return exitSignaled, nil
	}
	return 0, err
}

// onHandoffReturned reports the outcome and ends the session off the Update
// goroutine: Done posts to the daemon.
func (m *Model) onHandoffReturned(msg handoffReturnedMsg) tea.Cmd {
	code, launchErr := exitOutcome(msg.err)
	name := textsafe.Line(msg.node.Name)
	switch {
	case launchErr != nil:
		m.notice = notice{text: fmt.Sprintf("could not start %s on %s: %s", msg.tool, name, textsafe.Line(launchErr.Error())), isErr: true}
	case code == exitCommandNotFound && msg.tool == wire.ToolLazydocker:
		m.notice = notice{text: "lazydocker is not installed on " + name + "; SuperMgmt never installs it, see " + lazydockerInstall, isErr: true}
	case code != 0:
		m.notice = notice{text: fmt.Sprintf("%s on %s exited with code %d", msg.tool, name, code), isErr: true}
	default:
		m.say("back from %s on %s", msg.tool, name)
	}
	done := msg.h.Done
	return func() tea.Msg {
		done(code, launchErr)
		return handoffEndedMsg{}
	}
}

// onHandoffEnded refreshes what the screen shows: the session may have
// changed the node.
func (m *Model) onHandoffEnded(handoffEndedMsg) tea.Cmd {
	m.handingOff = false
	return m.reload(true, m.screenLoaders()...)
}
