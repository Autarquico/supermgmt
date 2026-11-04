package tui

import (
	"context"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	commandMove = "move"

	moveUsage        = "usage: move <app> <env> <node>"
	unavailableMoves = "this daemon does not serve app moves"
)

// moveStartMsg carries the apps a move command needs to find its target.
type moveStartMsg struct {
	appRef, env string
	dest        wire.Node
	apps        []wire.App
	err         error
}

// commandMove is `move <app> <env> <node>`. It opens a confirmation: nothing runs until the user presses y.
func (m *Model) commandMove(args []string) tea.Cmd {
	apps, appsOK := m.api.(AppsAPI)
	if _, movesOK := m.api.(AppMovesAPI); !appsOK || !movesOK {
		m.notice = notice{text: unavailableMoves, isErr: true}
		return nil
	}
	if len(args) != 3 {
		m.notice = notice{text: moveUsage, isErr: true}
		return nil
	}
	dest, err := m.resolveNode(args[2])
	if err != nil {
		m.notice = notice{text: err.Error(), isErr: true}
		return nil
	}
	msg := moveStartMsg{appRef: args[0], env: args[1], dest: dest}
	timeout, parent := m.opts.Timeout, m.ctx
	return func() tea.Msg {
		page, err := within(parent, timeout, func(ctx context.Context) (wire.Page[wire.App], error) {
			return apps.ListApps(ctx, wire.PageQuery{Limit: wire.MaxLimit})
		})
		msg.apps, msg.err = page.Items, err
		return msg
	}
}

func (m *Model) onMoveStart(msg moveStartMsg) tea.Cmd {
	if msg.err != nil {
		m.failure("cannot start move", msg.err)
		return nil
	}
	app, target, err := resolveTarget(msg.apps, msg.appRef, msg.env)
	if err != nil {
		m.notice = notice{text: err.Error(), isErr: true}
		return nil
	}
	api, ok := m.api.(AppMovesAPI)
	if !ok {
		m.notice = notice{text: unavailableMoves, isErr: true}
		return nil
	}
	dest := msg.dest
	m.confirm = &confirmation{
		title: "Move " + textsafe.Line(app.Name+"/"+target.Environment) + " to " + textsafe.Line(dest.Name),
		lines: []string{
			"The destination is checked first; the app keeps running until it is healthy there.",
			"Routes of the app are repointed to the new node inside the move.",
		},
		warnings: []string{
			"an app with volumes stops while their data is copied",
			"a routed app that is rolled back serves errors on its hostnames until it is healthy on the old node again",
		},
		run: func(ctx context.Context) (string, error) {
			res, err := api.MoveApp(ctx, target.ID, dest.ID)
			out := submissionNotice(res.Submission)
			if res.Move.Stateful {
				out += "; the app stops while its data is copied"
			}
			if hosts := moveHostnames(res.Move); hosts != "" {
				out += "; repoints " + hosts
			}
			return out, err
		},
	}
	return nil
}

// moveHostnames lists the hostnames the move repoints, as one safe line.
func moveHostnames(m wire.AppMove) string {
	names := make([]string, len(m.Routes))
	for i, r := range m.Routes {
		names[i] = textsafe.Line(r.Hostname)
	}
	return strings.Join(names, ", ")
}
