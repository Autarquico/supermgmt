package tui

import (
	"context"
	"fmt"
	"strconv"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	routeExpose   = "expose"
	routeUnexpose = "unexpose"

	routeAccessPublic = "public"
	routeAccessOwners = "owners"

	publicRouteWarning = "a public route is reachable from the internet with no authentication; the app owns its own auth"
	unavailableRoutes  = "this daemon does not serve app routes"
)

// routeStartMsg carries the apps a route command needs to find its target.
type routeStartMsg struct {
	kind        string
	appRef, env string
	expose      wire.ExposeAppRouteRequest // unexpose uses only Hostname
	apps        []wire.App
	err         error
}

// commandRoute is `expose <app> <env> <hostname> <service> <port> [public|owners]` and
// `unexpose <app> <env> <hostname>`. Both open a confirmation: nothing runs until the user presses y.
func (m *Model) commandRoute(cmd string, args []string) tea.Cmd {
	usage := "usage: expose <app> <env> <hostname> <service> <port> [public|owners]"
	if cmd == routeUnexpose {
		usage = "usage: unexpose <app> <env> <hostname>"
	}
	apps, appsOK := m.api.(AppsAPI)
	if _, routesOK := m.api.(AppRoutesAPI); !appsOK || !routesOK {
		m.notice = notice{text: unavailableRoutes, isErr: true}
		return nil
	}
	msg := routeStartMsg{kind: cmd, appRef: argAt(args, 0), env: argAt(args, 1)}
	switch {
	case cmd == routeUnexpose && len(args) == 3:
		msg.expose.Hostname = args[2]
	case cmd == routeExpose && (len(args) == 5 || len(args) == 6):
		port, err := strconv.Atoi(args[4])
		if err != nil {
			m.notice = notice{text: usage + ": the port is a number", isErr: true}
			return nil
		}
		msg.expose = wire.ExposeAppRouteRequest{Hostname: args[2], Service: args[3], Port: port, Access: routeAccessPublic}
		if len(args) == 6 {
			if args[5] != routeAccessPublic && args[5] != routeAccessOwners {
				m.notice = notice{text: usage, isErr: true}
				return nil
			}
			msg.expose.Access = args[5]
		}
	default:
		m.notice = notice{text: usage, isErr: true}
		return nil
	}
	timeout, parent := m.opts.Timeout, m.ctx
	return func() tea.Msg {
		page, err := within(parent, timeout, func(ctx context.Context) (wire.Page[wire.App], error) {
			return apps.ListApps(ctx, wire.PageQuery{Limit: wire.MaxLimit})
		})
		msg.apps, msg.err = page.Items, err
		return msg
	}
}

func argAt(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func (m *Model) onRouteStart(msg routeStartMsg) tea.Cmd {
	if msg.err != nil {
		m.failure("cannot start "+msg.kind, msg.err)
		return nil
	}
	app, target, err := resolveTarget(msg.apps, msg.appRef, msg.env)
	if err != nil {
		m.notice = notice{text: err.Error(), isErr: true}
		return nil
	}
	api, ok := m.api.(AppRoutesAPI)
	if !ok {
		m.notice = notice{text: unavailableRoutes, isErr: true}
		return nil
	}
	where := textsafe.Line(app.Name + "/" + target.Environment)
	req := msg.expose
	if msg.kind == routeUnexpose {
		m.confirm = &confirmation{
			title: "Unexpose " + textsafe.Line(req.Hostname) + " of " + where,
			lines: []string{"Removes the DNS record, then the ingress rule, then the Access app."},
			run: func(ctx context.Context) (string, error) {
				res, err := api.UnexposeAppRoute(ctx, target.ID, req.Hostname)
				return submissionNotice(res.Submission), err
			},
		}
		return nil
	}
	c := &confirmation{
		title: "Expose " + textsafe.Line(req.Hostname) + " of " + where,
		lines: []string{
			fmt.Sprintf("Service: %s port %d", textsafe.Line(req.Service), req.Port),
			"Access: " + req.Access,
		},
		run: func(ctx context.Context) (string, error) {
			res, err := api.ExposeAppRoute(ctx, target.ID, req)
			return submissionNotice(res.Submission), err
		},
	}
	if req.Access == routeAccessPublic {
		c.warnings = []string{publicRouteWarning}
	}
	m.confirm = c
	return nil
}
