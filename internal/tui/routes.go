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

	publicRouteWarning = "a public route is reachable from the internet with no authentication; the service on the port owns its own auth"
	unavailableRoutes  = "this daemon does not serve node routes"
)

// commandRoute is `expose <node> <hostname> <port> [public|owners]` and `unexpose <node> <hostname>`. Both open a
// confirmation: nothing runs until the user presses y.
func (m *Model) commandRoute(cmd string, args []string) tea.Cmd {
	usage := "usage: expose <node> <hostname> <port> [public|owners]"
	if cmd == routeUnexpose {
		usage = "usage: unexpose <node> <hostname>"
	}
	api, ok := m.api.(NodeRoutesAPI)
	if !ok {
		m.notice = notice{text: unavailableRoutes, isErr: true}
		return nil
	}
	var req wire.ExposeNodeRouteRequest
	switch {
	case cmd == routeUnexpose && len(args) == 2:
		req.Hostname = args[1]
	case cmd == routeExpose && (len(args) == 3 || len(args) == 4):
		port, err := strconv.Atoi(args[2])
		if err != nil {
			m.notice = notice{text: usage + ": the port is a number", isErr: true}
			return nil
		}
		req = wire.ExposeNodeRouteRequest{Hostname: args[1], Port: port, Access: routeAccessPublic}
		if len(args) == 4 {
			if args[3] != routeAccessPublic && args[3] != routeAccessOwners {
				m.notice = notice{text: usage, isErr: true}
				return nil
			}
			req.Access = args[3]
		}
	default:
		m.notice = notice{text: usage, isErr: true}
		return nil
	}
	node, err := m.resolveNode(args[0])
	if err != nil {
		m.notice = notice{text: safe(err.Error()), isErr: true}
		return nil
	}
	where := textsafe.Line(node.Name)
	if cmd == routeUnexpose {
		m.confirm = &confirmation{
			title: "Unexpose " + textsafe.Line(req.Hostname) + " of " + where,
			lines: []string{"Removes the DNS record, then the ingress rule, then the Access app."},
			run: func(ctx context.Context) (string, error) {
				res, err := api.UnexposeNodeRoute(ctx, node.ID, req.Hostname)
				return submissionNotice(res.Submission), err
			},
		}
		return nil
	}
	c := &confirmation{
		title: "Expose " + textsafe.Line(req.Hostname) + " of " + where,
		lines: []string{
			fmt.Sprintf("Port: %d", req.Port),
			"Access: " + req.Access,
		},
		run: func(ctx context.Context) (string, error) {
			res, err := api.ExposeNodeRoute(ctx, node.ID, req)
			return submissionNotice(res.Submission), err
		},
	}
	if req.Access == routeAccessPublic {
		c.warnings = []string{publicRouteWarning}
	}
	m.confirm = c
	return nil
}
