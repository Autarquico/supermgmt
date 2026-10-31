package api

import (
	"context"
	"net/http"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
)

const actionNodeAdd = "node.add"

// tunnelEnrollments registers the routes of the nodes reached only through Cloudflare Tunnel (ADR-0039).
// Starting, reading the connector token, confirming, refusing and cancelling are node.add on the
// enrollment; reading is node.read. Without the service the routes answer CAPABILITY_UNAVAILABLE.
func (rs *routeSet) tunnelEnrollments() {
	s := rs.s
	enrollments := func() (*app.TunnelEnrollments, error) {
		if s.svc.TunnelEnrollments == nil {
			return nil, unavailable("tunnel enrollment")
		}
		return s.svc.TunnelEnrollments, nil
	}
	rs.read(wire.PathTunnelEnrollments, "node.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.TunnelEnrollment], error) {
		svc, err := enrollments()
		if err != nil {
			return wire.Page[wire.TunnelEnrollment]{}, err
		}
		views, err := svc.List(ctx, by)
		items := make([]wire.TunnelEnrollment, len(views))
		for i, v := range views {
			items[i] = tunnelEnrollmentView(v)
		}
		return wire.Page[wire.TunnelEnrollment]{Items: items}, err
	}))
	rs.read(wire.PathTunnelEnrollment, "node.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.TunnelEnrollment, error) {
		svc, err := enrollments()
		if err != nil {
			return wire.TunnelEnrollment{}, err
		}
		v, err := svc.Get(ctx, by, in.r.PathValue("name"))
		return tunnelEnrollmentView(v), err
	}))
	rs.routes = append(rs.routes, route{
		method: http.MethodGet, pattern: wire.PathTunnelEnrollmentToken, action: actionNodeAdd, credential: true,
		do: reading(s, func(ctx context.Context, by app.Caller, in input) (wire.TunnelEnrollmentToken, error) {
			svc, err := enrollments()
			if err != nil {
				return wire.TunnelEnrollmentToken{}, err
			}
			token, err := svc.Token(ctx, by, in.r.PathValue("name"))
			if err != nil {
				return wire.TunnelEnrollmentToken{}, err
			}
			return wire.TunnelEnrollmentToken{Token: token.Reveal()}, nil
		}),
	})
	rs.write(http.MethodPost, wire.PathTunnelEnrollments, actionNodeAdd, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DirectResult[app.TunnelEnrollmentView], error) {
			svc, err := enrollments()
			if err != nil {
				return app.DirectResult[app.TunnelEnrollmentView]{}, err
			}
			req, err := decode[wire.StartTunnelEnrollmentRequest](in)
			if err != nil {
				return app.DirectResult[app.TunnelEnrollmentView]{}, err
			}
			expires, err := parseExpiresIn(req.ExpiresIn)
			if err != nil {
				return app.DirectResult[app.TunnelEnrollmentView]{}, err
			}
			return svc.Start(ctx, by, app.StartTunnelEnrollment{Name: req.Name, Environment: req.Environment, Tags: req.Tags, ExpiresIn: expires})
		},
		direct(http.StatusCreated, tunnelEnrollmentView)))
	rs.write(http.MethodPost, wire.PathTunnelEnrollmentConfirm, actionNodeAdd, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.TunnelEnrollmentView, error) {
			svc, err := enrollments()
			if err != nil {
				return app.TunnelEnrollmentView{}, err
			}
			req, err := decode[wire.ConfirmTunnelEnrollmentRequest](in)
			if err != nil {
				return app.TunnelEnrollmentView{}, err
			}
			return svc.Confirm(ctx, by, in.r.PathValue("name"), req.EnrollmentID, req.HostPublicKey)
		},
		enrollmentDone))
	rs.write(http.MethodPost, wire.PathTunnelEnrollmentRefuse, actionNodeAdd, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.TunnelEnrollmentView, error) {
			svc, err := enrollments()
			if err != nil {
				return app.TunnelEnrollmentView{}, err
			}
			req, err := decode[wire.RefuseTunnelEnrollmentRequest](in)
			if err != nil {
				return app.TunnelEnrollmentView{}, err
			}
			return svc.Refuse(ctx, by, in.r.PathValue("name"), req.EnrollmentID, req.HostPublicKey)
		},
		enrollmentDone))
	rs.write(http.MethodPost, wire.PathTunnelEnrollmentCancel, actionNodeAdd, mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.TunnelEnrollmentView, error) {
			svc, err := enrollments()
			if err != nil {
				return app.TunnelEnrollmentView{}, err
			}
			return svc.Cancel(ctx, by, in.r.PathValue("name"))
		},
		enrollmentDone))
}

func enrollmentDone(v app.TunnelEnrollmentView) (int, any) {
	return http.StatusOK, tunnelEnrollmentView(v)
}

// parseExpiresIn reads the optional lifetime of an enrollment; empty leaves the default to the service.
func parseExpiresIn(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, invalid("expires_in must be a positive duration such as 90m")
	}
	return d, nil
}

func tunnelEnrollmentView(v app.TunnelEnrollmentView) wire.TunnelEnrollment {
	tags := v.Tags
	if tags == nil {
		tags = []string{}
	}
	return wire.TunnelEnrollment{
		ID: v.ID, NodeID: v.NodeID, Name: v.Name, Environment: v.Environment, Tags: tags, Hostname: v.Hostname,
		Phase: v.Phase, ExpiresAt: v.ExpiresAt, JoinLine: v.JoinLine, HostPublicKey: v.HostPublicKey,
		HostKeyFingerprint: v.HostKeyFingerprint, Error: v.Error,
	}
}
