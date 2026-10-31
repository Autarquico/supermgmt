package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

// Exemptions: routes that are not catalog actions (ADR-0014).
const (
	// ExemptSelf is for routes that describe or hold the caller's own connection.
	ExemptSelf = "exempt:self"
	// ExemptHealth is for the liveness and readiness probes.
	ExemptHealth = "exempt:health"
	// ExemptAuth is for the login, bootstrap, logout and enrollment routes: the
	// authentication endpoints are not actions (spec §23).
	ExemptAuth = "exempt:auth"
)

// Route says which catalog action (or exemption) a route stands for. The
// table is tested against the catalog: every route names exactly one.
type Route struct {
	Method, Pattern, Action string
	// Keyed routes require an Idempotency-Key.
	Keyed bool
	// Credential routes issue a credential once and reject an Idempotency-Key.
	Credential bool
	// UnixOnly routes are served on the local-mode Unix socket only.
	UnixOnly bool
}

type endpoint func(w http.ResponseWriter, r *http.Request) error

// authMode is how a route identifies its caller on HTTPS.
type authMode int

const (
	authRequired authMode = iota // a valid bearer token
	authOptional                 // a bearer token if one is sent
	authNone                     // no token: probes and login
)

type route struct {
	method, pattern, action string
	keyed, longLived        bool
	auth                    authMode
	// credential: issues a credential once (or is as sensitive); refuses an
	// Idempotency-Key and is never stored as an idempotent answer.
	credential bool
	unixOnly   bool
	// httpsOnly routes are not served on the local-mode Unix socket.
	httpsOnly bool
	maxBody   int64
	do        endpoint
}

func (rt route) isAction() bool { return rt.action != "" && !strings.HasPrefix(rt.action, "exempt:") }
func (rt route) isAuth() bool   { return rt.action == ExemptAuth }
func (rt route) writes() bool   { return rt.method != http.MethodGet && rt.method != http.MethodHead }

func (rt route) bodyLimit() int64 {
	if rt.maxBody > 0 {
		return rt.maxBody
	}
	return maxBodyBytes
}

// Routes lists the routes the server serves.
func (s *Server) Routes() []Route {
	out := make([]Route, len(s.routes))
	for i, rt := range s.routes {
		out[i] = Route{
			Method: rt.method, Pattern: rt.pattern, Action: rt.action,
			Keyed: rt.keyed, Credential: rt.credential, UnixOnly: rt.unixOnly,
		}
	}
	return out
}

func (s *Server) buildRoutes() []route {
	r := routeSet{s: s}
	r.reads()
	r.plans()
	r.jobs()
	r.providers()
	r.proxmox()
	r.repositories()
	r.apps()
	r.deployments()
	r.mcpClients()
	r.webhook()
	r.nodes()
	r.tunnelEnrollments()
	r.sessions()
	r.services()
	r.login()
	r.tokens()
	r.keys()
	r.backups()
	r.enrollment()
	r.stream()
	return slices.DeleteFunc(r.routes, func(rt route) bool {
		return rt.unixOnly && s.transport != viaUnixSocket || rt.httpsOnly && s.transport != viaHTTPS
	})
}

type routeSet struct {
	s      *Server
	routes []route
}

func (rs *routeSet) read(pattern, action string, do endpoint) {
	rs.routes = append(rs.routes, route{method: http.MethodGet, pattern: pattern, action: action, do: do})
}

func (rs *routeSet) write(method, pattern, action string, do endpoint) {
	rs.routes = append(rs.routes, route{method: method, pattern: pattern, action: action, keyed: true, do: do})
}

func (rs *routeSet) reads() {
	s := rs.s
	rs.routes = append(rs.routes, route{
		method: http.MethodGet, pattern: wire.PathHealthLive, action: ExemptHealth, auth: authNone,
		do: func(w http.ResponseWriter, r *http.Request) error {
			s.writeData(w, r, http.StatusOK, wire.Health{Status: "ok"})
			return nil
		},
	})
	rs.routes = append(rs.routes, route{method: http.MethodGet, pattern: wire.PathHealthReady, action: ExemptHealth, auth: authNone, do: s.health})
	rs.read(wire.PathMe, ExemptSelf, reading(s, func(ctx context.Context, by app.Caller, _ input) (wire.Me, error) {
		return s.svc.Queries.Me(ctx, by)
	}))
	rs.routes = append(rs.routes, route{method: http.MethodGet, pattern: wire.PathPresence, action: ExemptSelf, longLived: true, do: s.presence})
	rs.read(wire.PathSSHKey, actionConfigRead, reading(s, func(ctx context.Context, by app.Caller, _ input) (wire.SSHKey, error) {
		if _, err := s.svc.Queries.RequireRead(ctx, by, actionConfigRead, domain.ResourceRef{Type: domain.ResourceInstance}); err != nil {
			return wire.SSHKey{}, err
		}
		return s.svc.SSHKeys.Get(ctx)
	}))
	rs.read(wire.PathEvents, "event.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.Event], error) {
		q, err := wire.ParseEventQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[wire.Event]{}, err
		}
		return s.svc.Queries.Events(ctx, by, q)
	}))
}

func (rs *routeSet) plans() {
	s := rs.s
	rs.read(wire.PathPlan, "plan.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.CreatedPlan, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.CreatedPlan{}, err
		}
		return s.svc.Queries.Plan(ctx, by, id)
	}))
	rs.write(http.MethodPost, wire.PathPlans, "plan.create", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.CreatedPlan, error) {
			req, err := decode[wire.CreatePlanRequest](in)
			if err != nil {
				return app.CreatedPlan{}, err
			}
			if len(req.Targets) != 1 {
				return app.CreatedPlan{}, invalid("a plan has exactly one target in this version")
			}
			target := domain.ResourceRef{Type: req.Targets[0].Type, ID: req.Targets[0].ID}
			return s.svc.Plans.Create(ctx, by, app.PlanRequest{Action: req.Action, Target: target, Parameters: req.Parameters})
		},
		func(c app.CreatedPlan) (int, any) { return http.StatusCreated, app.CreatedPlanView(c) }))
	rs.write(http.MethodPost, wire.PathPlanSubmit, "plan.create", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.Submission, error) {
			id, err := in.id("id")
			if err != nil {
				return app.Submission{}, err
			}
			req, err := decode[wire.PlanHashRequest](in)
			if err != nil {
				return app.Submission{}, err
			}
			return s.svc.Plans.Submit(ctx, by, id, req.PlanHash)
		},
		submitted))
}

func submitted(sub app.Submission) (int, any) { return http.StatusAccepted, app.SubmissionView(sub) }

func (rs *routeSet) jobs() {
	s := rs.s
	rs.read(wire.PathApprovals, "job.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.Approval], error) {
		page, err := wire.ParsePageQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[wire.Approval]{}, err
		}
		return s.svc.Queries.Approvals(ctx, by, page)
	}))
	rs.read(wire.PathJobs, "job.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.Job], error) {
		q, err := wire.ParseJobQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[wire.Job]{}, err
		}
		return s.svc.Queries.Jobs(ctx, by, q)
	}))
	rs.read(wire.PathJob, "job.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.JobDetail, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.JobDetail{}, err
		}
		return s.svc.Queries.Job(ctx, by, id)
	}))
	rs.write(http.MethodPost, wire.PathJobApprove, "approval.grant", rs.decision(s.svc.Approvals.Approve, false))
	rs.write(http.MethodPost, wire.PathJobReject, "approval.reject", rs.decision(s.svc.Approvals.Reject, true))
	rs.write(http.MethodPost, wire.PathJobCancel, "job.cancel", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (jobs.Job, error) {
			id, err := in.id("id")
			if err != nil {
				return jobs.Job{}, err
			}
			req, err := decode[wire.PlanHashRequest](in)
			if err != nil {
				return jobs.Job{}, err
			}
			return s.svc.Governance.Cancel(ctx, by, id, req.PlanHash)
		}, jobDone))
	rs.write(http.MethodPost, wire.PathJobResolve, "job.resolve", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (jobs.Job, error) {
			id, err := in.id("id")
			if err != nil {
				return jobs.Job{}, err
			}
			req, err := decode[wire.ResolveRequest](in)
			if err != nil {
				return jobs.Job{}, err
			}
			outcome, err := resolveOutcome(req.Outcome)
			if err != nil {
				return jobs.Job{}, err
			}
			return s.svc.Governance.Resolve(ctx, by, app.ResolveRequest{
				JobID: id, PlanHash: req.PlanHash, Outcome: outcome, Note: req.Note, AssumeQuiescent: req.AssumeQuiescent,
			})
		}, jobDone))
}

func jobDone(j jobs.Job) (int, any) { return http.StatusOK, app.JobView(j) }

func resolveOutcome(o wire.Outcome) (jobs.ResolveOutcome, error) {
	switch o {
	case wire.OutcomeSucceeded:
		return jobs.ResolveSucceeded, nil
	case wire.OutcomeFailed:
		return jobs.ResolveFailed, nil
	case wire.OutcomeRollbackFailed:
		return jobs.ResolveRollbackFailed, nil
	}
	return "", invalid("outcome must be succeeded, failed or rollback_failed")
}

// decision is the endpoint of approve and reject, which differ in the service
// they call and in rejecting needing a reason.
func (rs *routeSet) decision(call func(context.Context, app.Caller, app.DecisionRequest) (jobs.Job, error), needsReason bool) endpoint {
	return mutation(rs.s,
		func(ctx context.Context, by app.Caller, in input) (jobs.Job, error) {
			id, err := in.id("id")
			if err != nil {
				return jobs.Job{}, err
			}
			req, err := decode[wire.DecisionRequest](in)
			if err != nil {
				return jobs.Job{}, err
			}
			if needsReason && strings.TrimSpace(req.Reason) == "" {
				return jobs.Job{}, invalid("a reason is required to reject")
			}
			return call(ctx, by, app.DecisionRequest{JobID: id, PlanHash: req.PlanHash, Reason: req.Reason})
		}, jobDone)
}

func (rs *routeSet) providers() {
	s := rs.s
	rs.read(wire.PathProviders, "provider.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.Provider], error) {
		if _, err := wire.ParsePageQuery(in.r.URL.Query()); err != nil {
			return wire.Page[wire.Provider]{}, err
		}
		providers, err := s.svc.Inventory.ListProviders(ctx, by)
		if providers == nil {
			providers = []wire.Provider{}
		}
		return wire.Page[wire.Provider]{Items: providers}, err
	}))
	rs.write(http.MethodPost, wire.PathProviders, "provider.write", mutation(s, s.registerProvider, direct(http.StatusCreated, app.ProviderView)))
}

// registerProvider routes POST /providers by the body's type: local, or github
// (approval-gated provider.write).
func (s *Server) registerProvider(ctx context.Context, by app.Caller, in input) (app.DirectResult[domain.Provider], error) {
	var kind wire.CreateProviderRequest
	_ = json.Unmarshal(in.body, &kind) // a malformed body is reported by the strict decode below
	switch kind.Type {
	case wire.ProviderGitHub:
		if s.svc.Apps == nil {
			return app.DirectResult[domain.Provider]{}, invalid("the %q provider is not available", wire.ProviderGitHub)
		}
		req, err := decode[wire.CreateGitHubProviderRequest](in)
		if err != nil {
			return app.DirectResult[domain.Provider]{}, err
		}
		return s.svc.Apps.CreateGitHubProvider(ctx, by, req)
	case wire.ProviderLocal:
		if _, err := decode[wire.CreateProviderRequest](in); err != nil {
			return app.DirectResult[domain.Provider]{}, err
		}
		return s.svc.Inventory.RegisterLocal(ctx, by)
	}
	return app.DirectResult[domain.Provider]{}, invalid("provider type must be %q or %q", wire.ProviderLocal, wire.ProviderGitHub)
}

// direct renders the outcome of a `direct` action: applied at once with
// appliedStatus, or pending as a control_plane.apply job (202).
func direct[T, V any](appliedStatus int, view func(T) V) func(app.DirectResult[T]) (int, any) {
	return func(d app.DirectResult[T]) (int, any) {
		switch {
		case d.Applied != nil:
			applied := view(*d.Applied)
			return appliedStatus, wire.Direct[V]{Applied: &applied}
		case d.Pending != nil:
			pending := app.SubmissionView(*d.Pending)
			return http.StatusAccepted, wire.Direct[V]{Pending: &pending}
		}
		return http.StatusInternalServerError, wire.Direct[V]{}
	}
}

func same[T any](v T) T { return v }

func (rs *routeSet) nodes() {
	s := rs.s
	rs.read(wire.PathNodes, "node.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.Node], error) {
		q, err := wire.ParseNodeQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[wire.Node]{}, err
		}
		return s.svc.Inventory.ListNodes(ctx, by, q)
	}))
	rs.read(wire.PathNode, "node.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Node, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.Node{}, err
		}
		focus, err := focusParam(in)
		if err != nil {
			return wire.Node{}, err
		}
		return s.svc.Inventory.GetNode(ctx, by, id, focus)
	}))
	rs.routes = append(rs.routes, route{
		method: http.MethodPost, pattern: wire.PathNodesSSHHostKey, action: "node.add",
		do: reading(s, func(ctx context.Context, by app.Caller, in input) (wire.HostKey, error) {
			req, err := decode[wire.ScanHostKeyRequest](in)
			if err != nil {
				return wire.HostKey{}, err
			}
			key, err := s.svc.Inventory.ScanHostKey(ctx, by, req.Host, req.Port)
			return wire.HostKey{AuthorizedKey: key.Authorized, Type: key.Type, FingerprintSHA256: key.FingerprintSHA256}, err
		}),
	})
	rs.write(http.MethodPost, wire.PathNodesSSH, "node.add", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DirectResult[wire.Node], error) {
			req, err := decode[wire.AddSSHNodeRequest](in)
			if err != nil {
				return app.DirectResult[wire.Node]{}, err
			}
			return s.svc.Inventory.AddSSHNode(ctx, by, app.AddSSHNode{
				Name: req.Name, Host: req.Host, Port: req.Port, User: req.User, AdminUser: req.AdminUser,
				HostKey: req.HostPublicKey, CredentialRef: req.CredentialRef, AdminCredentialRef: req.AdminCredentialRef,
				Environment: req.Environment, Tags: req.Tags,
			})
		},
		direct(http.StatusCreated, same[wire.Node])))
	rs.write(http.MethodPatch, wire.PathNode, "node.update", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DirectResult[wire.Node], error) {
			id, err := in.id("id")
			if err != nil {
				return app.DirectResult[wire.Node]{}, err
			}
			revision, err := in.ifMatch()
			if err != nil {
				return app.DirectResult[wire.Node]{}, err
			}
			patch, err := decode[wire.NodePatch](in)
			if err != nil {
				return app.DirectResult[wire.Node]{}, err
			}
			return s.svc.Inventory.UpdateNode(ctx, by, id, revision, patch)
		},
		direct(http.StatusOK, same[wire.Node])))
	rs.write(http.MethodDelete, wire.PathNode, "node.remove", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.DirectResult[wire.Node], error) {
			id, err := in.id("id")
			if err != nil {
				return app.DirectResult[wire.Node]{}, err
			}
			revision, err := in.ifMatch()
			if err != nil {
				return app.DirectResult[wire.Node]{}, err
			}
			return s.svc.Inventory.RemoveNode(ctx, by, id, revision)
		},
		direct(http.StatusOK, same[wire.Node])))
	rs.write(http.MethodPost, wire.PathNodeProbe, "node.probe", mutation(s, s.probe, submitted))
	rs.read(wire.PathNodeServices, "service.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Page[wire.Service], error) {
		id, err := in.id("id")
		if err != nil {
			return wire.Page[wire.Service]{}, err
		}
		page, err := wire.ParsePageQuery(in.r.URL.Query())
		if err != nil {
			return wire.Page[wire.Service]{}, err
		}
		return s.svc.Inventory.ListServices(ctx, by, id, page)
	}))
	rs.read(wire.PathNodeConnectInfo, "node.connect", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.ConnectInfo, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.ConnectInfo{}, err
		}
		return s.svc.Inventory.ConnectInfo(ctx, by, id)
	}))
}

// probe plans and submits node.probe. The plan is created outside the
// idempotent step on purpose: a retried request creates one more unsubmitted
// plan (they expire) but, through the key, submits only one job.
func (s *Server) probe(ctx context.Context, by app.Caller, in input) (app.Submission, error) {
	id, err := in.id("id")
	if err != nil {
		return app.Submission{}, err
	}
	unkeyed := by
	unkeyed.Idempotency = nil
	created, err := s.svc.Plans.Create(ctx, unkeyed, app.PlanRequest{
		Action: "node.probe", Target: domain.ResourceRef{Type: domain.ResourceNode, ID: id},
	})
	if err != nil {
		return app.Submission{}, err
	}
	return s.svc.Plans.Submit(ctx, by, created.Record.ID, created.Record.PlanHash)
}

func focusParam(in input) (bool, error) {
	raw := in.r.URL.Query().Get(wire.QueryFocus)
	if raw == "" {
		return false, nil
	}
	focus, err := strconv.ParseBool(raw)
	if err != nil {
		return false, invalid("query parameter %s must be true or false", wire.QueryFocus)
	}
	return focus, nil
}

func (rs *routeSet) sessions() {
	s := rs.s
	rs.write(http.MethodPost, wire.PathNodeSessions, "node.connect", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (wire.SessionOpened, error) {
			id, err := in.id("id")
			if err != nil {
				return wire.SessionOpened{}, err
			}
			req, err := decode[wire.OpenSessionRequest](in)
			if err != nil {
				return wire.SessionOpened{}, err
			}
			session, info, err := s.svc.Sessions.Open(ctx, by, id, string(req.Tool))
			return wire.SessionOpened{Session: session, ConnectInfo: info}, err
		},
		func(opened wire.SessionOpened) (int, any) { return http.StatusCreated, opened }))
	rs.write(http.MethodPost, wire.PathNodeSessionEnd, "node.connect", mutation(s,
		func(ctx context.Context, by app.Caller, in input) (app.Session, error) {
			node, err := in.id("id")
			if err != nil {
				return app.Session{}, err
			}
			session, err := in.id("sid")
			if err != nil {
				return app.Session{}, err
			}
			req, err := decode[wire.EndSessionRequest](in)
			if err != nil {
				return app.Session{}, err
			}
			return s.svc.Sessions.End(ctx, by, node, session, app.EndSession{Reason: req.Reason, ExitCode: req.ExitCode})
		},
		func(session app.Session) (int, any) { return http.StatusOK, session }))
}

func (rs *routeSet) services() {
	s := rs.s
	rs.read(wire.PathService, "service.read", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.Service, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.Service{}, err
		}
		return s.svc.Inventory.GetService(ctx, by, id)
	}))
	rs.read(wire.PathServiceLogs, "service.logs", reading(s, func(ctx context.Context, by app.Caller, in input) (wire.LogChunk, error) {
		id, err := in.id("id")
		if err != nil {
			return wire.LogChunk{}, err
		}
		q, err := wire.ParseLogQuery(in.r.URL.Query())
		if err != nil {
			return wire.LogChunk{}, err
		}
		return s.svc.Inventory.ServiceLogs(ctx, by, id, q.Lines)
	}))
	for pattern, verb := range map[string]domain.ServiceVerb{
		wire.PathServiceStart:   domain.VerbStart,
		wire.PathServiceStop:    domain.VerbStop,
		wire.PathServiceRestart: domain.VerbRestart,
	} {
		rs.write(http.MethodPost, pattern, verb.Action(), mutation(s,
			func(ctx context.Context, by app.Caller, in input) (app.Submission, error) {
				id, err := in.id("id")
				if err != nil {
					return app.Submission{}, err
				}
				return s.svc.Services.Act(ctx, by, id, verb)
			}, submitted))
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) error {
	if s.ready != nil {
		if err := s.ready(r.Context()); err != nil {
			return smerr.Wrap(err, smerr.CodeInternal, "", "not ready")
		}
	}
	s.writeData(w, r, http.StatusOK, wire.Health{Status: "ok"})
	return nil
}

// presence is held open by long-lived clients so the daemon knows someone is
// watching (ADR-0014). It ends when the client goes or the server shuts down.
func (s *Server) presence(w http.ResponseWriter, r *http.Request) error {
	defer s.residency.Present()()
	s.writeData(w, r, http.StatusOK, wire.Health{Status: "connected"})
	if err := http.NewResponseController(w).Flush(); err != nil {
		return nil // the client is already gone
	}
	select {
	case <-r.Context().Done():
	case <-s.closing:
	}
	return nil
}
