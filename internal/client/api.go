package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func (c *Client) Me(ctx context.Context) (wire.Me, error) {
	return call[wire.Me](ctx, c, get(wire.PathMe, nil))
}

// SSHKey returns the public half of the instance SSH identity (spec §8.4).
func (c *Client) SSHKey(ctx context.Context) (wire.SSHKey, error) {
	return call[wire.SSHKey](ctx, c, get(wire.PathSSHKey, nil))
}

// ---- providers and nodes ---------------------------------------------------

func (c *Client) ListProviders(ctx context.Context, q wire.PageQuery) (wire.Page[wire.Provider], error) {
	return call[wire.Page[wire.Provider]](ctx, c, get(wire.PathProviders, q.Values()))
}

// RegisterLocal records the user's consent to manage this machine (spec §14).
func (c *Client) RegisterLocal(ctx context.Context) (wire.Direct[wire.Provider], error) {
	return call[wire.Direct[wire.Provider]](ctx, c, post(wire.PathProviders, wire.CreateProviderRequest{Type: wire.ProviderLocal}))
}

func (c *Client) ListNodes(ctx context.Context, q wire.NodeQuery) (wire.Page[wire.Node], error) {
	return call[wire.Page[wire.Node]](ctx, c, get(wire.PathNodes, q.Values()))
}

func (c *Client) GetNode(ctx context.Context, id domain.ID, focus bool) (wire.Node, error) {
	query := url.Values{}
	if focus {
		query.Set(wire.QueryFocus, strconv.FormatBool(true))
	}
	return call[wire.Node](ctx, c, get(wire.Path(wire.PathNode, string(id)), query))
}

// ScanHostKey is the read-only keyscan behind the first-trust confirmation.
func (c *Client) ScanHostKey(ctx context.Context, r wire.ScanHostKeyRequest) (wire.HostKey, error) {
	req := post(wire.PathNodesSSHHostKey, r)
	req.unkeyed = true
	return call[wire.HostKey](ctx, c, req)
}

func (c *Client) AddSSHNode(ctx context.Context, r wire.AddSSHNodeRequest) (wire.Direct[wire.Node], error) {
	return call[wire.Direct[wire.Node]](ctx, c, post(wire.PathNodesSSH, r))
}

// UpdateNode patches a node; specRevision is the revision the caller read.
func (c *Client) UpdateNode(ctx context.Context, id domain.ID, specRevision int64, p wire.NodePatch) (wire.Direct[wire.Node], error) {
	req := request{method: http.MethodPatch, path: wire.Path(wire.PathNode, string(id)), body: p, ifMatch: strconv.FormatInt(specRevision, 10)}
	return call[wire.Direct[wire.Node]](ctx, c, req)
}

// RemoveNode retires a node; specRevision is the revision the caller read.
func (c *Client) RemoveNode(ctx context.Context, id domain.ID, specRevision int64) (wire.Direct[wire.Node], error) {
	req := request{method: http.MethodDelete, path: wire.Path(wire.PathNode, string(id)), ifMatch: strconv.FormatInt(specRevision, 10)}
	return call[wire.Direct[wire.Node]](ctx, c, req)
}

func (c *Client) ProbeNode(ctx context.Context, id domain.ID) (wire.Submission, error) {
	return call[wire.Submission](ctx, c, post(wire.Path(wire.PathNodeProbe, string(id)), nil))
}

func (c *Client) ConnectInfo(ctx context.Context, id domain.ID) (wire.ConnectInfo, error) {
	return call[wire.ConnectInfo](ctx, c, get(wire.Path(wire.PathNodeConnectInfo, string(id)), nil))
}

// ---- services --------------------------------------------------------------

func (c *Client) ListServices(ctx context.Context, node domain.ID, q wire.PageQuery) (wire.Page[wire.Service], error) {
	return call[wire.Page[wire.Service]](ctx, c, get(wire.Path(wire.PathNodeServices, string(node)), q.Values()))
}

func (c *Client) GetService(ctx context.Context, id domain.ID) (wire.Service, error) {
	return call[wire.Service](ctx, c, get(wire.Path(wire.PathService, string(id)), nil))
}

func (c *Client) ServiceLogs(ctx context.Context, id domain.ID, q wire.LogQuery) (wire.LogChunk, error) {
	return call[wire.LogChunk](ctx, c, get(wire.Path(wire.PathServiceLogs, string(id)), q.Values()))
}

// ServiceAction submits start, stop or restart. Any other verb is refused
// here, since the daemon has no route for it.
func (c *Client) ServiceAction(ctx context.Context, id domain.ID, verb domain.ServiceVerb) (wire.Submission, error) {
	pattern, err := actionPattern(verb)
	if err != nil {
		return wire.Submission{}, err
	}
	return call[wire.Submission](ctx, c, post(wire.Path(pattern, string(id)), nil))
}

// ---- plans, jobs, approvals ------------------------------------------------

func (c *Client) CreatePlan(ctx context.Context, r wire.CreatePlanRequest) (wire.CreatedPlan, error) {
	return call[wire.CreatedPlan](ctx, c, post(wire.PathPlans, r))
}

func (c *Client) SubmitPlan(ctx context.Context, plan domain.ID, planHash string) (wire.Submission, error) {
	return call[wire.Submission](ctx, c, post(wire.Path(wire.PathPlanSubmit, string(plan)), wire.PlanHashRequest{PlanHash: planHash}))
}

func (c *Client) ListApprovals(ctx context.Context, q wire.PageQuery) (wire.Page[wire.Approval], error) {
	return call[wire.Page[wire.Approval]](ctx, c, get(wire.PathApprovals, q.Values()))
}

func (c *Client) Approve(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error) {
	return call[wire.Job](ctx, c, post(wire.Path(wire.PathJobApprove, string(job)), r))
}

func (c *Client) Reject(ctx context.Context, job domain.ID, r wire.DecisionRequest) (wire.Job, error) {
	return call[wire.Job](ctx, c, post(wire.Path(wire.PathJobReject, string(job)), r))
}

func (c *Client) ListJobs(ctx context.Context, q wire.JobQuery) (wire.Page[wire.Job], error) {
	return call[wire.Page[wire.Job]](ctx, c, get(wire.PathJobs, q.Values()))
}

func (c *Client) GetJob(ctx context.Context, id domain.ID) (wire.JobDetail, error) {
	return call[wire.JobDetail](ctx, c, get(wire.Path(wire.PathJob, string(id)), nil))
}

func (c *Client) CancelJob(ctx context.Context, id domain.ID, planHash string) (wire.Job, error) {
	return call[wire.Job](ctx, c, post(wire.Path(wire.PathJobCancel, string(id)), wire.PlanHashRequest{PlanHash: planHash}))
}

func (c *Client) ResolveJob(ctx context.Context, id domain.ID, r wire.ResolveRequest) (wire.Job, error) {
	return call[wire.Job](ctx, c, post(wire.Path(wire.PathJobResolve, string(id)), r))
}

// ---- events ----------------------------------------------------------------

func (c *Client) ListEvents(ctx context.Context, q wire.EventQuery) (wire.Page[wire.Event], error) {
	return call[wire.Page[wire.Event]](ctx, c, get(wire.PathEvents, q.Values()))
}

func actionPattern(verb domain.ServiceVerb) (string, error) {
	switch verb {
	case domain.VerbStart:
		return wire.PathServiceStart, nil
	case domain.VerbStop:
		return wire.PathServiceStop, nil
	case domain.VerbRestart:
		return wire.PathServiceRestart, nil
	}
	return "", smerr.New(smerr.CodeInvalidArgument, "", "unknown service action "+strconv.Quote(string(verb))+": want start, stop or restart")
}
