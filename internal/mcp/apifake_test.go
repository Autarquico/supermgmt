package mcp

import (
	"context"
	"strconv"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// fakeAPI is an in-memory API. Methods the read tools do not use are served
// by the embedded nil interface and would panic, which a test would surface.
type fakeAPI struct {
	API

	nodes    []wire.Node
	services map[domain.ID][]wire.Service
	routes   []wire.NodeRoute
	events   []wire.Event
	logs     wire.LogChunk

	me          wire.Me
	jobs        []wire.Job
	jobDetails  map[domain.ID]wire.JobDetail
	approvals   []wire.Approval
	plans       map[domain.ID]wire.CreatedPlan
	providers   []wire.Provider
	backups     []wire.Backup
	enrollments []wire.TunnelEnrollment
	sshKey      wire.SSHKey
	actions     []wire.PlannableAction

	pageSize int            // items per page; 0 serves everything in one page
	failWith error          // returned by every method when set
	calls    map[string]int // method name -> number of calls

	lastLogQuery   wire.LogQuery
	lastEventQuery wire.EventQuery
	lastNodeQuery  wire.NodeQuery
	lastJobQuery   wire.JobQuery
}

func (f *fakeAPI) enter(method string) error {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[method]++
	return f.failWith
}

func pageOf[T any](all []T, q wire.PageQuery, size int) wire.Page[T] {
	start := 0
	if q.Cursor != "" {
		start, _ = strconv.Atoi(q.Cursor)
	}
	if size <= 0 || start+size >= len(all) {
		return wire.Page[T]{Items: all[start:]}
	}
	return wire.Page[T]{Items: all[start : start+size], NextCursor: strconv.Itoa(start + size)}
}

func (f *fakeAPI) ListNodes(_ context.Context, q wire.NodeQuery) (wire.Page[wire.Node], error) {
	f.lastNodeQuery = q
	return pageOf(f.nodes, q.PageQuery, f.pageSize), f.enter("ListNodes")
}

func (f *fakeAPI) GetNode(_ context.Context, id domain.ID, _ bool) (wire.Node, error) {
	if err := f.enter("GetNode"); err != nil {
		return wire.Node{}, err
	}
	for _, n := range f.nodes {
		if n.ID == id {
			return n, nil
		}
	}
	return wire.Node{}, smerr.New(smerr.CodeNotFound, "", "no such node")
}

func (f *fakeAPI) ListServices(_ context.Context, node domain.ID, q wire.PageQuery) (wire.Page[wire.Service], error) {
	return pageOf(f.services[node], q, f.pageSize), f.enter("ListServices")
}

func (f *fakeAPI) GetService(_ context.Context, id domain.ID) (wire.Service, error) {
	if err := f.enter("GetService"); err != nil {
		return wire.Service{}, err
	}
	for _, list := range f.services {
		for _, s := range list {
			if s.ID == id {
				return s, nil
			}
		}
	}
	return wire.Service{}, smerr.New(smerr.CodeNotFound, "", "no such service")
}

func (f *fakeAPI) ServiceLogs(_ context.Context, _ domain.ID, q wire.LogQuery) (wire.LogChunk, error) {
	f.lastLogQuery = q
	return f.logs, f.enter("ServiceLogs")
}

func (f *fakeAPI) ListEvents(_ context.Context, q wire.EventQuery) (wire.Page[wire.Event], error) {
	f.lastEventQuery = q
	return pageOf(f.events, q.PageQuery, f.pageSize), f.enter("ListEvents")
}

func (f *fakeAPI) ListAllNodeRoutes(context.Context, bool) (wire.Page[wire.NodeRoute], error) {
	return wire.Page[wire.NodeRoute]{Items: f.routes}, f.enter("ListAllNodeRoutes")
}

func (f *fakeAPI) Me(context.Context) (wire.Me, error) { return f.me, f.enter("Me") }

func (f *fakeAPI) SSHKey(context.Context) (wire.SSHKey, error) { return f.sshKey, f.enter("SSHKey") }

func (f *fakeAPI) ListProviders(_ context.Context, q wire.PageQuery) (wire.Page[wire.Provider], error) {
	return pageOf(f.providers, q, f.pageSize), f.enter("ListProviders")
}

func (f *fakeAPI) ListJobs(_ context.Context, q wire.JobQuery) (wire.Page[wire.Job], error) {
	f.lastJobQuery = q
	return pageOf(f.jobs, q.PageQuery, f.pageSize), f.enter("ListJobs")
}

func (f *fakeAPI) GetJob(_ context.Context, id domain.ID) (wire.JobDetail, error) {
	if err := f.enter("GetJob"); err != nil {
		return wire.JobDetail{}, err
	}
	detail, ok := f.jobDetails[id]
	if !ok {
		return wire.JobDetail{}, smerr.New(smerr.CodeNotFound, "", "no such job")
	}
	return detail, nil
}

func (f *fakeAPI) ListApprovals(_ context.Context, q wire.PageQuery) (wire.Page[wire.Approval], error) {
	return pageOf(f.approvals, q, f.pageSize), f.enter("ListApprovals")
}

func (f *fakeAPI) GetPlan(_ context.Context, id domain.ID) (wire.CreatedPlan, error) {
	if err := f.enter("GetPlan"); err != nil {
		return wire.CreatedPlan{}, err
	}
	plan, ok := f.plans[id]
	if !ok {
		return wire.CreatedPlan{}, smerr.New(smerr.CodeNotFound, "", "no such plan")
	}
	return plan, nil
}

func (f *fakeAPI) ListBackups(context.Context) (wire.Page[wire.Backup], error) {
	return wire.Page[wire.Backup]{Items: f.backups}, f.enter("ListBackups")
}

func (f *fakeAPI) ListTunnelEnrollments(context.Context) (wire.Page[wire.TunnelEnrollment], error) {
	return wire.Page[wire.TunnelEnrollment]{Items: f.enrollments}, f.enter("ListTunnelEnrollments")
}

func (f *fakeAPI) ListActions(context.Context) (wire.Page[wire.PlannableAction], error) {
	return wire.Page[wire.PlannableAction]{Items: f.actions}, f.enter("ListActions")
}
