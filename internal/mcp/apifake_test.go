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

	pageSize int            // items per page; 0 serves everything in one page
	failWith error          // returned by every method when set
	calls    map[string]int // method name -> number of calls

	lastLogQuery   wire.LogQuery
	lastEventQuery wire.EventQuery
	lastNodeQuery  wire.NodeQuery
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
