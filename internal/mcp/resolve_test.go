package mcp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func resolveNodeIDOf(n int) domain.ID {
	return domain.ID(fmt.Sprintf("0190a5c3-7b1e-7c3a-9d2e-%012d", n))
}

func wantToolError(t *testing.T, err error, code smerr.Code, reason smerr.Reason) {
	t.Helper()
	var got *toolError
	if !errors.As(err, &got) {
		t.Fatalf("err = %v, want a tool error", err)
	}
	if got.Code != code || got.Reason != reason {
		t.Errorf("err = %s/%s, want %s/%s", got.Code, got.Reason, code, reason)
	}
}

func TestResolveNode(t *testing.T) {
	api := &fakeAPI{nodes: []wire.Node{
		{ID: resolveNodeIDOf(1), Name: "web-1"},
		{ID: resolveNodeIDOf(2), Name: "web-2"},
		{ID: resolveNodeIDOf(3), Name: "dup"},
		{ID: resolveNodeIDOf(4), Name: "dup"},
	}}
	tests := []struct {
		name       string
		ref        string
		want       domain.ID
		wantCode   smerr.Code
		wantReason smerr.Reason
	}{
		{name: "exact name", ref: "web-2", want: resolveNodeIDOf(2)},
		{name: "unknown name", ref: "web-9", wantCode: smerr.CodeNotFound},
		{name: "name is not a prefix match", ref: "web", wantCode: smerr.CodeNotFound},
		{name: "ambiguous", ref: "dup", wantCode: smerr.CodeInvalidArgument, wantReason: smerr.ReasonAmbiguousTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveNode(context.Background(), api, tt.ref)
			if tt.wantCode != "" {
				wantToolError(t, err, tt.wantCode, tt.wantReason)
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("resolveNode(%q) = %v, %v; want %v", tt.ref, got, err, tt.want)
			}
		})
	}
}

func TestResolveNode_AnIDNeedsNoAPICall(t *testing.T) {
	api := &fakeAPI{}
	id := resolveNodeIDOf(7)

	got, err := resolveNode(context.Background(), api, string(id))

	if err != nil || got != id {
		t.Errorf("resolveNode = %v, %v; want %v", got, err, id)
	}
	if len(api.calls) != 0 {
		t.Errorf("API calls = %v, want none", api.calls)
	}
}

func TestResolveNode_ReadsEveryPageBeforeDecidingUniqueness(t *testing.T) {
	api := &fakeAPI{pageSize: 1, nodes: []wire.Node{
		{ID: resolveNodeIDOf(1), Name: "twin"},
		{ID: resolveNodeIDOf(2), Name: "other"},
		{ID: resolveNodeIDOf(3), Name: "twin"},
	}}

	_, err := resolveNode(context.Background(), api, "twin")

	wantToolError(t, err, smerr.CodeInvalidArgument, smerr.ReasonAmbiguousTarget)
}

func TestResolveNode_PagingIsBoundedAt50Pages(t *testing.T) {
	nodes := make([]wire.Node, maxResolvePages+5)
	for i := range nodes {
		nodes[i] = wire.Node{ID: resolveNodeIDOf(i + 1), Name: fmt.Sprintf("n%d", i)}
	}
	api := &fakeAPI{pageSize: 1, nodes: nodes}

	_, err := resolveNode(context.Background(), api, "n0")

	wantToolError(t, err, smerr.CodeInvalidArgument, "")
	if api.calls["ListNodes"] != maxResolvePages {
		t.Errorf("ListNodes calls = %d, want %d", api.calls["ListNodes"], maxResolvePages)
	}
}

func TestResolveNode_ListingFailureSurfaces(t *testing.T) {
	api := &fakeAPI{failWith: smerr.New(smerr.CodeInternal, "", "boom")}

	_, err := resolveNode(context.Background(), api, "web-1")

	if got := toolFailure(err); got.Code != smerr.CodeInternal {
		t.Errorf("failure = %v", got)
	}
}

func TestResolveService(t *testing.T) {
	node := resolveNodeIDOf(1)
	api := &fakeAPI{
		nodes: []wire.Node{{ID: node, Name: "web-1"}},
		services: map[domain.ID][]wire.Service{node: {
			{ID: resolveNodeIDOf(10), Name: "nginx"},
			{ID: resolveNodeIDOf(11), Name: "getty@tty1.service"},
			{ID: resolveNodeIDOf(12), Name: "dup"},
			{ID: resolveNodeIDOf(13), Name: "dup"},
		}},
	}
	tests := []struct {
		name       string
		ref        string
		want       domain.ID
		wantCode   smerr.Code
		wantReason smerr.Reason
	}{
		{name: "name@node", ref: "nginx@web-1", want: resolveNodeIDOf(10)},
		{name: "instance name containing @", ref: "getty@tty1.service@web-1", want: resolveNodeIDOf(11)},
		{name: "service not on the node", ref: "redis@web-1", wantCode: smerr.CodeNotFound},
		{name: "node not found", ref: "nginx@web-9", wantCode: smerr.CodeNotFound},
		{name: "ambiguous on the node", ref: "dup@web-1", wantCode: smerr.CodeInvalidArgument, wantReason: smerr.ReasonAmbiguousTarget},
		{name: "bare name", ref: "nginx", wantCode: smerr.CodeInvalidArgument},
		{name: "empty node", ref: "nginx@", wantCode: smerr.CodeInvalidArgument},
		{name: "empty name", ref: "@web-1", wantCode: smerr.CodeInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveService(context.Background(), api, tt.ref)
			if tt.wantCode != "" {
				wantToolError(t, err, tt.wantCode, tt.wantReason)
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("resolveService(%q) = %v, %v; want %v", tt.ref, got, err, tt.want)
			}
		})
	}
}

func TestResolveApp(t *testing.T) {
	api := &fakeAPI{apps: []wire.App{
		{ID: resolveNodeIDOf(1), Name: "shop"},
		{ID: resolveNodeIDOf(2), Name: "blog"},
		{ID: resolveNodeIDOf(3), Name: "blog"},
	}}

	if got, err := resolveApp(context.Background(), api, "shop"); err != nil || got != resolveNodeIDOf(1) {
		t.Errorf("shop = %v, %v", got, err)
	}
	_, err := resolveApp(context.Background(), api, "blog")
	wantToolError(t, err, smerr.CodeInvalidArgument, smerr.ReasonAmbiguousTarget)
	_, err = resolveApp(context.Background(), api, "wiki")
	wantToolError(t, err, smerr.CodeNotFound, "")
}

// A name that sanitation would rewrite still resolves, and only by its raw
// value: the display copy can never retarget a call.
func TestResolveNode_UsesRawNamesNotTheSanitizedCopy(t *testing.T) {
	const raw = "web\x1b[31m-1"
	api := &fakeAPI{nodes: []wire.Node{
		{ID: resolveNodeIDOf(1), Name: raw},
		{ID: resolveNodeIDOf(2), Name: "web-1"},
	}}
	if view := ViewNode(api.nodes[0]); view.Name == raw {
		t.Fatalf("precondition: the view should sanitize %q", raw)
	}

	byRaw, err := resolveNode(context.Background(), api, raw)
	if err != nil || byRaw != resolveNodeIDOf(1) {
		t.Errorf("resolve by raw name = %v, %v; want node 1", byRaw, err)
	}
	displayed := ViewNode(api.nodes[0]).Name
	bySanitized, err := resolveNode(context.Background(), api, displayed)
	if err != nil || bySanitized != resolveNodeIDOf(2) {
		t.Errorf("resolve %q = %v, %v; want the node really named that (2)", displayed, bySanitized, err)
	}
}
