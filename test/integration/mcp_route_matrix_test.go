package integration

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

// The writes-gate matrix (ADR-0032, spec §11.1, §24): every route of the real
// API server, called with a concrete valid request by an `mcp` actor whose
// policy grants `*`, with mcp.write_tools_enabled off and on, over the Unix
// socket and in process. Each row pins the status, the error reason and the
// rows the request is allowed to create. A route that is served but absent
// from testdata/mcp_route_matrix.json fails TestMCPMatrixListsEveryRoute.

const mcpMatrixFile = "testdata/mcp_route_matrix.json"

// mcpMatrixClass says why a row answers as it does.
type mcpMatrixClass string

const (
	// classQuery: a catalog query; the writes gate lets it through.
	classQuery mcpMatrixClass = "query"
	// classWrite: a non-query action; refused with MCP_WRITES_DISABLED while
	// writes are off, under normal policy and floors once they are on.
	classWrite mcpMatrixClass = "write"
	// classPlan: plan.create is a query, so a plan is stored either way, but
	// its verdict is the denial while writes are off.
	classPlan mcpMatrixClass = "plan"
	// classForbidden: refused with MCP_ACTION_FORBIDDEN whatever the grant.
	classForbidden mcpMatrixClass = "forbidden"
	// classGovernance: an mcp actor can never approve, reject or resolve.
	classGovernance mcpMatrixClass = "governance"
	// classExempt: no catalog action; the route authenticates itself.
	classExempt mcpMatrixClass = "exempt"
)

type mcpMatrixRow struct {
	Route   string         `json:"route"`
	Class   mcpMatrixClass `json:"class"`
	Path    string         `json:"path"`
	Body    string         `json:"body"`
	Headers []string       `json:"headers"`
	Stream  bool           `json:"stream"`
	// Note records why a row answers in a way that needs a decision.
	Note string        `json:"note,omitempty"`
	Off  mcpMatrixWant `json:"off"`
	On   mcpMatrixWant `json:"on"`
}

// mcpMatrixWant is the expected outcome of one row in one writes mode.
type mcpMatrixWant struct {
	Status int          `json:"status"`
	Reason smerr.Reason `json:"reason,omitempty"`
	// PlanDecision is the policy verdict stored with a plan the request created.
	PlanDecision string `json:"plan_decision,omitempty"`
	// Created is the rows the request leaves behind, by watched count. A
	// watched count that is not listed must not change.
	Created map[string]int `json:"created,omitempty"`
	// NodeCommands is the commands the request sent to a node. A refused write
	// sends none.
	NodeCommands int `json:"node_commands,omitempty"`
}

// mcpMatrixWatches are the counts whose growth a denied write must never
// cause, each a table or a filtered table.
var mcpMatrixWatches = []string{
	"jobs", "plans", "job_approvals", "api_tokens", "deployments", "mcp_clients", "identities", "role_bindings",
	"secrets", "join_tokens", "interactive_sessions", "sessions", "apps", "app_targets", "nodes", "providers",
	"api_tokens WHERE revoked_at IS NOT NULL", "jobs WHERE state = 'cancelled'",
}

func loadMCPMatrix(t *testing.T) []mcpMatrixRow {
	t.Helper()
	raw, err := os.ReadFile(mcpMatrixFile)
	mcpRigMust(t, err)
	var doc struct {
		Rows []mcpMatrixRow `json:"rows"`
	}
	mcpRigMust(t, json.Unmarshal(raw, &doc))
	return doc.Rows
}

func (r mcpMatrixRow) want(writes bool) mcpMatrixWant {
	if writes {
		return r.On
	}
	return r.Off
}

// mcpMatrixOutcome is what one request did.
type mcpMatrixOutcome struct {
	Status       int
	Reason       smerr.Reason
	PlanDecision string
	Created      map[string]int
	NodeCommands int
}

func (rig *mcpRig) watched() map[string]int {
	counts := make(map[string]int, len(mcpMatrixWatches))
	for _, table := range mcpMatrixWatches {
		counts[table] = rig.count(table)
	}
	return counts
}

// attempt sends the row's request as the MCP client and reports what changed.
func (rig *mcpRig) attempt(via mcpRigTransport, row mcpMatrixRow) mcpMatrixOutcome {
	t := rig.t
	t.Helper()
	method, _, _ := strings.Cut(row.Route, " ")
	var headers []string
	if rig.isKeyed(row.Route) {
		headers = rig.keyed()
	}
	headers = append(headers, row.Headers...)
	before, commandsBefore := rig.watched(), rig.runtime.commands.Load()
	reply := rig.sendRow(via, method, rig.expand(row.Path), rig.expand(row.Body), row.Stream, headers)

	out := mcpMatrixOutcome{Status: reply.status, Created: map[string]int{}}
	if reply.status >= http.StatusBadRequest {
		out.Reason = reply.reason(t)
	}
	if row.Class == classPlan && reply.status == http.StatusCreated {
		var plan wire.CreatedPlan
		reply.data(t, &plan)
		out.PlanDecision = plan.Policy.Decision
	}
	out.NodeCommands = int(rig.runtime.commands.Load() - commandsBefore)
	for table, was := range before {
		if delta := rig.count(table) - was; delta != 0 {
			out.Created[table] = delta
		}
	}
	return out
}

func (rig *mcpRig) isKeyed(route string) bool {
	method, pattern, _ := strings.Cut(route, " ")
	for _, rt := range rig.server.Routes() {
		if rt.Method == method && rt.Pattern == pattern {
			return rt.Keyed
		}
	}
	return false
}

// sendRow is send, except that a stream is read only up to its response
// headers: the request is cancelled once they arrive.
func (rig *mcpRig) sendRow(via mcpRigTransport, method, path, body string, stream bool, headers []string) mcpRigReply {
	if !stream {
		return rig.send(via, method, path, body, headers...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	return rig.sendCtx(ctx, via, method, path, body, headers, true)
}

func TestMCPMatrixListsEveryRoute(t *testing.T) {
	rig := newMCPRig(t, false)
	listed := map[string]mcpMatrixRow{}
	for _, row := range loadMCPMatrix(t) {
		if _, dup := listed[row.Route]; dup {
			t.Errorf("route %q is listed twice", row.Route)
		}
		listed[row.Route] = row
	}
	served := map[string]api.Route{}
	for _, rt := range rig.server.Routes() {
		key := rt.Method + " " + rt.Pattern
		served[key] = rt
		if _, ok := listed[key]; !ok {
			t.Errorf("route %q is served but has no matrix row: decide what an mcp client gets from it", key)
		}
	}
	for key, row := range listed {
		rt, ok := served[key]
		if !ok {
			t.Errorf("row %q matches no served route", key)
			continue
		}
		if err := mcpMatrixClassMatches(rt, row.Class); err != "" {
			t.Errorf("row %q: %s", key, err)
		}
	}
}

// mcpMatrixClassMatches ties a row's class to the route's catalog action, so a
// route re-mapped to another action cannot keep a stale row.
func mcpMatrixClassMatches(rt api.Route, class mcpMatrixClass) string {
	if strings.HasPrefix(rt.Action, "exempt:") {
		if class != classExempt {
			return "the route is " + rt.Action + " but its class is " + string(class)
		}
		return ""
	}
	spec, known := policy.Lookup(rt.Action)
	switch {
	case !known:
		return "action " + rt.Action + " is not in the catalog"
	case class == classExempt:
		return "class exempt on catalog action " + rt.Action
	case class == classGovernance:
		if rt.Action != policy.ActionApprovalGrant && rt.Action != policy.ActionApprovalReject && rt.Action != policy.ActionJobResolve {
			return "class governance on " + rt.Action
		}
	case class == classForbidden:
		if !spec.CredentialIssuing && !slices.Contains([]string{"mcp_client.register", "mcp_client.delete", "identity.write", "role_binding.write"}, rt.Action) {
			return "class forbidden on " + rt.Action + ", which an mcp actor may be granted"
		}
	case class == classPlan:
		if rt.Action != "plan.create" {
			return "class plan on " + rt.Action
		}
	case class == classQuery:
		if spec.Mode != policy.ModeQuery {
			return "class query on " + rt.Action + ", which is not a query"
		}
	case class == classWrite:
		if spec.Mode == policy.ModeQuery {
			return "class write on " + rt.Action + ", which is a query"
		}
	}
	return ""
}

// ---- the matrix ------------------------------------------------------------

var mcpMatrixModes = []struct {
	name   string
	writes bool
}{{"writes off", false}, {"writes on", true}}

var mcpMatrixTransports = []mcpRigTransport{mcpRigSocket, mcpRigInProcess}

// assertRow sends the row's request and compares what happened with what the
// row expects in this writes mode.
func (rig *mcpRig) assertRow(via mcpRigTransport, row mcpMatrixRow) {
	t := rig.t
	t.Helper()
	want := row.want(rig.writes)
	got := rig.attempt(via, row)
	if got.Status != want.Status || got.Reason != want.Reason {
		t.Errorf("%s: status %d reason %q, want %d %q", row.Route, got.Status, got.Reason, want.Status, want.Reason)
	}
	if got.PlanDecision != want.PlanDecision {
		t.Errorf("%s: stored plan verdict %q, want %q", row.Route, got.PlanDecision, want.PlanDecision)
	}
	if got.NodeCommands != want.NodeCommands {
		t.Errorf("%s: %d commands reached a node, want %d", row.Route, got.NodeCommands, want.NodeCommands)
	}
	if !maps.Equal(got.Created, nonNilCounts(want.Created)) {
		t.Errorf("%s: left behind %v, want %v", row.Route, got.Created, want.Created)
	}
}

func nonNilCounts(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

// TestMCPRouteMatrix is the whole matrix: every route, both modes, both
// transports, each on a fresh rig.
func TestMCPRouteMatrix(t *testing.T) {
	rows := loadMCPMatrix(t)
	for _, mode := range mcpMatrixModes {
		for _, via := range mcpMatrixTransports {
			t.Run(mode.name+" over "+string(via), func(t *testing.T) {
				rig := newMCPRig(t, mode.writes)
				for _, row := range rows {
					rig.assertRow(via, row)
				}
			})
		}
	}
}

// mcpMatrixRowOf is the row of a route, for the tests that name one scenario.
func mcpMatrixRowOf(t *testing.T, route string) mcpMatrixRow {
	t.Helper()
	for _, row := range loadMCPMatrix(t) {
		if row.Route == route {
			return row
		}
	}
	t.Fatalf("no matrix row for %q", route)
	return mcpMatrixRow{}
}

// eachMCPMode runs check on a fresh rig for every mode and transport.
func eachMCPMode(t *testing.T, check func(t *testing.T, rig *mcpRig, via mcpRigTransport)) {
	t.Helper()
	for _, mode := range mcpMatrixModes {
		for _, via := range mcpMatrixTransports {
			t.Run(mode.name+" over "+string(via), func(t *testing.T) {
				check(t, newMCPRig(t, mode.writes), via)
			})
		}
	}
}

func TestAPlanIsStoredWithTheDenialAsItsVerdictWhileWritesAreOff(t *testing.T) {
	row := mcpMatrixRowOf(t, "POST "+wire.PathPlans)
	if row.Off.Status != http.StatusCreated || row.Off.PlanDecision != "deny" || row.Off.Created["plans"] != 1 {
		t.Fatalf("the plan row does not describe a stored, denied plan: %+v", row.Off)
	}
	eachMCPMode(t, func(t *testing.T, rig *mcpRig, via mcpRigTransport) { rig.assertRow(via, row) })
}

func TestSubmittingAPlanFailsWithNoJobWhileWritesAreOff(t *testing.T) {
	row := mcpMatrixRowOf(t, "POST "+wire.PathPlanSubmit)
	if row.Off.Status != http.StatusForbidden || row.Off.Reason != smerr.ReasonMCPWritesDisabled || row.Off.Created["jobs"] != 0 {
		t.Fatalf("the submit row does not describe a refusal without a job: %+v", row.Off)
	}
	eachMCPMode(t, func(t *testing.T, rig *mcpRig, via mcpRigTransport) { rig.assertRow(via, row) })
}

func TestAnMCPClientCanNeverApproveOrRejectAJob(t *testing.T) {
	for _, route := range []string{"POST " + wire.PathJobApprove, "POST " + wire.PathJobReject} {
		row := mcpMatrixRowOf(t, route)
		if row.Off.Status != http.StatusForbidden || row.On.Status != http.StatusForbidden {
			t.Fatalf("%s must be refused in both modes: %+v %+v", route, row.Off, row.On)
		}
		eachMCPMode(t, func(t *testing.T, rig *mcpRig, via mcpRigTransport) {
			rig.assertRow(via, row)
			if count := rig.count("job_approvals"); count != 0 {
				t.Errorf("%s left %d approval decisions", route, count)
			}
		})
	}
}

func TestAnMCPClientCanNeverIssueAnAPITokenEvenWithAFullGrant(t *testing.T) {
	row := mcpMatrixRowOf(t, "POST "+wire.PathTokens)
	for _, want := range []mcpMatrixWant{row.Off, row.On} {
		if want.Status != http.StatusForbidden || want.Reason != smerr.ReasonMCPActionForbidden || len(want.Created) != 0 {
			t.Fatalf("the token row must be MCP_ACTION_FORBIDDEN with no rows in both modes: %+v", want)
		}
	}
	eachMCPMode(t, func(t *testing.T, rig *mcpRig, via mcpRigTransport) {
		before := rig.count("api_tokens")
		rig.assertRow(via, row)
		if after := rig.count("api_tokens"); after != before {
			t.Errorf("api_tokens went from %d to %d rows", before, after)
		}
	})
}

func TestADeploymentIsRefusedWithNoRowWhileWritesAreOff(t *testing.T) {
	row := mcpMatrixRowOf(t, "POST "+wire.PathDeployments)
	if row.Off.Status != http.StatusForbidden || row.Off.Reason != smerr.ReasonMCPWritesDisabled || len(row.Off.Created) != 0 {
		t.Fatalf("the deployment row does not describe a refusal with no rows: %+v", row.Off)
	}
	eachMCPMode(t, func(t *testing.T, rig *mcpRig, via mcpRigTransport) { rig.assertRow(via, row) })
}

func TestARefusedWriteNeverSendsACommandToANode(t *testing.T) {
	for _, via := range mcpMatrixTransports {
		t.Run(string(via), func(t *testing.T) {
			rig := newMCPRig(t, false)
			for _, row := range loadMCPMatrix(t) {
				got := rig.attempt(via, row)
				if got.Status == http.StatusForbidden && got.NodeCommands != 0 {
					t.Errorf("%s was refused yet sent %d commands to a node", row.Route, got.NodeCommands)
				}
			}
		})
	}
}
