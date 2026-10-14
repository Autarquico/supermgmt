package app

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

func (f *fixture) setHold(held bool) {
	f.t.Helper()
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.SetRestoreHold(ctx, tx, held, f.clock.Now())
	})
}

func (f *fixture) newHold() *HoldService {
	f.t.Helper()
	h, err := NewHold(f.cfg, f.store)
	if err != nil {
		f.t.Fatalf("NewHold: %v", err)
	}
	return h
}

func isRestoreHold(err error) bool { return smerr.FromReason(smerr.ReasonRestoreHold, "").Is(err) }

func TestHoldLoadReadsThePersistedValueAndFailsClosed(t *testing.T) {
	f := newFixture(t)
	hold := f.newHold()
	sub, _ := f.submitReboot()
	f.approveToQuorum(sub.Job)
	ctx := context.Background()

	if held, err := hold.Load(ctx); err != nil || held {
		t.Fatalf("Load with no row = %v, %v; want false", held, err)
	}

	f.setHold(true)
	if held, err := hold.Load(ctx); err != nil || !held {
		t.Fatalf("Load with the hold set = %v, %v; want true", held, err)
	}
	if _, ok := f.claim(); ok {
		t.Error("a job was claimed while the hold is in force")
	}

	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		return database.PutSetting(ctx, tx, database.Setting{Key: database.SettingRestoreHold, Value: json.RawMessage(`"yes"`), UpdatedAt: f.clock.Now()})
	})
	held, err := hold.Load(ctx)
	if err == nil || !held {
		t.Errorf("Load of an unreadable value = %v, %v; want true and an error that refuses the start", held, err)
	}
	if _, ok := f.claim(); ok {
		t.Error("a job was claimed although the hold could not be read")
	}
	if err := hold.Guard(ctx, "node.add", f.caller(f.alice)); !isRestoreHold(err) {
		t.Errorf("Guard with an unreadable hold = %v, want the write refused", err)
	}

	f.setHold(false)
	if held, err := hold.Load(ctx); err != nil || held {
		t.Fatalf("Load after clearing = %v, %v", held, err)
	}
	if _, ok := f.claim(); !ok {
		t.Error("the claim gate stayed closed after the hold was cleared")
	}
}

func TestHoldGuardEnumeratesItsExceptions(t *testing.T) {
	f := newFixture(t)
	hold := f.newHold()
	f.setHold(true)
	ctx := context.Background()
	alice := f.caller(f.alice)

	cases := []struct {
		name    string
		action  string
		by      Caller
		allowed bool
	}{
		{"a user write", "node.add", alice, false},
		{"a user write with no action stamped", "", alice, false},
		{"an anonymous write for a named action", "node.add", Caller{}, false},
		{"job.resolve", policy.ActionJobResolve, alice, true},
		{"restore.complete", ActionRestoreComplete, Caller{Source: adminSocketSource}, true},
		{"no principal, no action: login, bootstrap, reconciliation, observation, sweeps", "", Caller{}, true},
		{"the admin socket issuing a bootstrap code", "", Caller{Source: adminSocketSource}, true},
	}
	for _, tc := range cases {
		err := hold.Guard(ctx, tc.action, tc.by)
		if tc.allowed && err != nil {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
		if !tc.allowed {
			wantError(t, err, smerr.CodeConflict, smerr.ReasonRestoreHold)
		}
	}
	f.setHold(false)
	if err := hold.Guard(ctx, "node.add", alice); err != nil {
		t.Errorf("Guard without a hold = %v", err)
	}
}

// TestEveryServiceWriteIsRefusedDuringHold drives each mutating entry point of
// the application services with a principal and checks the hold refuses it
// before anything is written, then that the same call is not the hold's
// doing once the hold is lifted.
func TestEveryServiceWriteIsRefusedDuringHold(t *testing.T) {
	n := newNodeFixture(t)
	auth := newAuth(t, n.fixture, nil)
	sessions, err := NewSessions(n.cfg)
	if err != nil {
		t.Fatal(err)
	}
	governance, err := NewGovernance(n.cfg, n.store)
	if err != nil {
		t.Fatal(err)
	}
	alice, admin := n.caller(n.alice), n.caller(n.admin)
	session := alice
	session.Credential = domain.CredentialContext{Kind: domain.CredentialSession, ID: "session-1"}
	missing := domain.ID("00000000-0000-7000-8000-00000000ffff")

	writes := []struct {
		name string
		run  func(ctx context.Context) error
	}{
		{"plan.create", func(ctx context.Context) error { _, err := n.plans.Create(ctx, alice, n.reboot()); return err }},
		{"plan.submit", func(ctx context.Context) error { _, err := n.plans.Submit(ctx, alice, missing, "h"); return err }},
		{"approval.grant", func(ctx context.Context) error {
			_, err := n.appr.Approve(ctx, alice, DecisionRequest{JobID: missing, PlanHash: "h"})
			return err
		}},
		{"approval.reject", func(ctx context.Context) error {
			_, err := n.appr.Reject(ctx, alice, DecisionRequest{JobID: missing, PlanHash: "h"})
			return err
		}},
		{"job.cancel", func(ctx context.Context) error { _, err := governance.Cancel(ctx, alice, missing, "h"); return err }},
		{"node.add", func(ctx context.Context) error {
			_, err := n.inv.AddSSHNode(ctx, admin, n.addRequest("web-9", ""))
			return err
		}},
		{"node.update", func(ctx context.Context) error {
			_, err := n.inv.UpdateNode(ctx, admin, missing, 1, NodePatch{})
			return err
		}},
		{"node.remove", func(ctx context.Context) error { _, err := n.inv.RemoveNode(ctx, admin, missing, 1); return err }},
		{"provider.register_local", func(ctx context.Context) error { _, err := n.inv.RegisterLocal(ctx, admin); return err }},
		{"service.restart", func(ctx context.Context) error {
			_, err := n.svcs.Act(ctx, alice, n.service.ID, domain.VerbRestart)
			return err
		}},
		{"session.open", func(ctx context.Context) error {
			_, _, err := sessions.Open(ctx, alice, n.node.ID, "shell")
			return err
		}},
		{"session.end", func(ctx context.Context) error {
			_, err := sessions.End(ctx, alice, n.node.ID, missing, EndSession{Reason: wire.EndExited})
			return err
		}},
		{"token.create", func(ctx context.Context) error {
			_, err := auth.CreateToken(ctx, admin, n.tokenRequest())
			return err
		}},
		{"token.revoke", func(ctx context.Context) error { return auth.RevokeToken(ctx, admin, missing) }},
		{"logout", func(ctx context.Context) error { return auth.Logout(ctx, session) }},
	}

	n.setHold(true)
	for _, w := range writes {
		before := len(n.events())
		err := w.run(WithAction(context.Background(), w.name))
		if !isRestoreHold(err) {
			t.Errorf("%s during hold = %v, want CONFLICT/RESTORE_HOLD", w.name, err)
		}
		if after := len(n.events()); after != before {
			t.Errorf("%s during hold wrote %d audit events", w.name, after-before)
		}
		if err := w.run(context.Background()); !isRestoreHold(err) {
			t.Errorf("%s during hold without a stamped action = %v, want CONFLICT/RESTORE_HOLD (fail closed)", w.name, err)
		}
	}

	n.setHold(false)
	for _, w := range writes {
		if err := w.run(WithAction(context.Background(), w.name)); isRestoreHold(err) {
			t.Errorf("%s after the hold was lifted is still refused: %v", w.name, err)
		}
	}
}

func TestJobResolveAndPrincipalLessWritesPassDuringHold(t *testing.T) {
	f := newFixture(t)
	governance, err := NewGovernance(f.cfg, f.store)
	if err != nil {
		t.Fatal(err)
	}
	f.setHold(true)
	ctx := context.Background()
	missing := domain.ID("00000000-0000-7000-8000-00000000ffff")

	_, err = governance.Resolve(WithAction(ctx, policy.ActionJobResolve), f.caller(f.admin), ResolveRequest{JobID: missing, PlanHash: "h"})
	if isRestoreHold(err) {
		t.Errorf("job.resolve was refused by the hold: %v", err)
	}
	_, err = governance.Resolve(ctx, f.caller(f.admin), ResolveRequest{JobID: missing, PlanHash: "h"})
	if !isRestoreHold(err) {
		t.Errorf("an unstamped resolve = %v; the hold fails closed for a principal without an action", err)
	}

	wrote := false
	err = f.plans.write(ctx, func(context.Context, *database.Tx) error { wrote = true; return nil })
	if err != nil || !wrote {
		t.Errorf("a write with no principal (reconciliation, sweeps, read audits, login) = %v, ran %v; want it to pass", err, wrote)
	}
}

func TestRefusedKeyedRequestStoresNoRecordAndRunsOnceTheHoldIsLifted(t *testing.T) {
	f := newFixture(t)
	by, runs := f.keyed(f.alice, "key-held", "hash-a")
	f.setHold(true)

	_, err := f.plans.Create(WithAction(context.Background(), "plan.create"), by, f.reboot())

	if !isRestoreHold(err) {
		t.Fatalf("Create = %v, want the hold", err)
	}
	if n := f.count(`SELECT count(*) FROM idempotency_records`); n != 0 || runs.Load() != 0 {
		t.Errorf("a refused request left %d idempotency records and ran its responder %d times", n, runs.Load())
	}
	f.setHold(false)
	if _, err := f.plans.Create(WithAction(context.Background(), "plan.create"), by, f.reboot()); err != nil || runs.Load() != 1 {
		t.Errorf("retry after the hold = %v, responder runs %d; want success and 1", err, runs.Load())
	}
}

func TestCompleteEndsTheHoldAuditedAndOpensTheClaimGate(t *testing.T) {
	f := newFixture(t)
	hold := f.newHold()
	sub, _ := f.submitReboot()
	f.approveToQuorum(sub.Job)
	f.setHold(true)
	ctx := context.Background()
	if _, err := hold.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.claim(); ok {
		t.Fatal("claimed during hold")
	}

	if err := hold.Complete(ctx, 1000); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if held, err := database.GetRestoreHold(ctx, f.db.Reader()); err != nil || held {
		t.Errorf("hold after Complete = %v, %v", held, err)
	}
	events := f.events(eventRestoreCompleted)
	if len(events) != 1 || events[0].Data["peer_uid"] != float64(1000) && events[0].Data["peer_uid"] != 1000 {
		t.Errorf("restore.completed events = %+v, want one naming the peer", events)
	}
	if _, ok := f.claim(); !ok {
		t.Error("the claim gate is still closed after Complete")
	}
	if err := hold.Complete(ctx, 1000); err != nil || len(f.events(eventRestoreCompleted)) != 1 {
		t.Errorf("a second Complete = %v with %d events; want a quiet no-op", err, len(f.events(eventRestoreCompleted)))
	}
}

// TestEveryWriteTransactionIsClassified keeps the guard honest: a new
// WithWriteTx in this package must be added here with the reason it does not
// pass through commit (and so not through the hold guard), so the choice is
// reviewed and the transport guard (Hold.Guard on every write route) knows
// what it is covering.
func TestEveryWriteTransactionIsClassified(t *testing.T) {
	classified := map[string]string{
		"commit":                                "the shared write path; guards the hold itself",
		"Prober.record":                         "observation write by the system (discovery), allowed during hold",
		"InstanceAudit.recordVersionTransition": "system audit at daemon start, before serving (ADR-0035)",
		"InstanceAudit.importPending":           "system import of offline downgrade audit at daemon start, before serving (ADR-0035)",
		"SecretsRepo.Put":                       "secrets storage under a service that authorizes the caller; covered by the transport guard",
		"SecretsRepo.PutSettings":               "settings storage under a service that authorizes the caller; covered by the transport guard",
		"SecretsKeyRepo.UpdateKeys":             "key rotation storage under KeyManager; covered by the transport guard",
		"SecretsRepo.PutStaged":                 "staging a secret import under KeyManager; covered by the transport guard",
		"SecretsRepo.ActivateStaged":            "activation by an approved job; jobs are never claimed during hold",
		"SecretsRepo.DeleteStaged":              "discarding a staged import; cleanup, allowed during hold",
	}
	found := map[string]bool{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !callsWithWriteTx(fn) {
				continue
			}
			name := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				name = receiverName(fn.Recv.List[0].Type) + "." + name
			}
			found[name] = true
			if _, known := classified[name]; !known {
				t.Errorf("%s (%s) opens a write transaction outside commit; classify it in this test and decide whether it needs the hold guard", name, file)
			}
		}
	}
	for name := range classified {
		if !found[name] {
			t.Errorf("%s is classified but no longer opens a write transaction; remove it from the list", name)
		}
	}
	if !slices.Contains(holdExceptions, policy.ActionJobResolve) {
		t.Error("job.resolve must stay on the hold exception list")
	}
}

func callsWithWriteTx(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithWriteTx" {
				found = true
			}
		}
		return !found
	})
	return found
}

func receiverName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return "?"
}
