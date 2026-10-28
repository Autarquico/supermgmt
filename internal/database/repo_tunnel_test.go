package database

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/migrations"
)

func (f *fixture) tunnelNode(ctx context.Context, q Querier, name string) domain.Node {
	return f.node(ctx, q, f.provider(ctx, q, "p-"+name), name)
}

func (f *fixture) tunnelOp(ctx context.Context, q Querier, node domain.Node, kind TunnelOperationKind) TunnelOperation {
	f.t.Helper()
	return must(CreateTunnelOperation(ctx, q, TunnelOperation{
		ID: f.ids.NewID(), NodeID: node.ID, Kind: kind, AccountID: "acct", Zone: "example.com",
		InstanceID: "inst", Hostname: node.Name + ".example.com", CreatedAt: testEpoch,
	}))
}

func TestTunnelOperationLifecycle(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node := f.tunnelNode(ctx, q, "n1")
		op := f.tunnelOp(ctx, q, node, TunnelEnable)
		if op.Generation != 1 || op.Phase != PhaseStarted || !op.PhaseStartedAt.Equal(testEpoch) {
			t.Fatalf("created = %+v", op)
		}
		later := testEpoch.Add(time.Minute)
		op = must(AdvanceTunnelPhase(ctx, q, op.ID, 1, PhaseStarted, PhaseTunnelCreated, TunnelObjects{TunnelID: "tun"}, later))
		if op.Phase != PhaseTunnelCreated || op.Objects.TunnelID != "tun" || !op.PhaseStartedAt.Equal(later) {
			t.Fatalf("advanced = %+v", op)
		}
		op = must(AdvanceTunnelPhase(ctx, q, op.ID, 1, PhaseTunnelCreated, PhaseDNSCreated, TunnelObjects{DNSRecordID: "dns"}, later))
		if op.Objects != (TunnelObjects{TunnelID: "tun", DNSRecordID: "dns"}) {
			t.Fatalf("objects = %+v", op.Objects)
		}
		active := must(ActiveTunnelOperation(ctx, q, node.ID))
		if active.ID != op.ID {
			t.Fatalf("active = %s, want %s", active.ID, op.ID)
		}
		if all := must(ListActiveTunnelOperations(ctx, q)); len(all) != 1 {
			t.Fatalf("active list = %d", len(all))
		}

		op = must(AdvanceTunnelPhase(ctx, q, op.ID, 1, PhaseDNSCreated, PhaseCommitted, TunnelObjects{}, later))
		if !op.Phase.Finished() {
			t.Fatalf("phase = %s", op.Phase)
		}
		_, err := ActiveTunnelOperation(ctx, q, node.ID)
		wantError(t, err, smerr.CodeNotFound, "")
		if all := must(ListActiveTunnelOperations(ctx, q)); len(all) != 0 {
			t.Fatalf("active list after commit = %d", len(all))
		}
		next := f.tunnelOp(ctx, q, node, TunnelDisable)
		if next.Generation != 2 {
			t.Fatalf("second generation = %d, want 2", next.Generation)
		}
		if got := must(ListTunnelOperations(ctx, q, node.ID)); len(got) != 2 || got[0].Generation != 2 {
			t.Fatalf("history = %+v", got)
		}
	})
}

func TestAdvanceTunnelPhaseRefusesStaleExpectation(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		op := f.tunnelOp(ctx, q, f.tunnelNode(ctx, q, "n1"), TunnelEnable)
		must(AdvanceTunnelPhase(ctx, q, op.ID, 1, PhaseStarted, PhaseTokenReady, TunnelObjects{}, testEpoch))

		_, err := AdvanceTunnelPhase(ctx, q, op.ID, 1, PhaseStarted, PhaseTunnelCreated, TunnelObjects{TunnelID: "late"}, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = AdvanceTunnelPhase(ctx, q, op.ID, 2, PhaseTokenReady, PhaseTunnelCreated, TunnelObjects{TunnelID: "late"}, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = AdvanceTunnelPhase(ctx, q, "01970000-0000-7000-8000-0000000000ff", 1, PhaseStarted, PhaseTokenReady, TunnelObjects{}, testEpoch)
		wantError(t, err, smerr.CodeNotFound, "")

		got := must(GetTunnelOperation(ctx, q, op.ID))
		if got.Phase != PhaseTokenReady || got.Objects.TunnelID != "" {
			t.Fatalf("a refused advance changed the record: %+v", got)
		}
	})
}

func TestTunnelOperationHaltAndResume(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		op := f.tunnelOp(ctx, q, f.tunnelNode(ctx, q, "n1"), TunnelEnable)
		op = must(AdvanceTunnelPhase(ctx, q, op.ID, 1, PhaseStarted, PhaseIngressSet, TunnelObjects{TunnelID: "tun"}, testEpoch))

		_, err := HaltTunnelOperation(ctx, q, op.ID, 1, PhaseStarted, PhaseFailed, "x", testEpoch)
		wantError(t, err, smerr.CodeConflict, "")
		_, err = HaltTunnelOperation(ctx, q, op.ID, 1, PhaseIngressSet, PhaseDone, "x", testEpoch)
		wantError(t, err, smerr.CodeInvalidArgument, "")

		op = must(HaltTunnelOperation(ctx, q, op.ID, 1, PhaseIngressSet, PhaseConflict, "name taken", testEpoch))
		if op.Phase != PhaseConflict || op.HaltedPhase != PhaseIngressSet || op.LastError != "name taken" {
			t.Fatalf("halted = %+v", op)
		}
		if _, err := ActiveTunnelOperation(ctx, q, op.NodeID); err != nil {
			t.Fatalf("a halted operation must keep holding the node: %v", err)
		}
		op = must(AdvanceTunnelPhase(ctx, q, op.ID, 1, PhaseConflict, PhaseIngressSet, TunnelObjects{}, testEpoch))
		if op.Phase != PhaseIngressSet || op.HaltedPhase != "" || op.LastError != "" {
			t.Fatalf("resumed = %+v", op)
		}
	})
}

func TestOnlyOneActiveTunnelOperationPerNode(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		a := f.tunnelNode(ctx, q, "a")
		b := f.node(ctx, q, f.provider(ctx, q, "p2"), "b")
		first := f.tunnelOp(ctx, q, a, TunnelEnable)
		f.tunnelOp(ctx, q, b, TunnelEnable) // another node is unaffected

		_, err := CreateTunnelOperation(ctx, q, TunnelOperation{
			ID: f.ids.NewID(), NodeID: a.ID, Kind: TunnelDisable, AccountID: "acct", Zone: "z", InstanceID: "i", CreatedAt: testEpoch,
		})
		wantError(t, err, smerr.CodeConflict, "")

		must(HaltTunnelOperation(ctx, q, first.ID, 1, PhaseStarted, PhaseFailed, "boom", testEpoch))
		_, err = CreateTunnelOperation(ctx, q, TunnelOperation{
			ID: f.ids.NewID(), NodeID: a.ID, Kind: TunnelDisable, AccountID: "acct", Zone: "z", InstanceID: "i", CreatedAt: testEpoch,
		})
		wantError(t, err, smerr.CodeConflict, "")
	})
}

func TestTunnelOperationSchemaRejects(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		node := f.tunnelNode(ctx, q, "n1")
		op := f.tunnelOp(ctx, q, node, TunnelEnable)
		const insert = `INSERT INTO tunnel_operations (id, node_id, generation, operation, phase, halted_phase, phase_started_at,
			account_id, zone, instance_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, 'a', 'z', 'i', 1, 1)`
		for name, c := range map[string]struct {
			gen        int
			op, phase  string
			halted     any
			wantSubstr string
		}{
			"unknown phase":           {2, "enable", "teleported", nil, "CHECK"},
			"disable phase on enable": {2, "enable", "switched", nil, "CHECK"},
			"enable phase on disable": {2, "disable", "verified", nil, "CHECK"},
			"unknown operation":       {2, "rotate", "started", nil, "CHECK"},
			"halted without phase":    {2, "enable", "failed", nil, "CHECK"},
			"halted phase on running": {2, "enable", "started", "started", "CHECK"},
			"unknown halted phase":    {2, "enable", "failed", "teleported", "CHECK"},
			"foreign halted phase":    {2, "enable", "failed", "switched", "CHECK"},
			"generation zero":         {0, "disable", "started", nil, "CHECK"},
		} {
			_, err := q.ExecContext(ctx, insert, f.ids.NewID(), node.ID, c.gen, c.op, c.phase, c.halted)
			if err == nil || !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("%s: err = %v, want %s failure", name, err, c.wantSubstr)
			}
		}
		_, err := q.ExecContext(ctx, insert, f.ids.NewID(), "01970000-0000-7000-8000-0000000000ff", 5, "enable", "done", nil)
		if err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("done on enable: err = %v", err)
		}
		_, err = q.ExecContext(ctx, insert, f.ids.NewID(), "01970000-0000-7000-8000-0000000000ff", 5, "disable", "done", nil)
		if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
			t.Errorf("unknown node: err = %v, want FOREIGN KEY failure", err)
		}

		// recorded IDs, node and generation never change
		must(AdvanceTunnelPhase(ctx, q, op.ID, 1, PhaseStarted, PhaseTunnelCreated, TunnelObjects{TunnelID: "tun"}, testEpoch))
		for _, stmt := range []string{
			`UPDATE tunnel_operations SET tunnel_id = 'other'`,
			`UPDATE tunnel_operations SET generation = 9`,
			`UPDATE tunnel_operations SET operation = 'disable'`,
		} {
			if _, err := q.ExecContext(ctx, stmt); err == nil || !strings.Contains(err.Error(), "keeps its identity") {
				t.Errorf("%s: err = %v", stmt, err)
			}
		}
	})
}

func TestCloudflareStateConditionalUpdates(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		_, err := GetCloudflareState(ctx, q)
		wantError(t, err, smerr.CodeNotFound, "")

		state := CloudflareState{
			AccountID: "acct", Token: CloudflareToken{ID: "t1", Name: "supermgmt-inst", CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(24 * time.Hour)},
			ServicePolicyID: "p-svc", OwnersPolicyID: "p-own",
		}
		_, err = SaveCloudflareState(ctx, q, state, 3, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")

		saved := must(SaveCloudflareState(ctx, q, state, 0, testEpoch))
		if saved.Revision != 1 || saved.Rotation != RotationIdle || saved.Pending != nil || saved.Token.ID != "t1" ||
			!saved.Token.ExpiresAt.Equal(state.Token.ExpiresAt) {
			t.Fatalf("saved = %+v", saved)
		}
		_, err = SaveCloudflareState(ctx, q, state, 0, testEpoch)
		wantError(t, err, smerr.CodeConflict, "")

		later := testEpoch.Add(time.Hour)
		saved.Rotation = RotationCreated
		saved.Pending = &CloudflareToken{ID: "t2", Name: "supermgmt-inst", CreatedAt: later, ExpiresAt: later.Add(24 * time.Hour)}
		rotating := must(SaveCloudflareState(ctx, q, saved, 1, later))
		if rotating.Revision != 2 || rotating.Pending == nil || rotating.Pending.ID != "t2" ||
			!rotating.CreatedAt.Equal(testEpoch) || !rotating.UpdatedAt.Equal(later) {
			t.Fatalf("rotating = %+v", rotating)
		}
		_, err = SaveCloudflareState(ctx, q, saved, 1, later) // stale writer
		wantError(t, err, smerr.CodeConflict, "")

		done := rotating
		done.Token, done.Pending, done.Rotation = *rotating.Pending, nil, RotationIdle
		done = must(SaveCloudflareState(ctx, q, done, 2, later))
		if done.Revision != 3 || done.Token.ID != "t2" || done.Pending != nil {
			t.Fatalf("done = %+v", done)
		}

		bad := done
		bad.Rotation = RotationRetiring // a rotation phase without a pending token
		if _, err := SaveCloudflareState(ctx, q, bad, 3, later); err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("rotation without pending token: err = %v", err)
		}
	})
}

// A database at schema 6 keeps its data and gains the tunnel tables with 000007.
func TestMigration000007KeepsExistingData(t *testing.T) {
	ctx := context.Background()
	all, err := loadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, filepath.Join(t.TempDir(), "sm.db"), Options{Clock: domaintest.NewFakeClock(testEpoch)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, m := range all {
		if m.version <= 6 {
			if err := db.apply(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	err = db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO identities (id, actor_type, subject, created_at) VALUES (?, 'human', 'alice', 1)`, idA)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate from version 6: %v", err)
	}
	for query, want := range map[string]int{
		`SELECT count(*) FROM identities WHERE subject = 'alice'`:                                1,
		`SELECT count(*) FROM schema_migrations WHERE version = 7`:                               1,
		`SELECT max(version) FROM schema_migrations`:                                             all[len(all)-1].version,
		`SELECT count(*) FROM tunnel_operations`:                                                 0,
		`SELECT count(*) FROM cloudflare_state`:                                                  0,
		`SELECT count(*) FROM pragma_foreign_key_check`:                                          0,
		`SELECT count(*) FROM pragma_table_list WHERE name = 'tunnel_operations' AND strict = 1`: 1,
		`SELECT count(*) FROM pragma_table_list WHERE name = 'cloudflare_state' AND strict = 1`:  1,
	} {
		if got := scalar[int](t, db.Reader(), query); got != want {
			t.Errorf("%s = %d, want %d", query, got, want)
		}
	}
}
