package database

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ---- instance and settings -------------------------------------------------

func TestInstanceIsWrittenOnce(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		_, err := GetInstance(ctx, q)
		wantError(t, err, smerr.CodeNotFound, "")

		first := Instance{ID: f.ids.NewID(), Name: "home", CreatedAt: testEpoch}
		noErr(t, CreateInstance(ctx, q, first))
		wantError(t, CreateInstance(ctx, q, Instance{ID: f.ids.NewID(), Name: "other", CreatedAt: testEpoch}),
			smerr.CodeConflict, "")

		if got := must(GetInstance(ctx, q)); got != first {
			t.Fatalf("instance = %+v, want %+v", got, first)
		}
	})
}

func TestSettingsUpsertAndPrefixListing(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		put := func(key, value string, at time.Time) error {
			return PutSetting(ctx, q, Setting{Key: key, Value: json.RawMessage(value), UpdatedAt: at})
		}
		noErr(t, put("active_kek_id", `"a"`, testEpoch))
		noErr(t, put("kek_check.a", `"x"`, testEpoch))
		noErr(t, put("kek_check.b", `"y"`, testEpoch))
		noErr(t, put("active_kek_id", `"b"`, testEpoch.Add(time.Minute)))

		got := must(GetSetting(ctx, q, "active_kek_id"))
		if string(got.Value) != `"b"` || !got.UpdatedAt.Equal(testEpoch.Add(time.Minute)) {
			t.Fatalf("upserted setting = %+v", got)
		}
		_, err := GetSetting(ctx, q, "missing")
		wantError(t, err, smerr.CodeNotFound, "")

		keys := keysOf(must(ListSettings(ctx, q, "kek_check.")))
		if !slices.Equal(keys, []string{"kek_check.a", "kek_check.b"}) {
			t.Fatalf("prefix listing = %v", keys)
		}
		if all := must(ListSettings(ctx, q, "")); len(all) != 3 {
			t.Fatalf("empty prefix lists %d settings, want 3", len(all))
		}
		wantError(t, put("bad", `{not json`, testEpoch), smerr.CodeInvalidArgument, "")
		wantError(t, put("", `1`, testEpoch), smerr.CodeInvalidArgument, "")
	})
}

func keysOf(settings []Setting) []string {
	keys := make([]string, len(settings))
	for i, s := range settings {
		keys[i] = s.Key
	}
	return keys
}

// ---- node addresses --------------------------------------------------------

func address(id domain.ID, addr string, source AddressSource, seen time.Time) NodeAddress {
	return NodeAddress{ID: id, Address: addr, Family: FamilyIPv4, Scope: ScopePrivate, Source: source, LastSeenAt: seen}
}

func TestReplaceNodeAddressesKeepsIDsAndOtherSources(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		keep := address(f.ids.NewID(), "10.0.0.1", SourceProbe, testEpoch)
		drop := address(f.ids.NewID(), "10.0.0.2", SourceProbe, testEpoch)
		fromProvider := address(f.ids.NewID(), "192.0.2.9", SourceProvider, testEpoch)
		noErr(t, ReplaceNodeAddresses(ctx, q, n.ID, SourceProbe, []NodeAddress{keep, drop}))
		noErr(t, ReplaceNodeAddresses(ctx, q, n.ID, SourceProvider, []NodeAddress{fromProvider}))

		later := testEpoch.Add(time.Hour)
		kept := address(f.ids.NewID(), "10.0.0.1", SourceProbe, later)
		kept.Preferred = true
		added := address(f.ids.NewID(), "fd00::1", SourceProbe, later)
		added.Family = FamilyIPv6
		noErr(t, ReplaceNodeAddresses(ctx, q, n.ID, SourceProbe, []NodeAddress{kept, added}))

		got := must(ListNodeAddresses(ctx, q, n.ID))
		var seen []string
		for _, a := range got {
			seen = append(seen, a.Address)
		}
		if !slices.Equal(seen, []string{"10.0.0.1", "192.0.2.9", "fd00::1"}) {
			t.Fatalf("addresses = %v, want the preferred first, the provider one kept, 10.0.0.2 dropped", seen)
		}
		if got[0].ID != keep.ID || !got[0].Preferred || !got[0].LastSeenAt.Equal(later) {
			t.Fatalf("known address was not updated in place: %+v (original id %s)", got[0], keep.ID)
		}
	})
}

func TestReplaceNodeAddressesRejectsInvalidInput(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		bad := address(f.ids.NewID(), "10.0.0.1", SourceProbe, testEpoch)
		bad.Scope = "galactic"
		wantError(t, ReplaceNodeAddresses(ctx, q, n.ID, SourceProbe, []NodeAddress{bad}), smerr.CodeInvalidArgument, "")

		wrongSource := address(f.ids.NewID(), "10.0.0.1", SourceProvider, testEpoch)
		wantError(t, ReplaceNodeAddresses(ctx, q, n.ID, SourceProbe, []NodeAddress{wrongSource}), smerr.CodeInvalidArgument, "")
		if got := must(ListNodeAddresses(ctx, q, n.ID)); len(got) != 0 {
			t.Fatalf("rejected input stored %d addresses", len(got))
		}
	})
}

// ---- idempotency -----------------------------------------------------------

func TestIdempotencyRecordReplaysExactBytes(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		who := f.identity(ctx, q, domain.ActorHuman, "alice")
		envelope := []byte("{\"data\": {\"id\":\"x\"},\n \"meta\":null}\n") // odd spacing and a trailing newline on purpose
		rec := IdempotencyRecord{
			IdentityID: who.ID, Key: "k1", Method: "POST", Path: "/api/v1/nodes/ssh",
			RequestHash: "sha256:aa", StatusCode: 201, ResponseJSON: envelope,
			CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(24 * time.Hour),
		}
		noErr(t, InsertIdempotencyRecord(ctx, q, rec))

		got := must(GetIdempotencyRecord(ctx, q, who.ID, "k1"))
		if !bytes.Equal(got.ResponseJSON, envelope) {
			t.Fatalf("response bytes = %q, want %q", got.ResponseJSON, envelope)
		}
		if got.StatusCode != 201 || got.RequestHash != "sha256:aa" || got.JobID != nil || !got.ExpiresAt.Equal(rec.ExpiresAt) {
			t.Fatalf("record = %+v", got)
		}
		wantError(t, InsertIdempotencyRecord(ctx, q, rec), smerr.CodeConflict, "")

		_, err := GetIdempotencyRecord(ctx, q, who.ID, "other-key")
		wantError(t, err, smerr.CodeNotFound, "")
		bob := f.identity(ctx, q, domain.ActorHuman, "bob")
		_, err = GetIdempotencyRecord(ctx, q, bob.ID, "k1")
		wantError(t, err, smerr.CodeNotFound, "") // keys are scoped to the identity
	})
}

func TestIdempotencyRecordRollsBackWithItsMutation(t *testing.T) {
	db := migratedTest(t)
	ids := newFixture(t).ids
	who := Identity{ID: ids.NewID(), ActorType: domain.ActorHuman, Subject: "alice", CreatedAt: testEpoch}
	noErr(t, db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		return CreateIdentity(ctx, tx, who)
	}))

	_ = db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		noErr(t, InsertIdempotencyRecord(ctx, tx, IdempotencyRecord{
			IdentityID: who.ID, Key: "k", Method: "POST", Path: "/p", RequestHash: "h", StatusCode: 200,
			ResponseJSON: []byte("{}"), CreatedAt: testEpoch, ExpiresAt: testEpoch.Add(time.Hour),
		}))
		return os.ErrInvalid // the mutation failed after the record was staged
	})
	_, err := GetIdempotencyRecord(context.Background(), db.Reader(), who.ID, "k")
	wantError(t, err, smerr.CodeNotFound, "")
}

func TestSweepIdempotencyRecordsRemovesOnlyExpired(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		who := f.identity(ctx, q, domain.ActorHuman, "alice")
		for key, expires := range map[string]time.Time{
			"old": testEpoch.Add(-time.Second), "boundary": testEpoch, "fresh": testEpoch.Add(time.Second),
		} {
			noErr(t, InsertIdempotencyRecord(ctx, q, IdempotencyRecord{
				IdentityID: who.ID, Key: key, Method: "POST", Path: "/p", RequestHash: "h", StatusCode: 200,
				ResponseJSON: []byte("{}"), CreatedAt: testEpoch.Add(-time.Hour), ExpiresAt: expires,
			}))
		}
		if removed := must(SweepIdempotencyRecords(ctx, q, testEpoch)); removed != 2 {
			t.Fatalf("removed = %d, want the expired and the boundary record", removed)
		}
		if _, err := GetIdempotencyRecord(ctx, q, who.ID, "fresh"); err != nil {
			t.Fatalf("fresh record gone: %v", err)
		}
	})
}

// ---- secrets ---------------------------------------------------------------

func secret(f *fixture, name string, kek domain.ID, ciphertext string) SecretRecord {
	return SecretRecord{
		ID: f.ids.NewID(), Name: name, EnvelopeVersion: 1, KEKID: kek,
		WrappedDEK: []byte{0, 1, 2, 0xff}, Ciphertext: []byte(ciphertext),
		Metadata: map[string]any{"fingerprint": "SHA256:abc"}, CreatedAt: testEpoch,
	}
}

func TestSecretVersionsAreAssignedPerName(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		kek := f.ids.NewID()
		v1 := must(PutSecretVersion(ctx, q, secret(f, "ssh/default", kek, "one")))
		v2 := must(PutSecretVersion(ctx, q, secret(f, "ssh/default", kek, "two")))
		other := must(PutSecretVersion(ctx, q, secret(f, "other", kek, "x")))
		if v1.Version != 1 || v2.Version != 2 || other.Version != 1 {
			t.Fatalf("versions = %d, %d, %d; want 1, 2, 1", v1.Version, v2.Version, other.Version)
		}

		latest := must(GetSecret(ctx, q, "ssh/default", 0))
		if latest.Version != 2 || string(latest.Ciphertext) != "two" {
			t.Fatalf("latest = %+v", latest)
		}
		pinned := must(GetSecret(ctx, q, "ssh/default", 1))
		if string(pinned.Ciphertext) != "one" || !bytes.Equal(pinned.WrappedDEK, []byte{0, 1, 2, 0xff}) ||
			pinned.KEKID != kek || pinned.Metadata["fingerprint"] != "SHA256:abc" || pinned.RotatedAt != nil {
			t.Fatalf("pinned = %+v", pinned)
		}
		_, err := GetSecret(ctx, q, "ssh/default", 3)
		wantError(t, err, smerr.CodeNotFound, "")
		_, err = GetSecret(ctx, q, "absent", 0)
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestSecretRejectsUnknownEnvelopeVersion(t *testing.T) {
	f := newFixture(t)
	err := f.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		r := secret(f, "ssh/default", f.ids.NewID(), "x")
		r.EnvelopeVersion = 2
		_, err := PutSecretVersion(ctx, tx, r)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("err = %v, want envelope_version CHECK failure", err)
	}
}

func TestReferencedKEKIDsCoversSecretsAndSettings(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		if ids := must(ReferencedKEKIDs(ctx, q)); len(ids) != 0 {
			t.Fatalf("fresh database references %v", ids)
		}
		a, b, c := domain.ID("kek-a"), domain.ID("kek-b"), domain.ID("kek-c")
		must(PutSecretVersion(ctx, q, secret(f, "s1", a, "x")))
		must(PutSecretVersion(ctx, q, secret(f, "s2", a, "x")))
		must(PutSecretVersion(ctx, q, secret(f, "s3", b, "x")))
		noErr(t, PutSetting(ctx, q, Setting{Key: "active_kek_id", Value: json.RawMessage(`"kek-c"`), UpdatedAt: testEpoch}))
		noErr(t, PutSetting(ctx, q, Setting{Key: "kek_check.kek-c", Value: json.RawMessage(`"x"`), UpdatedAt: testEpoch}))
		noErr(t, PutSetting(ctx, q, Setting{Key: "kek_check.kek-a", Value: json.RawMessage(`"x"`), UpdatedAt: testEpoch}))
		noErr(t, PutSetting(ctx, q, Setting{Key: "unrelated", Value: json.RawMessage(`"kek-z"`), UpdatedAt: testEpoch}))

		if got := must(ReferencedKEKIDs(ctx, q)); !slices.Equal(got, []domain.ID{a, b, c}) {
			t.Fatalf("referenced = %v, want [a b c] sorted without duplicates", got)
		}
	})
}

// ---- interactive sessions --------------------------------------------------

func newSession(f *fixture, ctx context.Context, q Querier) (InteractiveSession, Identity, domain.Node) {
	who := f.identity(ctx, q, domain.ActorHuman, "alice")
	node := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
	s := must(CreateInteractiveSession(ctx, q, InteractiveSession{
		ID: f.ids.NewID(), IdentityID: who.ID, NodeID: node.ID, Tool: ToolShell, CreatedAt: testEpoch,
	}))
	return s, who, node
}

func TestInteractiveSessionFirstEndWins(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		s, who, node := newSession(f, ctx, q)
		if s.State != SessionIssued || s.ExitCode != nil || s.EndedAt != nil {
			t.Fatalf("new session = %+v", s)
		}

		three := 3
		first := testEpoch.Add(time.Minute)
		ended, wasFirst := must2(EndInteractiveSession(ctx, q, s.ID, who.ID, node.ID,
			SessionEnd{Reason: EndedExited, ExitCode: &three, At: first}))
		if !wasFirst || ended.State != SessionEnded || ended.ExitCode == nil || *ended.ExitCode != 3 ||
			ended.EndReason != EndedExited || !ended.EndedAt.Equal(first) {
			t.Fatalf("first end = %+v (first %v)", ended, wasFirst)
		}

		zero := 0
		again, wasFirst := must2(EndInteractiveSession(ctx, q, s.ID, who.ID, node.ID,
			SessionEnd{Reason: EndedLaunchFailed, ExitCode: &zero, At: first.Add(time.Hour)}))
		if wasFirst || again.EndReason != EndedExited || *again.ExitCode != 3 || !again.EndedAt.Equal(first) {
			t.Fatalf("second end changed the session: %+v (first %v)", again, wasFirst)
		}
	})
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic("unexpected error: " + err.Error())
	}
	return a, b
}

func TestInteractiveSessionEndIsBoundToCallerAndNode(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		s, who, node := newSession(f, ctx, q)
		mallory := f.identity(ctx, q, domain.ActorHuman, "mallory")
		elsewhere := f.node(ctx, q, f.provider(ctx, q, "p2"), "db-1")
		end := SessionEnd{Reason: EndedExited, At: testEpoch}

		_, _, err := EndInteractiveSession(ctx, q, s.ID, mallory.ID, node.ID, end)
		wantError(t, err, smerr.CodeNotFound, "")
		_, _, err = EndInteractiveSession(ctx, q, s.ID, who.ID, elsewhere.ID, end)
		wantError(t, err, smerr.CodeNotFound, "")
		_, _, err = EndInteractiveSession(ctx, q, f.ids.NewID(), who.ID, node.ID, end)
		wantError(t, err, smerr.CodeNotFound, "")
		_, _, err = EndInteractiveSession(ctx, q, s.ID, who.ID, node.ID, SessionEnd{Reason: EndedAbandoned, At: testEpoch})
		wantError(t, err, smerr.CodeInvalidArgument, "")

		if got := must(GetInteractiveSession(ctx, q, s.ID)); got.State != SessionIssued {
			t.Fatalf("refused ends changed the session: %+v", got)
		}
	})
}

func TestAbandonStaleSessions(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		old, who, node := newSession(f, ctx, q)
		recent := must(CreateInteractiveSession(ctx, q, InteractiveSession{
			ID: f.ids.NewID(), IdentityID: who.ID, NodeID: node.ID, Tool: ToolBtop, CreatedAt: testEpoch.Add(time.Hour),
		}))
		done := must(CreateInteractiveSession(ctx, q, InteractiveSession{
			ID: f.ids.NewID(), IdentityID: who.ID, NodeID: node.ID, Tool: ToolTmux, CreatedAt: testEpoch,
		}))
		must2(EndInteractiveSession(ctx, q, done.ID, who.ID, node.ID, SessionEnd{Reason: EndedExited, At: testEpoch}))

		at := testEpoch.Add(25 * time.Hour)
		abandoned := must(AbandonStaleSessions(ctx, q, testEpoch, at))
		if !slices.Equal(abandoned, []domain.ID{old.ID}) {
			t.Fatalf("abandoned = %v, want only %s", abandoned, old.ID)
		}
		got := must(GetInteractiveSession(ctx, q, old.ID))
		if got.State != SessionAbandoned || got.EndReason != EndedAbandoned || !got.EndedAt.Equal(at) {
			t.Fatalf("abandoned session = %+v", got)
		}
		if still := must(GetInteractiveSession(ctx, q, recent.ID)); still.State != SessionIssued {
			t.Fatalf("recent session = %+v", still)
		}
		if ended := must(GetInteractiveSession(ctx, q, done.ID)); ended.State != SessionEnded {
			t.Fatalf("ended session = %+v", ended)
		}

		_, err := CreateInteractiveSession(ctx, q, InteractiveSession{
			ID: f.ids.NewID(), IdentityID: who.ID, NodeID: node.ID, Tool: "vim", CreatedAt: testEpoch,
		})
		wantError(t, err, smerr.CodeInvalidArgument, "")
	})
}

// ---- runtimes and services discovered --------------------------------------

func discoveredService(f *fixture, rt domain.Runtime, native string, kind domain.ServiceKind, status string) domain.Service {
	return domain.Service{
		ID: f.ids.NewID(), RuntimeID: rt.ID, NodeID: rt.NodeID, NativeID: native, Name: native,
		Kind: string(kind), Status: status, Health: "healthy",
		Metadata: map[string]any{"n": native}, LastSeenAt: &testEpoch,
	}
}

func TestUpsertRuntimeKeepsTheStoredID(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		first := must(UpsertRuntime(ctx, q, domain.Runtime{
			ID: f.ids.NewID(), NodeID: n.ID, Type: "docker", NativeID: "docker", Version: "27", Status: "running",
		}))
		again := must(UpsertRuntime(ctx, q, domain.Runtime{
			ID: f.ids.NewID(), NodeID: n.ID, Type: "docker", NativeID: "docker", Version: "28", Status: "degraded",
			Metadata: map[string]any{"k": "v"}, LastSeenAt: &testEpoch,
		}))
		if again.ID != first.ID || again.Version != "28" || again.Status != "degraded" ||
			again.Metadata["k"] != "v" || again.LastSeenAt == nil {
			t.Fatalf("upserted runtime = %+v (first %s)", again, first.ID)
		}
		if rts := must(ListRuntimes(ctx, q, n.ID)); len(rts) != 1 {
			t.Fatalf("runtimes = %d, want 1", len(rts))
		}
	})
}

func TestUpsertServiceRefreshesObservationsOnly(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		rt := must(UpsertRuntime(ctx, q, domain.Runtime{ID: f.ids.NewID(), NodeID: n.ID, Type: "systemd", NativeID: "systemd"}))
		first := must(UpsertService(ctx, q, discoveredService(f, rt, "nginx.service", domain.ServiceSystemdUnit, "active")))
		if first.SpecRevision != 1 {
			t.Fatalf("new service revision = %d", first.SpecRevision)
		}

		refreshed := discoveredService(f, rt, "nginx.service", domain.ServiceSystemdUnit, "failed")
		refreshed.Health = "unhealthy"
		again := must(UpsertService(ctx, q, refreshed))
		if again.ID != first.ID || again.Status != "failed" || again.Health != "unhealthy" || again.SpecRevision != 1 {
			t.Fatalf("refreshed service = %+v (first %s)", again, first.ID)
		}

		bad := discoveredService(f, rt, "x", "container", "running")
		_, err := UpsertService(ctx, q, bad)
		wantError(t, err, smerr.CodeInvalidArgument, "")
	})
}

func TestRetireMissingServicesMarksGoneAndReviveRestoresThem(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		rt := must(UpsertRuntime(ctx, q, domain.Runtime{ID: f.ids.NewID(), NodeID: n.ID, Type: "systemd", NativeID: "systemd"}))
		other := must(UpsertRuntime(ctx, q, domain.Runtime{ID: f.ids.NewID(), NodeID: n.ID, Type: "docker", NativeID: "docker"}))
		stays := must(UpsertService(ctx, q, discoveredService(f, rt, "a.service", domain.ServiceSystemdUnit, "active")))
		leaves := must(UpsertService(ctx, q, discoveredService(f, rt, "b.service", domain.ServiceSystemdUnit, "active")))
		untouched := must(UpsertService(ctx, q, discoveredService(f, other, "web", domain.ServiceDockerContainer, "running")))

		retired := must(RetireMissingServices(ctx, q, rt.ID, []string{"a.service"}))
		if len(retired) != 1 || retired[0].ID != leaves.ID {
			t.Fatalf("retired = %+v, want only b.service", retired)
		}
		if got := must(GetService(ctx, q, leaves.ID)); got.Status != StatusGone || got.Health != "" {
			t.Fatalf("retired service = %+v", got)
		}
		if got := must(GetService(ctx, q, stays.ID)); got.Status != "active" {
			t.Fatalf("seen service = %+v", got)
		}
		if got := must(GetService(ctx, q, untouched.ID)); got.Status != "running" {
			t.Fatalf("other runtime's service = %+v", got)
		}
		if again := must(RetireMissingServices(ctx, q, rt.ID, []string{"a.service"})); len(again) != 0 {
			t.Fatalf("second retire reported %+v, want nothing new", again)
		}

		back := must(UpsertService(ctx, q, discoveredService(f, rt, "b.service", domain.ServiceSystemdUnit, "active")))
		if back.ID != leaves.ID || back.Status != "active" {
			t.Fatalf("reappeared service = %+v, want the same id and observed status", back)
		}
		if all := must(RetireMissingServices(ctx, q, rt.ID, nil)); len(all) != 2 {
			t.Fatalf("retire with nothing seen retired %d services, want 2", len(all))
		}
	})
}

func TestRetireMissingRuntimesCascadesToServices(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		systemd := must(UpsertRuntime(ctx, q, domain.Runtime{ID: f.ids.NewID(), NodeID: n.ID, Type: "systemd", NativeID: "systemd", Status: "running"}))
		docker := must(UpsertRuntime(ctx, q, domain.Runtime{ID: f.ids.NewID(), NodeID: n.ID, Type: "docker", NativeID: "docker", Status: "running"}))
		web := must(UpsertService(ctx, q, discoveredService(f, docker, "web", domain.ServiceDockerContainer, "running")))
		unit := must(UpsertService(ctx, q, discoveredService(f, systemd, "a.service", domain.ServiceSystemdUnit, "active")))

		retired := must(RetireMissingRuntimes(ctx, q, n.ID, []RuntimeKey{{"systemd", "systemd"}}))
		if len(retired) != 1 || retired[0].ID != docker.ID || retired[0].Status != StatusGone {
			t.Fatalf("retired runtimes = %+v, want docker", retired)
		}
		if got := must(GetRuntime(ctx, q, docker.ID)); got.Status != StatusGone {
			t.Fatalf("docker runtime = %+v", got)
		}
		if got := must(GetService(ctx, q, web.ID)); got.Status != StatusGone {
			t.Fatalf("service of the retired runtime = %+v", got)
		}
		if got := must(GetService(ctx, q, unit.ID)); got.Status != "active" {
			t.Fatalf("service of the kept runtime = %+v", got)
		}
		if again := must(RetireMissingRuntimes(ctx, q, n.ID, []RuntimeKey{{"systemd", "systemd"}})); len(again) != 0 {
			t.Fatalf("second retire reported %+v", again)
		}
	})
}

func TestServicesByRuntimeUseAnIndex(t *testing.T) {
	db := migratedTest(t)
	rows, err := db.Reader().QueryContext(context.Background(),
		`EXPLAIN QUERY PLAN SELECT id FROM services WHERE runtime_id = 'r'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	noErr(t, rows.Err())
	if joined := strings.Join(plan, "; "); !strings.Contains(joined, "USING") || strings.Contains(joined, "SCAN services") {
		t.Fatalf("query plan = %q, want an index search on runtime_id", joined)
	}
}

// ---- capability and observation reads --------------------------------------

func TestGetNodeCapabilityReturnsMetadata(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		n := f.node(ctx, q, f.provider(ctx, q, "p"), "web-1")
		noErr(t, SetNodeCapability(ctx, q, n.ID, NodeCapability{
			Capability: "node.setup", Available: true, CheckedAt: testEpoch,
			Metadata: map[string]any{"setup_version": float64(1), "docker_access": true},
		}))
		got := must(GetNodeCapability(ctx, q, n.ID, "node.setup"))
		if !got.Available || got.Metadata["setup_version"] != float64(1) || got.Metadata["docker_access"] != true {
			t.Fatalf("capability = %+v", got)
		}
		_, err := GetNodeCapability(ctx, q, n.ID, "node.ssh")
		wantError(t, err, smerr.CodeNotFound, "")
	})
}

func TestLatestObservationsPickTheNewestPerResource(t *testing.T) {
	f := newFixture(t)
	f.tx(func(ctx context.Context, q Querier) {
		p := f.provider(ctx, q, "p")
		a, b := f.node(ctx, q, p, "a"), f.node(ctx, q, p, "b")
		record := func(node domain.ID, kind, value string, at time.Time, expires *time.Time) {
			noErr(t, RecordObservation(ctx, q, Observation{
				ID: f.ids.NewID(), ResourceType: domain.ResourceNode, ResourceID: node, Kind: kind,
				Value: json.RawMessage(value), ObservedAt: at, ExpiresAt: expires,
			}))
		}
		expired := testEpoch.Add(-time.Hour)
		record(a.ID, "metrics", `{"cpu":1}`, testEpoch, nil)
		record(a.ID, "metrics", `{"cpu":2}`, testEpoch.Add(time.Minute), &expired)
		record(a.ID, "probe", `{"os":"linux"}`, testEpoch.Add(time.Hour), nil)
		record(b.ID, "metrics", `{"cpu":9}`, testEpoch, nil)
		record(b.ID, "metrics", `{"cpu":8}`, testEpoch, nil) // same instant: the later id wins

		latest := must(LatestObservations(ctx, q, domain.ResourceNode, "metrics"))
		if len(latest) != 2 || string(latest[a.ID].Value.(json.RawMessage)) != `{"cpu":2}` ||
			string(latest[b.ID].Value.(json.RawMessage)) != `{"cpu":8}` {
			t.Fatalf("latest metrics = %+v", latest)
		}
		if exp := latest[a.ID].ExpiresAt; exp == nil || !exp.Equal(expired) {
			t.Fatalf("expired observation must still be returned, with its expiry: %+v", latest[a.ID])
		}

		one := must(LatestObservation(ctx, q, domain.ResourceRef{Type: domain.ResourceNode, ID: a.ID}, "probe"))
		if string(one.Value.(json.RawMessage)) != `{"os":"linux"}` {
			t.Fatalf("latest probe = %+v", one)
		}
		_, err := LatestObservation(ctx, q, domain.ResourceRef{Type: domain.ResourceNode, ID: b.ID}, "probe")
		wantError(t, err, smerr.CodeNotFound, "")
		if none := must(LatestObservations(ctx, q, domain.ResourceService, "metrics")); len(none) != 0 {
			t.Fatalf("other resource type returned %+v", none)
		}
	})
}

// ---- inspect ---------------------------------------------------------------

func TestInspect(t *testing.T) {
	ctx := context.Background()
	latest, err := LatestSchemaVersion()
	if err != nil || latest < 2 {
		t.Fatalf("LatestSchemaVersion = %d, %v; want at least 2", latest, err)
	}

	t.Run("missing file is reported and not created", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent.db")
		got, err := Inspect(ctx, path)
		if err != nil || got.Exists {
			t.Fatalf("Inspect = %+v, %v", got, err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("Inspect created the database: %v", err)
		}
	})

	t.Run("unmigrated file has no schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.db")
		db, err := Open(ctx, path, Options{})
		noErr(t, err)
		noErr(t, db.Close())
		got, err := Inspect(ctx, path)
		if err != nil || !got.Exists || got.HasSchema || got.SchemaVersion != 0 || got.IntegrityFindings != nil {
			t.Fatalf("Inspect = %+v, %v", got, err)
		}
	})

	t.Run("migrated file reports its version and leaves it unchanged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sm.db")
		db, err := Open(ctx, path, Options{})
		noErr(t, err)
		noErr(t, db.Migrate(ctx))
		defer db.Close()
		got, err := Inspect(ctx, path)
		if err != nil || !got.HasSchema || got.SchemaVersion != latest || got.IntegrityFindings != nil {
			t.Fatalf("Inspect = %+v, %v", got, err)
		}
		if err := db.WithWriteTx(ctx, func(ctx context.Context, tx *Tx) error { return nil }); err != nil {
			t.Fatalf("Inspect left the writer unusable: %v", err)
		}
	})

	t.Run("corrupt file is an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "junk.db")
		noErr(t, os.WriteFile(path, bytes.Repeat([]byte("not sqlite "), 400), 0o600))
		if _, err := Inspect(ctx, path); err == nil {
			t.Fatal("Inspect accepted a file that is not a database")
		}
	})
}

// A single-statement version computation must hold under concurrent writers.
func TestSecretVersionsDoNotCollideAcrossConcurrentWriters(t *testing.T) {
	db := migratedTest(t)
	ids := newFixture(t).ids
	const writers = 8
	var wg sync.WaitGroup
	versions := make(chan int, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.WithWriteTx(context.Background(), func(ctx context.Context, tx *Tx) error {
				r, err := PutSecretVersion(ctx, tx, SecretRecord{
					ID: ids.NewID(), Name: "ssh/default", EnvelopeVersion: 1, KEKID: "k",
					WrappedDEK: []byte{1}, Ciphertext: []byte{2}, CreatedAt: testEpoch,
				})
				versions <- r.Version
				return err
			})
			noErr(t, err)
		}()
	}
	wg.Wait()
	close(versions)
	var got []int
	for v := range versions {
		got = append(got, v)
	}
	slices.Sort(got)
	for i, v := range got {
		if v != i+1 {
			t.Fatalf("versions = %v, want 1..%d", got, writers)
		}
	}
}
