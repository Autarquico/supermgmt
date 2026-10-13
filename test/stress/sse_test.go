//go:build stress

package stress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api"
	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	sseStreamsPerIdentity = 4
	sseWait               = 30 * time.Second
	sseTokenCreated       = "token.created"
)

type sseRig struct {
	t       *testing.T
	db      *database.DB
	clock   *domaintest.FakeClock
	auth    *app.AuthService
	server  *api.Server
	baseURL string
	http    *http.Client
}

func newSSERig(t *testing.T, stream api.StreamOptions) *sseRig {
	t.Helper()
	ctx := context.Background()
	clock, ids := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)), domain.UUIDv7Generator{}
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "sm.db"), database.Options{Clock: clock})
	sseMust(t, err)
	t.Cleanup(func() { _ = db.Close() })
	sseMust(t, db.Migrate(ctx))
	pol, err := policy.Default()
	sseMust(t, err)
	cfg := app.Config{DB: db, Clock: clock, IDs: ids, Policy: pol, Credentials: auth.CredentialStatus{DB: db, Clock: clock}}

	reval, err := app.NewRevalidator(cfg)
	sseMust(t, err)
	store, err := jobs.NewStore(jobs.Config{DB: db, Clock: clock, IDs: ids, Revalidator: reval, LockPlanner: app.LockPlanner{}})
	sseMust(t, err)
	svc := sseServices(t, cfg, store)
	authService, err := app.NewAuthService(cfg, app.AuthOptions{Tokens: auth.Minter{}})
	sseMust(t, err)
	svc.Auth = authService
	holdService, err := app.NewHold(cfg, store)
	sseMust(t, err)
	svc.Hold = holdService

	server, err := api.New(api.Options{
		Services: svc, IDs: ids, Resolver: auth.DBResolver{DB: db, Clock: clock}, DB: db, Clock: clock, Stream: stream,
	})
	sseMust(t, err)
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	sseMust(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	rig := &sseRig{
		t: t, db: db, clock: clock, auth: authService, server: server,
		baseURL: "http://" + listener.Addr().String(), http: &http.Client{},
	}
	t.Cleanup(rig.http.CloseIdleConnections)
	return rig
}

func sseServices(t *testing.T, cfg app.Config, store *jobs.Store) api.Services {
	t.Helper()
	plans, err := app.NewPlans(cfg, store)
	sseMust(t, err)
	approvals, err := app.NewApprovals(cfg, store)
	sseMust(t, err)
	governance, err := app.NewGovernance(cfg, store)
	sseMust(t, err)
	actions, err := app.NewServices(cfg, store)
	sseMust(t, err)
	queries, err := app.NewQueries(cfg, store, config.ModeServer)
	sseMust(t, err)
	inventory, err := app.NewInventory(cfg, app.InventoryOptions{Store: store, Connector: app.Connector{}, Mode: config.ModeServer})
	sseMust(t, err)
	sessions, err := app.NewSessions(cfg)
	sseMust(t, err)
	keys, err := api.NewSSHKeys(func(context.Context) (secrets.Identity, error) { return secrets.Identity{}, nil })
	sseMust(t, err)
	return api.Services{
		Plans: plans, Approvals: approvals, Governance: governance, Services: actions,
		Queries: queries, Inventory: inventory, Sessions: sessions, SSHKeys: keys,
	}
}

func sseMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// admin creates an admin identity with an API token and returns the token.
func (r *sseRig) admin() string {
	r.t.Helper()
	ctx, ids := context.Background(), domain.UUIDv7Generator{}
	identity := ids.NewID()
	sseMust(r.t, r.db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := database.CreateIdentity(ctx, tx, database.Identity{ID: identity, ActorType: domain.ActorHuman, Subject: identity.String(), CreatedAt: r.clock.Now()}); err != nil {
			return err
		}
		role, err := database.GetRoleByName(ctx, tx, "admin")
		if err != nil {
			return err
		}
		return database.CreateRoleBinding(ctx, tx, database.RoleBinding{ID: ids.NewID(), IdentityID: identity, RoleID: role.ID, CreatedAt: r.clock.Now()})
	}))
	issued, err := r.auth.CreateToken(ctx,
		app.Caller{ID: identity, Credential: domain.CredentialContext{Kind: domain.CredentialLocalSocket}},
		wire.CreateTokenRequest{Name: "stress", ExpiresAt: r.clock.Now().Add(time.Hour)})
	sseMust(r.t, err)
	return issued.Value
}

// createToken makes the server emit one token.created event.
func (r *sseRig) createToken(bearer, name string) error {
	body := `{"name":"` + name + `","expires_at":"` + r.clock.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, r.baseURL+wire.PathTokens, bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set(wire.HeaderAuthorization, "Bearer "+bearer)
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &sseStatusError{status: resp.StatusCode}
	}
	return nil
}

type sseStatusError struct{ status int }

func (e *sseStatusError) Error() string { return "unexpected status " + strconv.Itoa(e.status) }

// openStream returns the open response; status is whatever the server answered.
func (r *sseRig) openStream(bearer string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, r.baseURL+wire.PathEventStream, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(wire.HeaderAuthorization, "Bearer "+bearer)
	return r.http.Do(req)
}

// mustOpenStream opens a stream and consumes its ": stream open" greeting.
func (r *sseRig) mustOpenStream(bearer string) (*http.Response, *bufio.Scanner) {
	r.t.Helper()
	resp, err := r.openStream(bearer)
	sseMust(r.t, err)
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		r.t.Fatalf("open stream: status %d", resp.StatusCode)
	}
	r.t.Cleanup(func() { _ = resp.Body.Close() })
	lines := bufio.NewScanner(resp.Body)
	if !lines.Scan() || lines.Text() != ": stream open" {
		r.t.Fatalf("first line = %q, want the stream greeting", lines.Text())
	}
	return resp, lines
}

// sseSeen is what one reader observed on its stream.
type sseSeen struct {
	created int
	seqs    []int64
}

// sseCollect reads frames until it has seen want token.created events or the
// stream ends.
func sseCollect(lines *bufio.Scanner, want int) sseSeen {
	var seen sseSeen
	var id int64
	var isEvent bool
	for seen.created < want && lines.Scan() {
		switch line := lines.Text(); {
		case strings.HasPrefix(line, "id: "):
			id, _ = strconv.ParseInt(strings.TrimPrefix(line, "id: "), 10, 64)
		case strings.HasPrefix(line, "event: "):
			isEvent = line == "event: event"
		case strings.HasPrefix(line, "data: ") && isEvent:
			var event wire.Event
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) != nil {
				continue
			}
			seen.seqs = append(seen.seqs, id)
			if event.Action == sseTokenCreated {
				seen.created++
			}
		}
	}
	return seen
}

var sseFastStream = api.StreamOptions{
	Poll: 10 * time.Millisecond, Revalidate: time.Hour, Heartbeat: time.Hour, WriteTimeout: 500 * time.Millisecond,
	MaxPerIdentity: sseStreamsPerIdentity,
}

// ssePostEvents creates count tokens, concurrently from as many fresh admins as
// the per-identity write bucket needs (the bucket never refills on a fake clock).
func ssePostEvents(t *testing.T, rig *sseRig, namePrefix string, count int) {
	t.Helper()
	const perAdmin = 15
	posters := (count + perAdmin - 1) / perAdmin
	bearers := make([]string, posters)
	for i := range bearers {
		bearers[i] = rig.admin()
	}
	jobsRunConcurrently(posters, func(poster int) {
		for n := poster * perAdmin; n < min(count, (poster+1)*perAdmin); n++ {
			if err := rig.createToken(bearers[poster], namePrefix+strconv.Itoa(n)); err != nil {
				t.Errorf("create token %d: %v", n, err)
				return
			}
		}
	})
}

func TestEveryStreamReceivesEveryEventInOrderUnderConcurrentWrites(t *testing.T) {
	const watchers, events = 6, 36
	rig := newSSERig(t, sseFastStream)
	type reader struct {
		resp  *http.Response
		lines *bufio.Scanner
	}
	var readers []reader
	for range watchers {
		bearer := rig.admin()
		for range sseStreamsPerIdentity {
			resp, lines := rig.mustOpenStream(bearer)
			readers = append(readers, reader{resp, lines})
		}
	}

	results := make([]sseSeen, len(readers))
	var collecting sync.WaitGroup
	for i, rd := range readers {
		collecting.Add(1)
		go func() {
			defer collecting.Done()
			results[i] = sseCollect(rd.lines, events)
		}()
	}
	ssePostEvents(t, rig, "fanout-", events)

	finished := make(chan struct{})
	go func() { collecting.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(sseWait):
		for _, rd := range readers {
			_ = rd.resp.Body.Close()
		}
		<-finished
		t.Fatal("streams did not receive every event in time")
	}

	for i, seen := range results {
		if seen.created != events {
			t.Errorf("stream %d saw %d %s events, want %d", i, seen.created, sseTokenCreated, events)
		}
		for j := 1; j < len(seen.seqs); j++ {
			if seen.seqs[j] <= seen.seqs[j-1] {
				t.Errorf("stream %d: event ids %v are not strictly increasing", i, seen.seqs)
				break
			}
		}
	}
}

func TestAStalledConsumerNeitherStarvesOthersNorKeepsItsSlot(t *testing.T) {
	const events = 200
	rig := newSSERig(t, sseFastStream)
	stalledIdentity, healthy := rig.admin(), rig.admin()

	// The stalled identity opens every stream it may and then never reads.
	var stalled []*http.Response
	for range sseStreamsPerIdentity {
		resp, _ := rig.mustOpenStream(stalledIdentity)
		stalled = append(stalled, resp)
	}
	resp, err := rig.openStream(stalledIdentity)
	sseMust(t, err)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("stream beyond the per-identity limit: status %d, want 429", resp.StatusCode)
	}

	_, healthyLines := rig.mustOpenStream(healthy)
	seenCh := make(chan sseSeen, 1)
	go func() { seenCh <- sseCollect(healthyLines, events) }()
	ssePostEvents(t, rig, "stall-"+strings.Repeat("x", 40)+"-", events)

	select {
	case seen := <-seenCh:
		if seen.created != events {
			t.Errorf("healthy stream saw %d events, want %d", seen.created, events)
		}
	case <-time.After(sseWait):
		t.Fatal("a stalled consumer starved the healthy stream")
	}

	for _, resp := range stalled {
		_ = resp.Body.Close()
	}
	deadline := time.After(sseWait)
	for {
		reopened, err := rig.openStream(stalledIdentity)
		sseMust(t, err)
		_ = reopened.Body.Close()
		if reopened.StatusCode == http.StatusOK {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("slots of closed streams were not released: status %d", reopened.StatusCode)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestShutdownReturnsWhileStreamsAreOpenAndNobodyReads(t *testing.T) {
	rig := newSSERig(t, sseFastStream)
	for range 3 {
		bearer := rig.admin()
		for range sseStreamsPerIdentity {
			rig.mustOpenStream(bearer)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), sseWait)
	defer cancel()
	if err := rig.server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown with open streams: %v", err)
	}
}
