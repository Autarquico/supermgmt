package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	m4AppShop   domain.ID = "0192a000-0000-7000-8000-00000000e001"
	m4AppDocs   domain.ID = "0192a000-0000-7000-8000-00000000e002"
	m4TargetStg domain.ID = "0192a000-0000-7000-8000-00000000f001"
	m4TargetPrd domain.ID = "0192a000-0000-7000-8000-00000000f002"
	m4DeployOne domain.ID = "0192a000-0000-7000-8000-000000001001"
	m4DeployTwo domain.ID = "0192a000-0000-7000-8000-000000001002"
	m4DeployTri domain.ID = "0192a000-0000-7000-8000-000000001003"
	m4DeployOrp domain.ID = "0192a000-0000-7000-8000-000000001004"
)

// m4API is the fixture API plus the M4 lists.
type m4API struct {
	*fakeAPI
	apps        []wire.App
	deployments []wire.Deployment
}

func (f *m4API) ListApps(ctx context.Context, _ wire.PageQuery) (wire.Page[wire.App], error) {
	if err := f.enter(ctx, "ListApps"); err != nil {
		return wire.Page[wire.App]{}, err
	}
	return wire.Page[wire.App]{Items: f.apps}, nil
}

func (f *m4API) ListDeployments(ctx context.Context, _ wire.PageQuery) (wire.Page[wire.Deployment], error) {
	if err := f.enter(ctx, "ListDeployments"); err != nil {
		return wire.Page[wire.Deployment]{}, err
	}
	return wire.Page[wire.Deployment]{Items: f.deployments}, nil
}

func newM4API() *m4API {
	return &m4API{
		fakeAPI: newFake(),
		apps: []wire.App{
			{
				ID: m4AppShop, Name: "shop", Repository: &wire.Repository{Owner: "acme", Name: "shop"},
				Targets: []wire.AppTarget{{ID: m4TargetStg, Environment: "staging"}, {ID: m4TargetPrd, Environment: "production"}},
			},
			{ID: m4AppDocs, Name: "docs"},
		},
		deployments: []wire.Deployment{
			{ID: m4DeployOne, Kind: "deploy", AppID: m4AppShop, AppTargetID: m4TargetStg, State: "succeeded", CommitSHA: "1111111aaaa", CreatedAt: epoch.Add(-3 * time.Hour)},
			{ID: m4DeployTwo, Kind: "deploy", AppID: m4AppShop, AppTargetID: m4TargetPrd, State: "failed", CommitSHA: "2222222bbbb", CreatedAt: epoch.Add(-2 * time.Hour)},
			{ID: m4DeployTri, Kind: "deploy", AppID: m4AppShop, AppTargetID: m4TargetPrd, State: "waiting_ci", CommitSHA: "3333333cccc", CreatedAt: epoch.Add(-time.Hour)},
			{ID: m4DeployOrp, Kind: "rollback", AppID: "0192a000-0000-7000-8000-00000000e999", AppTargetID: "0192a000-0000-7000-8000-00000000f999", State: "rolled_back", CommitSHA: "4444444dddd", CreatedAt: epoch.Add(-30 * time.Minute)},
		},
	}
}

// m4ListsRig drives the two list screens the way the Model will.
type m4ListsRig struct {
	h           *harness
	apps        appsScreen
	deployments deploymentsScreen
}

func newM4ListsRig(t *testing.T, api API) *m4ListsRig {
	t.Helper()
	return &m4ListsRig{h: newHarness(t, api, 80, 24)}
}

func (l *m4ListsRig) loadAll() {
	l.h.t.Helper()
	l.h.drain(l.apps.load(l.h.m))
	l.h.drain(l.deployments.load(l.h.m))
}

func (l *m4ListsRig) appsView() string {
	bw, bh := l.h.m.bodySize()
	return stripANSI(strings.Join(fitLines(l.apps.body(l.h.m, bw, bh), bw, bh), "\n"))
}

func (l *m4ListsRig) deploymentsView() string {
	bw, bh := l.h.m.bodySize()
	return stripANSI(strings.Join(fitLines(l.deployments.body(l.h.m, l.apps.items, bw, bh), bw, bh), "\n"))
}

func TestM4ListGoldens(t *testing.T) {
	l := newM4ListsRig(t, newM4API())
	l.loadAll()
	bw, bh := l.h.m.bodySize()
	assertGolden(t, "m4_apps", l.appsView(), bw, bh)
	assertGolden(t, "m4_deployments", l.deploymentsView(), bw, bh)
}

func TestM4DeploymentsListNewestFirstWithAppAndEnvironment(t *testing.T) {
	l := newM4ListsRig(t, newM4API())
	l.loadAll()
	view := l.deploymentsView()
	for _, want := range []string{"shop / production", "shop / staging"} {
		if !strings.Contains(view, want) {
			t.Errorf("view lacks %q:\n%s", want, view)
		}
	}
	if newest, oldest := strings.Index(view, "rollback"), strings.Index(view, "1111111"); newest > oldest {
		t.Errorf("newest deployment is listed after the oldest:\n%s", view)
	}
}

func TestM4UnknownAppTargetFallsBackToShortID(t *testing.T) {
	l := newM4ListsRig(t, newM4API())
	l.loadAll()
	if view := l.deploymentsView(); !strings.Contains(view, "0000f999") {
		t.Errorf("an orphan deployment should show its short target id:\n%s", view)
	}
}

func TestM4ListsSayWhenTheDaemonCannotServeThem(t *testing.T) {
	l := newM4ListsRig(t, newFake())
	if cmd := l.apps.load(l.h.m); cmd != nil {
		t.Fatal("a client without AppsAPI must not issue a load")
	}
	for name, view := range map[string]string{"apps": l.appsView(), "deployments": l.deploymentsView()} {
		if !strings.Contains(view, unavailableApps) {
			t.Errorf("%s view does not say it is unavailable:\n%s", name, view)
		}
	}
}

func TestM4SlowListingNeverBlocksTheTUI(t *testing.T) {
	api := newM4API()
	release := make(chan struct{})
	api.hook("ListApps", func(ctx context.Context) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	l := newM4ListsRig(t, api)
	l.h.m.opts.Timeout = 50 * time.Millisecond

	cmd := l.apps.load(l.h.m)
	answered := make(chan tea.Msg, 1)
	go func() { answered <- cmd() }()

	if view := l.appsView(); !strings.Contains(view, "loading…") {
		t.Errorf("while the listing is slow the screen should say it is loading:\n%s", view)
	}
	select {
	case msg := <-answered:
		l.h.drain(l.h.send(msg))
	case <-time.After(2 * time.Second):
		t.Fatal("the load did not give up at its timeout")
	}
	close(release)
	if view := l.appsView(); !strings.Contains(view, "cannot load") {
		t.Errorf("a timed-out listing should be reported:\n%s", view)
	}
}

func TestM4ListKeepsItsRowsAndSaysStaleWhenReloadFails(t *testing.T) {
	api := newM4API()
	l := newM4ListsRig(t, api)
	l.loadAll()

	api.hook("ListApps", func(context.Context) error { return errors.New("daemon went away") })
	api.hook("ListDeployments", func(context.Context) error { return errors.New("daemon went away") })
	l.loadAll()

	for name, view := range map[string]string{"apps": l.appsView(), "deployments": l.deploymentsView()} {
		if !strings.Contains(view, "[stale]") {
			t.Errorf("%s view is not marked stale:\n%s", name, view)
		}
		if !strings.Contains(view, "shop") {
			t.Errorf("%s view lost its rows:\n%s", name, view)
		}
	}
}

func TestM4ListFailureBeforeFirstLoadIsAnError(t *testing.T) {
	api := newM4API()
	api.hook("ListApps", func(context.Context) error { return errors.New("denied") })
	l := newM4ListsRig(t, api)
	l.loadAll()
	if view := l.appsView(); !strings.Contains(view, "cannot load: denied") || strings.Contains(view, "[stale]") {
		t.Errorf("a first failure is an error, not stale data:\n%s", view)
	}
}

func TestM4SelectionSurvivesReload(t *testing.T) {
	api := newM4API()
	l := newM4ListsRig(t, api)
	l.loadAll()
	l.apps.key(keyMsg("j"))
	if got := l.apps.items[l.apps.cur].Name; got != "docs" {
		t.Fatalf("cursor on %q, want docs", got)
	}
	api.apps = append([]wire.App{{ID: "0192a000-0000-7000-8000-00000000e003", Name: "alpha"}}, api.apps...)
	l.loadAll()
	if got := l.apps.items[l.apps.cur].Name; got != "docs" {
		t.Errorf("after a reload the cursor moved to %q, want docs", got)
	}
}

func TestM4EmptyListsPointToTheCommand(t *testing.T) {
	api := newM4API()
	api.apps, api.deployments = nil, nil
	l := newM4ListsRig(t, api)
	l.loadAll()
	if view := l.appsView(); !strings.Contains(view, "sm apps create") {
		t.Errorf("empty apps view:\n%s", view)
	}
	if view := l.deploymentsView(); !strings.Contains(view, "sm deploy") {
		t.Errorf("empty deployments view:\n%s", view)
	}
}

func TestM4DeploymentCursorMovesWithinTheList(t *testing.T) {
	l := newM4ListsRig(t, newM4API())
	l.loadAll()
	l.deployments.key(keyMsg("G"))
	if got := l.deployments.items[l.deployments.cur].ID; got != m4DeployOne {
		t.Errorf("G selected %s, want the oldest deployment", got)
	}
	l.deployments.key(keyMsg("k"))
	if got := l.deployments.items[l.deployments.cur].ID; got != m4DeployTwo {
		t.Errorf("k selected %s, want the next newer deployment", got)
	}
}
