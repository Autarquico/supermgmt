package tui

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func newHarnessWith(t *testing.T, api API, o Options, w, h int) *harness {
	t.Helper()
	o.Timeout, o.Location = time.Second, time.UTC
	hs := &harness{t: t, m: New(api, o)}
	hs.send(tea.WindowSizeMsg{Width: w, Height: h})
	return hs
}

var remoteSettings = Settings{Profile: "home", Server: "https://mgmt.example.com"}

func TestProvidersScreenListsProvidersReadOnly(t *testing.T) {
	h := newHarness(t, newFake(), 80, 24)
	h.start()
	h.press("6")
	if h.m.screen != screenProviders {
		t.Fatalf("screen = %s", screenTitles[h.m.screen])
	}
	view := h.view()
	for _, want := range []string{"Providers", "NAME", "ssh", "static", "local", "api", "ready"} {
		contains(t, view, want)
	}
}

func TestProvidersScreenLoadsOnlyWhenOpened(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	h.start()
	if api.count("ListProviders") != 0 {
		t.Fatalf("providers were loaded for the dashboard")
	}
	h.press("6")
	if api.count("ListProviders") != 1 {
		t.Errorf("ListProviders called %d times, want 1", api.count("ListProviders"))
	}
}

func TestSettingsScreenShowsModeProfileServerAndIdentity(t *testing.T) {
	h := newHarnessWith(t, newFake(), Options{Settings: remoteSettings}, 80, 24)
	h.start()
	h.press("7")
	view := h.view()
	for _, want := range []string{"Settings", "local", "home", "https://mgmt.example.com", "alex", "admin"} {
		contains(t, view, want)
	}
}

func TestSettingsScreenOfTheLocalDaemonSaysSo(t *testing.T) {
	h := newHarness(t, newFake(), 80, 24)
	h.start()
	h.press("7")
	contains(t, h.view(), "local daemon")
}

func TestGoldenProvidersAndSettings(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		keys string
	}{
		{"providers_80x24", Options{}, "6"},
		{"settings_80x24", Options{}, "7"},
		{"settings_remote_80x24", Options{Settings: remoteSettings, Follow: func(context.Context, func(wire.Event) error) error { return nil }}, "7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarnessWith(t, newFake(), tc.opts, 80, 24)
			if tc.opts.Follow != nil {
				h.m.followState = followLive
			}
			h.start()
			h.press(tc.keys)
			assertGolden(t, tc.name, h.view(), 80, 24)
		})
	}
}

// ---- live updates ---------------------------------------------------------------------

func TestStreamedEventRefreshesTheCurrentScreen(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	h.start()
	before := api.count("ListNodes")
	h.drain(h.send(streamEventMsg{event: wire.Event{Seq: 3}}))
	if got := api.count("ListNodes"); got != before+1 {
		t.Errorf("ListNodes called %d times after an event, want %d", got, before+1)
	}
}

func TestStreamedEventsDoNotPileUpRequests(t *testing.T) {
	api := newFake()
	h := newHarness(t, api, 80, 24)
	_ = h.m.Init() // issued, never answered: every key stays loading
	for range 20 {
		h.drain(h.send(streamEventMsg{event: wire.Event{Seq: 1}}))
	}
	if n := api.count("ListNodes"); n != 0 {
		t.Errorf("events re-issued %d requests while one was in flight", n)
	}
}

func TestEndedStreamIsShownAndPollingContinues(t *testing.T) {
	api := newFake()
	h := newHarnessWith(t, api, Options{Follow: func(context.Context, func(wire.Event) error) error { return nil }}, 100, 24)
	h.m.followState = followLive
	h.start()
	h.drain(h.send(streamEndedMsg{err: smerr.New(smerr.CodeUnauthenticated, "", "token revoked")}))
	if h.m.followState != followStopped {
		t.Errorf("followState = %q", h.m.followState)
	}
	contains(t, h.view(), "live updates stopped")
	contains(t, h.view(), "token revoked")

	before := api.count("ListNodes")
	h.drain(h.send(tickMsg{}))
	if api.count("ListNodes") != before+1 {
		t.Errorf("the periodic refresh stopped with the stream")
	}
	h.press("7")
	contains(t, h.view(), "live stream stopped")
}

func TestFollowRelaysEventsAndReportsTheEnd(t *testing.T) {
	var mu sync.Mutex
	var got []tea.Msg
	send := func(m tea.Msg) { mu.Lock(); defer mu.Unlock(); got = append(got, m) }
	failure := errors.New("access lost")
	follow(context.Background(), func(_ context.Context, handle func(wire.Event) error) error {
		for seq := int64(1); seq <= 2; seq++ {
			if err := handle(wire.Event{Seq: seq}); err != nil {
				return err
			}
		}
		return failure
	}, send)
	if len(got) != 3 {
		t.Fatalf("got %d messages, want 2 events and the end: %v", len(got), got)
	}
	if e, ok := got[0].(streamEventMsg); !ok || e.event.Seq != 1 {
		t.Errorf("first message = %#v", got[0])
	}
	if end, ok := got[2].(streamEndedMsg); !ok || !errors.Is(end.err, failure) {
		t.Errorf("last message = %#v", got[2])
	}
}

func TestFollowStaysSilentWhenTheProgramEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var sent int
	follow(ctx, func(ctx context.Context, _ func(wire.Event) error) error {
		cancel()
		return ctx.Err()
	}, func(tea.Msg) { sent++ })
	if sent != 0 {
		t.Errorf("a cancelled stream sent %d messages", sent)
	}
}
