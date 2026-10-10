//go:build fixtures

package m1

import (
	"slices"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const keyBudget = 50 * time.Millisecond

// Scenario: un nodo offline no congela la TUI.
// Given an unreachable node among the managed ones, when the TUI refreshes,
// then the rest keeps answering (< 50 ms per key) and the node shows an
// error/stale state.
func TestM1_OfflineNodeDoesNotFreezeTUI(t *testing.T) {
	nodes := startNodes(t, fixture.Options{}, fixture.Options{}, fixture.Options{})
	healthy, frozen := nodes[0], nodes[2]
	in := newInstance(t, instanceOptions{FastRefresh: true})
	in.startDaemon()
	api := in.client()

	a := addNode(t, api, in, healthy, "node-a", "staging")
	b := addNode(t, api, in, nodes[1], "node-b", "staging")
	c := addNode(t, api, in, frozen, "node-c", "staging")
	for _, n := range []wire.Node{a, b, c} {
		waitDiscovered(t, api, n.ID)
	}

	if err := frozen.Pause(t.Context()); err != nil {
		t.Fatalf("pause node-c: %v", err)
	}
	t.Cleanup(func() { _ = frozen.Unpause(t.Context()) })

	// Sample GET /nodes while the refresher's dial to the paused node hangs.
	var latencies []time.Duration
	sample := func() {
		start := monotonicNow()
		if _, err := api.ListNodes(t.Context(), wire.NodeQuery{}); err != nil {
			t.Fatalf("list nodes during the hung dial: %v", err)
		}
		latencies = append(latencies, time.Since(start))
		time.Sleep(20 * time.Millisecond)
	}
	for !isUnreachable(t, api, c.ID) && len(latencies) < 2000 {
		sample()
	}
	for range 200 {
		sample()
	}
	slices.Sort(latencies)
	p99 := latencies[len(latencies)*99/100]
	t.Logf("GET /nodes during the hung dial: %d samples, p50 %s, p99 %s, max %s",
		len(latencies), latencies[len(latencies)/2], p99, latencies[len(latencies)-1])
	if p99 >= keyBudget {
		t.Errorf("GET /nodes p99 = %s during a hung dial, want < %s", p99, keyBudget)
	}

	got, err := api.GetNode(t.Context(), c.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reachability != domain.ReachabilityUnreachable && !got.Stale {
		t.Errorf("paused node reports reachability %s, stale %t; want an error or stale state", got.Reachability, got.Stale)
	}

	tui := newTUI(t, api, 120, 40)
	tui.waitScreen("1 warning", 20*time.Second)

	t.Run("every key answers within the budget", func(t *testing.T) {
		keys := []string{"2", "down", "up", "enter", "esc", "3", "4", "5", "1", "?", "esc"}
		var slowest time.Duration
		for i := range 110 {
			key := keys[i%len(keys)]
			took := tui.pressTimed(key)
			slowest = max(slowest, took)
			if took >= keyBudget {
				t.Errorf("key %d (%q) took %s, want < %s", i, key, took, keyBudget)
			}
		}
		t.Logf("slowest of 110 keys: %s", slowest)
	})

	t.Run("the paused node shows a stale state in the TUI", func(t *testing.T) {
		tui.press("2")
		for range 5 {
			tui.press("up")
		}
		tui.press("down")
		tui.press("down")
		tui.press("enter")
		if !tui.screenHas("node-c") {
			t.Fatalf("the third node is not selected:\n%s", tui.screen())
		}
		tui.waitScreen("stale", 10*time.Second)
	})
}

func isUnreachable(t *testing.T, api *client.Client, id domain.ID) bool {
	t.Helper()
	n, err := api.GetNode(t.Context(), id, false)
	return err == nil && (n.Reachability == domain.ReachabilityUnreachable || n.Stale)
}
