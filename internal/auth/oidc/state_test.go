package oidc

import (
	"context"
	"strconv"
	"testing"
	"time"
)

var (
	stateNow    = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	stateExpiry = stateNow.Add(10 * time.Minute)
)

func putAs(r *registry[int], id, owner string, v int) { r.put(id, owner, v, stateExpiry, stateNow) }

func TestRegistryEvictsTheOldestPastItsLimit(t *testing.T) {
	r := newRegistry[int](3, 3)
	for i := range 4 {
		putAs(r, strconv.Itoa(i), "", i)
	}
	if _, ok := r.get("0"); ok {
		t.Error("the oldest entry survived")
	}
	for i := 1; i < 4; i++ {
		if v, ok := r.get(strconv.Itoa(i)); !ok || v != i {
			t.Errorf("entry %d lost", i)
		}
	}
}

func TestRegistryTakeIsSingleUseAndFreesTheSlot(t *testing.T) {
	r := newRegistry[int](2, 2)
	putAs(r, "a", "", 1)
	putAs(r, "b", "", 2)
	if v, ok := r.take("a"); !ok || v != 1 {
		t.Fatalf("take = %d, %v", v, ok)
	}
	if _, ok := r.take("a"); ok {
		t.Fatal("take returned the entry twice")
	}
	putAs(r, "c", "", 3) // fits without evicting "b"
	if _, ok := r.get("b"); !ok {
		t.Fatal("b was evicted although a slot was free")
	}
}

func TestRegistryDropsExpiredEntriesBeforeEvictingLiveOnes(t *testing.T) {
	r := newRegistry[int](2, 2)
	r.put("stale", "a", 1, stateNow.Add(time.Minute), stateNow)
	r.put("live", "b", 2, stateExpiry, stateNow)

	r.put("new", "c", 3, stateExpiry, stateNow.Add(2*time.Minute))

	if _, ok := r.get("live"); !ok {
		t.Error("a live entry was evicted while an expired one took a slot")
	}
	if _, ok := r.get("stale"); ok {
		t.Error("an expired entry survived")
	}
}

func TestOneClientCannotEvictAnotherClientsPendingLogin(t *testing.T) {
	r := newRegistry[int](10, 3)
	putAs(r, "victim", "10.0.0.1", 0)

	for i := range 50 {
		putAs(r, "spam-"+strconv.Itoa(i), "10.0.0.2", i)
	}

	if _, ok := r.get("victim"); !ok {
		t.Fatal("a flood from another address evicted the pending login")
	}
	if n := r.ownedBy("10.0.0.2"); n != 3 {
		t.Errorf("the flooding address holds %d entries, want its cap of 3", n)
	}
}

func TestClientAddressTravelsInTheContext(t *testing.T) {
	if got := clientOf(WithClient(context.Background(), "203.0.113.9")); got != "203.0.113.9" {
		t.Errorf("clientOf = %q", got)
	}
	if got := clientOf(context.Background()); got != "" {
		t.Errorf("clientOf without a tag = %q", got)
	}
}
