package oidc

import (
	"strconv"
	"testing"
)

func TestRegistryEvictsTheOldestPastItsLimit(t *testing.T) {
	r := newRegistry[int](3)
	for i := range 4 {
		r.put(strconv.Itoa(i), i)
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
	r := newRegistry[int](2)
	r.put("a", 1)
	r.put("b", 2)
	if v, ok := r.take("a"); !ok || v != 1 {
		t.Fatalf("take = %d, %v", v, ok)
	}
	if _, ok := r.take("a"); ok {
		t.Fatal("take returned the entry twice")
	}
	r.put("c", 3) // fits without evicting "b"
	if _, ok := r.get("b"); !ok {
		t.Fatal("b was evicted although a slot was free")
	}
}
