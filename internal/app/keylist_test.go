package app

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestListKeysShowsTheActiveAndTheLoadedKeysWithTheirCreationTime(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)
	ctx := context.Background()
	first, _ := k.keys.Active()
	created := k.clock.Now()
	k.clock.Advance(time.Hour)
	rotation, err := k.km.RotateMasterKey(ctx, k.caller(k.admin))
	mustf(t, err, "RotateMasterKey")
	k.mustRun(rotation.Pending)
	second, _ := k.keys.Active()

	listed, err := k.km.ListKeys(ctx, k.caller(k.admin))

	mustf(t, err, "ListKeys")
	if len(listed) != 2 {
		t.Fatalf("listed %d keys, want 2: %+v", len(listed), listed)
	}
	active := map[string]bool{}
	for _, key := range listed {
		active[key.ID.String()] = key.Active
		if !key.Loaded || key.CreatedAt.IsZero() {
			t.Errorf("key %+v: want loaded with a creation time", key)
		}
		if key.ID == first && !key.CreatedAt.Equal(created) {
			t.Errorf("first key created %s, want %s", key.CreatedAt, created)
		}
	}
	if isActive, listed := active[second.String()]; !listed || !isActive {
		t.Errorf("the new key %s is not listed as active: %+v", second, active)
	}
	if isActive, listed := active[first.String()]; !listed || isActive {
		t.Errorf("the previous key %s must be listed and inactive: %+v", first, active)
	}
}

func TestListKeysIsAConfigReadAndAuditsARefusal(t *testing.T) {
	k := newKeysFixture(t, config.ModeLocal)

	_, err := k.km.ListKeys(context.Background(), k.caller(k.dave))

	if smerr.CodeOf(err) != smerr.CodePolicyDenied {
		t.Fatalf("err = %v, want POLICY_DENIED", err)
	}
	if n := len(k.events("policy.deny")); n != 1 {
		t.Errorf("%d policy.deny events, want 1", n)
	}
}
