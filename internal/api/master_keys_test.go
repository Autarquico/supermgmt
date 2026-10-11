package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// listingKeys is a Keys port that can only list: any other method would panic
// on the nil embedded interface, proving the route calls nothing else.
type listingKeys struct {
	app.Keys
	keys []wire.MasterKey
	err  error
}

func (l listingKeys) ListKeys(context.Context, app.Caller) ([]wire.MasterKey, error) {
	return l.keys, l.err
}

// keysWithoutListing is a Keys port that predates key listing.
type keysWithoutListing struct{ app.Keys }

func TestMasterKeysAreListedAsAPage(t *testing.T) {
	created := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	h := newHarness(t, func(o *harnessOptions) {
		o.keys = listingKeys{keys: []wire.MasterKey{{ID: "0192a000-0000-7000-8000-00000000f001", Active: true, Loaded: true, CreatedAt: created}}}
	})

	r := h.do(http.MethodGet, wire.PathMasterKeys, "", nil)

	var env wire.Envelope[wire.Page[wire.MasterKey]]
	if err := json.Unmarshal(r.Body, &env); err != nil || r.Status != http.StatusOK {
		t.Fatalf("status %d body %s", r.Status, r.Body)
	}
	if len(env.Data.Items) != 1 || !env.Data.Items[0].Active || !env.Data.Items[0].CreatedAt.Equal(created) {
		t.Errorf("page = %+v", env.Data)
	}
}

func TestNoMasterKeysIsAnEmptyListNotNull(t *testing.T) {
	h := newHarness(t, func(o *harnessOptions) { o.keys = listingKeys{} })

	r := h.do(http.MethodGet, wire.PathMasterKeys, "", nil)

	var raw struct {
		Data struct {
			Items []wire.MasterKey `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(r.Body, &raw); err != nil || raw.Data.Items == nil {
		t.Errorf("body %s: items must be [] (%v)", r.Body, err)
	}
}

func TestMasterKeyListingFollowsThePolicyVerdict(t *testing.T) {
	h := newHarness(t, func(o *harnessOptions) {
		o.keys = listingKeys{err: smerr.New(smerr.CodePolicyDenied, smerr.ReasonDefaultDeny, "no")}
	})

	r := h.do(http.MethodGet, wire.PathMasterKeys, "", nil)

	if r.Status != http.StatusForbidden || decodeError(t, r).Code != smerr.CodePolicyDenied {
		t.Errorf("status %d body %s", r.Status, r.Body)
	}
}

func TestMasterKeyListingIsUnavailableWithoutKeyManagementOrListing(t *testing.T) {
	for name, keys := range map[string]app.Keys{"unwired": nil, "no listing": keysWithoutListing{}} {
		h := newHarness(t, func(o *harnessOptions) { o.keys = keys })

		r := h.do(http.MethodGet, wire.PathMasterKeys, "", nil)

		if r.Status != http.StatusUnprocessableEntity || decodeError(t, r).Code != smerr.CodeCapabilityUnavailable {
			t.Errorf("%s: status %d body %s", name, r.Status, r.Body)
		}
	}
}
