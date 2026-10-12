package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// The discovery itself is tested against a fake cluster in internal/app; these
// tests are about the route. The service here has no token to read, so a sync
// ends as a recorded failure of the provider, which is still a refresh that
// ran: it is what makes "the route ran the sync" observable without a cluster.

type pveHarness struct {
	*harness
	provider domain.Provider
}

// newPVEHarness serves a caller with the given roles (admin when nil).
func newPVEHarness(t *testing.T, roles []string) *pveHarness {
	t.Helper()
	h := newHarness(t, func(o *harnessOptions) {
		if roles != nil {
			o.roles = roles
		}
		o.proxmox = func(cfg app.Config) *app.ProxmoxSync {
			sync, err := app.NewProxmoxSync(cfg, app.ProxmoxSyncOptions{
				Token: func(context.Context, string) (audit.Secret, error) { return "", context.Canceled },
			})
			must(t, err)
			return sync
		}
	})
	now := domain.SystemClock{}.Now()
	var provider domain.Provider
	must(t, h.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		var err error
		provider, err = database.CreateProvider(ctx, tx, domain.Provider{
			ID: h.ids.NewID(), Type: "proxmox", Name: "pve", Origin: domain.ProviderStatic, Endpoint: "https://pve.lan:8006",
			CredentialRef: "secret://providers/pve/token", CreatedAt: now, UpdatedAt: now,
		})
		return err
	}))
	return &pveHarness{harness: h, provider: provider}
}

func (h *pveHarness) refresh(id string) reply {
	h.t.Helper()
	return h.post(strings.Replace(wire.PathProviderRefresh, "{id}", id, 1), "", "")
}

func (h *pveHarness) status() string {
	h.t.Helper()
	p, err := database.GetProvider(context.Background(), h.db.Reader(), h.provider.ID)
	must(h.t, err)
	return p.Status
}

func TestRefreshRunsTheSyncAndAnswersWithTheProviderAsItLeftIt(t *testing.T) {
	h := newPVEHarness(t, nil)

	r := h.refresh(h.provider.ID.String())

	var env wire.Envelope[wire.Provider]
	if err := json.Unmarshal(r.Body, &env); err != nil || r.Status != http.StatusOK {
		t.Fatalf("status %d body %s", r.Status, r.Body)
	}
	if env.Data.ID != h.provider.ID || env.Data.Name != "pve" || env.Data.Status != app.ProviderStatusError {
		t.Errorf("provider = %+v, want pve with the failed sync recorded", env.Data)
	}
	if h.status() != app.ProviderStatusError {
		t.Error("the route did not run the sync")
	}
}

func TestRefreshIsRateLimitedPerCallerAndProvider(t *testing.T) {
	h := newPVEHarness(t, nil)

	var statuses []int
	var last reply
	for range 4 {
		last = h.refresh(h.provider.ID.String())
		statuses = append(statuses, last.Status)
	}

	if last.Status != http.StatusTooManyRequests || last.Header.Get("Retry-After") == "" {
		t.Fatalf("statuses %v, Retry-After %q; want the fourth refresh to be 429 with a Retry-After", statuses, last.Header.Get("Retry-After"))
	}
	for _, s := range statuses[:3] {
		if s != http.StatusOK {
			t.Errorf("statuses %v: the first three refreshes are within the burst", statuses)
		}
	}
}

func TestRefreshNeedsAnExistingProviderAndProviderRead(t *testing.T) {
	h := newPVEHarness(t, nil)
	missing := h.refresh(h.ids.NewID().String())
	malformed := h.refresh("not-an-id")

	if missing.Status != http.StatusNotFound || malformed.Status != http.StatusBadRequest {
		t.Errorf("unknown provider: %d, malformed id: %d; want 404 and 400", missing.Status, malformed.Status)
	}

	nobody := newPVEHarness(t, []string{})
	denied := nobody.refresh(nobody.provider.ID.String())
	if denied.Status != http.StatusForbidden {
		t.Errorf("a caller without provider.read: status %d body %s", denied.Status, denied.Body)
	}
	if nobody.status() != "" {
		t.Error("a refused refresh ran the sync")
	}
}

func TestRefreshIsUnavailableWhereDiscoveryIsNotWired(t *testing.T) {
	h := newHarness(t)

	r := h.post(strings.Replace(wire.PathProviderRefresh, "{id}", h.ids.NewID().String(), 1), "", "")

	var failure struct{ Error struct{ Code smerr.Code } }
	if err := json.Unmarshal(r.Body, &failure); err != nil || r.Status != http.StatusUnprocessableEntity || failure.Error.Code != smerr.CodeCapabilityUnavailable {
		t.Errorf("status %d body %s", r.Status, r.Body)
	}
}
