package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/policy"
)

func TestTheAppReadsAreServiceReadAndLogsAreServiceLogsOnTheNode(t *testing.T) {
	want := map[string]string{
		"GET " + wire.PathApps:         "service.read",
		"GET " + wire.PathNodeApps:     "service.read",
		"GET " + wire.PathNodeApp:      "service.read",
		"GET " + wire.PathNodeAppStats: "service.read",
		"GET " + wire.PathNodeAppLogs:  "service.logs",
	}
	got := map[string]Route{}
	for _, rt := range newHarness(t).server.Routes() {
		got[rt.Method+" "+rt.Pattern] = rt
	}
	for key, action := range want {
		rt, ok := got[key]
		if !ok || rt.Action != action || rt.Keyed {
			t.Errorf("%s = %+v, want a read of %s", key, rt, action)
		}
		if _, inCatalog := policy.Lookup(action); !inCatalog {
			t.Errorf("%s is not a catalog action", action)
		}
	}
}

func TestAnAppReadRefusesABadProjectAndABadQueryBeforeAnythingElse(t *testing.T) {
	h := newHarness(t)
	node := h.ids.NewID().String()
	for name, path := range map[string]string{
		"uppercase project":  wire.Path(wire.PathNodeApp, node, "Shop"),
		"escaped traversal":  wire.Path(wire.PathNodeAppStats, node, "../x"),
		"project with a dot": wire.Path(wire.PathNodeAppLogs, node, "a.b") + "?component=web",
		"cursor and search":  wire.Path(wire.PathNodeAppLogs, node, "shop") + "?component=web&cursor=x&search=y",
		"lines too many":     wire.Path(wire.PathNodeAppLogs, node, "shop") + "?component=web&lines=1001",
		"stats not a bool":   wire.Path(wire.PathNodeApps, node) + "?stats=maybe",
	} {
		r := h.do(http.MethodGet, path, "", nil)
		if r.Status != http.StatusBadRequest && r.Status != http.StatusNotFound {
			t.Errorf("%s: status %d: %s", name, r.Status, r.Body)
		}
		if r.Status == http.StatusNotFound && name != "escaped traversal" {
			t.Errorf("%s: answered not found, so it was used before it was validated: %s", name, r.Body)
		}
	}
}

func TestListingAppsOfAllNodesAnswersAnEmptyPageWithoutNodes(t *testing.T) {
	r := newHarness(t).do(http.MethodGet, wire.PathApps+"?"+url.Values{"stats": {"true"}}.Encode(), "", nil)

	var env struct {
		Data wire.Page[wire.NodeApps] `json:"data"`
	}
	if r.Status != http.StatusOK || json.Unmarshal(r.Body, &env) != nil || len(env.Data.Items) != 0 {
		t.Errorf("status %d: %s", r.Status, r.Body)
	}
}
