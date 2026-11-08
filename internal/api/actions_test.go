package api

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/app"
)

func TestPlannableActions_EveryEntryNeedsWriteToolsAndNothingIsNull(t *testing.T) {
	page := plannableActions(app.PlannableByMCP())

	if len(page.Items) == 0 {
		t.Fatal("no plannable actions")
	}
	for _, item := range page.Items {
		if !item.NeedsWriteTools || item.Parameters == nil {
			t.Errorf("%s: %+v", item.Name, item)
		}
		for _, p := range item.Parameters {
			if p.Values == nil || p.RiskByValue == nil {
				t.Errorf("%s.%s has a null field: %+v", item.Name, p.Name, p)
			}
		}
		if item.Name == "proxmox.snapshot.delete" {
			t.Error("a forbidden action is listed")
		}
	}
}
