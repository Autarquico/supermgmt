package integration

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/cli"
)

func TestTheAppMoveCommandIsUnknown(t *testing.T) {
	for _, args := range [][]string{{"apps", "move"}, {"apps", "moves"}, {"apps", "move", "cleanup-source"}} {
		var stdout, stderr bytes.Buffer
		if exit := cli.Execute(args, &stdout, &stderr); exit != 2 {
			t.Errorf("sm %s: exit %d, want 2 (unknown command); stderr %q", strings.Join(args, " "), exit, stderr.String())
		}
	}
}

func TestTheAppMovePathsAnswerNotFound(t *testing.T) {
	rig := newMCPRig(t, true)
	for _, c := range []struct{ method, suffix string }{
		{http.MethodGet, "/moves"},
		{http.MethodPost, "/moves"},
		{http.MethodPost, "/moves/cleanup-source"},
		{http.MethodPost, "/moves/abandon"},
	} {
		got := rig.send(mcpRigSocket, c.method, "/api/v1/app-targets/anything"+c.suffix, "{}")
		if got.status != http.StatusNotFound {
			t.Errorf("%s %s: status %d, want 404", c.method, c.suffix, got.status)
		}
	}
}
