package daemon

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

const unreachablePVE = `providers:
  - type: proxmox
    name: pve
    endpoint: https://127.0.0.1:1
    credential_ref: secret://providers/pve/token
    sync_interval: 1h
`

// A server whose configuration names a Proxmox provider creates it, starts
// syncing it at once and tells the admin doctor how that went: here the token
// was never imported, so the first sync fails and says so.
func TestAServerWithAProxmoxProviderSyncsItAndReportsThroughTheDoctor(t *testing.T) {
	i := newServerInstance(t, unreachablePVE)
	r := i.start()

	var providers wire.DoctorCheck
	timeout := time.After(waitLimit)
wait:
	for {
		status, body := r.callAdmin(http.MethodGet, wire.AdminPathDoctor, "")
		if status != http.StatusOK {
			t.Fatalf("doctor: %d %s", status, body)
		}
		for _, c := range decodeData[wire.AdminDoctor](t, body).Checks {
			if c.Name == "providers" {
				providers = c
			}
		}
		if providers.Status == checkFail {
			break
		}
		select {
		case <-timeout:
			break wait
		case <-time.After(20 * time.Millisecond):
		}
	}

	if providers.Status != checkFail || !strings.Contains(providers.Detail, "pve: the last sync failed") ||
		!strings.Contains(providers.Detail, "API token is unavailable") {
		t.Errorf("providers check = %+v, want a failed first sync naming the missing token", providers)
	}
}
