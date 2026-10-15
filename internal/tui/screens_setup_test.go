package tui

import (
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
)

func TestSetupIsOfferedOnlyWhereItCanRun(t *testing.T) {
	for name, tc := range map[string]struct {
		node    wire.Node
		offered bool
	}{
		"linux ssh node": {wire.Node{Name: "web-1", Kind: "ssh", OS: "Debian GNU/Linux 13 (trixie)"}, true},
		"mac ssh node":   {wire.Node{Name: "macmini", Kind: "ssh", OS: "macOS 26.0"}, false},
		"local node":     {wire.Node{Name: "laptop", Kind: "local", OS: "Debian GNU/Linux 13 (trixie)"}, false},
		"proxmox guest":  {wire.Node{Name: "vm-100", Kind: "proxmox_guest"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			got := setupSummary(tc.node)
			if offered := strings.Contains(got, "/ setup "); offered != tc.offered {
				t.Errorf("setupSummary = %q, offered = %v, want %v", got, offered, tc.offered)
			}
		})
	}
}
