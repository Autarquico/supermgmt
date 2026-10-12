package proxmox

import "testing"

func TestPrivilegesHasIgnoresPropagation(t *testing.T) {
	p := Privileges{"VM.Audit": {Propagate: true}, "VM.PowerMgmt": {Propagate: false}}
	for priv, want := range map[string]bool{"VM.Audit": true, "VM.PowerMgmt": true, "Sys.Audit": false} {
		if got := p.Has(priv); got != want {
			t.Errorf("Has(%q) = %v, want %v", priv, got, want)
		}
	}
	if Privileges(nil).Has("VM.Audit") {
		t.Error("no privileges must grant nothing")
	}
}
