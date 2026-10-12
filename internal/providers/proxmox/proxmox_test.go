package proxmox

import "testing"

func TestPermsHasUsesTheNearestListedAncestor(t *testing.T) {
	p := Perms{"/": {"VM.Audit": true}, "/vms": {"VM.PowerMgmt": true}}
	tests := []struct {
		path, priv string
		want       bool
	}{
		{"/vms/101", "VM.Audit", false}, // /vms is listed and replaces /
		{"/vms/101", "VM.PowerMgmt", true},
		{"/vms", "VM.PowerMgmt", true},
		{"/", "VM.PowerMgmt", false},
		{"/storage/local", "VM.PowerMgmt", false},
		{"/storage/local", "Datastore.Audit", false},
	}
	for _, tt := range tests {
		if got := p.Has(tt.path, tt.priv); got != tt.want {
			t.Errorf("Has(%q, %q) = %v, want %v", tt.path, tt.priv, got, tt.want)
		}
	}
}

func TestADeeperListedPathReplacesWhatAParentGrants(t *testing.T) {
	p := Perms{"/": {"VM.Audit": true}, "/vms": {"VM.PowerMgmt": true}}

	if p.Has("/vms/101", "VM.Audit") {
		t.Error("VM.Audit on /vms/101 is inherited from / although /vms replaces it")
	}
	if !p.Has("/vms/101", "VM.PowerMgmt") || !p.Has("/storage/local", "VM.Audit") {
		t.Error("the nearest listed ancestor must decide")
	}
}
