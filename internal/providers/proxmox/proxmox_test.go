package proxmox

import "testing"

func TestPermsHasInheritsFromParentPaths(t *testing.T) {
	p := Perms{"/": {"VM.Audit": true}, "/vms": {"VM.PowerMgmt": true}}
	tests := []struct {
		path, priv string
		want       bool
	}{
		{"/vms/101", "VM.Audit", true},
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
