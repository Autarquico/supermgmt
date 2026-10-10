package policy

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
)

func TestMatchAction(t *testing.T) {
	cases := []struct {
		pattern, action string
		want            bool
	}{
		{"*", "node.read", true},
		{"*", "plan.create", true},
		{"*.read", "node.read", true},
		{"*.read", "service.read", true},
		{"*.read", "node.read.x", false},
		{"*.read", "read", false},
		{"*.read", "node.write", false},
		{"service.*", "service.start", true},
		{"service.*", "service", false},
		{"service.*", "proxmox.vm.power", false},
		{"proxmox.*.power", "proxmox.vm.power", true},
		{"proxmox.*", "proxmox.vm.power", false},
		{"proxmox.*.*", "proxmox.vm.power", true},
		{"node.read", "node.read", true},
		{"node.read", "node.reboot", false},
		{"node.re*", "node.read", false},
		{"", "node.read", false},
	}
	for _, tc := range cases {
		if got := matchAction(tc.pattern, tc.action); got != tc.want {
			t.Errorf("matchAction(%q, %q) = %v, want %v", tc.pattern, tc.action, got, tc.want)
		}
	}
}

func TestMatchSubject(t *testing.T) {
	actor := domain.Actor{ID: "id-1", Type: domain.ActorHuman, Roles: []string{"operator", "viewer"}}
	cases := []struct {
		entry string
		want  bool
	}{
		{"*", true},
		{"type:human", true},
		{"type:mcp", false},
		{"role:operator", true},
		{"role:viewer", true},
		{"role:admin", false},
		{"identity:id-1", true},
		{"identity:id-2", false},
		{"type:", false},
		{"role", false},
		{"group:operator", false},
	}
	for _, tc := range cases {
		if got := matchSubject(tc.entry, actor); got != tc.want {
			t.Errorf("matchSubject(%q) = %v, want %v", tc.entry, got, tc.want)
		}
	}
}

func TestMatchResource(t *testing.T) {
	attrs := Attributes{Tags: []string{"db", "eu"}, Environment: "staging", Provider: "pve", Node: "pve-1", App: "shop"}
	cases := []struct {
		entry string
		attrs Attributes
		want  bool
	}{
		{"*", attrs, true},
		{"*", Attributes{}, true},
		{"tag:db", attrs, true},
		{"tag:web", attrs, false},
		{"environment:staging", attrs, true},
		{"environment:production", attrs, false},
		{"provider:pve", attrs, true},
		{"node:pve-1", attrs, true},
		{"node:pve-2", attrs, false},
		{"app:shop", attrs, true},
		{"app:blog", attrs, false},
		{"environment:staging", Attributes{}, false},
		{"tag:db", Attributes{}, false},
		{"environment:", attrs, false},
		{"region:eu", attrs, false},
	}
	for _, tc := range cases {
		if got := matchResource(tc.entry, tc.attrs); got != tc.want {
			t.Errorf("matchResource(%q) = %v, want %v", tc.entry, got, tc.want)
		}
	}
}

func TestRuleMatchesResource_EntriesAreORed_OmittedMatchesAll(t *testing.T) {
	attrs := Attributes{Environment: "staging", Node: "pve-1"}
	if !(Rule{}).matchesResource(attrs) {
		t.Error("omitted resources must match everything")
	}
	if !(Rule{}).matchesResource(Attributes{}) {
		t.Error("omitted resources must match attribute-less targets")
	}
	either := Rule{Resources: []string{"environment:production", "node:pve-1"}}
	if !either.matchesResource(attrs) {
		t.Error("one matching entry is enough")
	}
	neither := Rule{Resources: []string{"environment:production", "node:pve-2"}}
	if neither.matchesResource(attrs) {
		t.Error("no matching entry must not match")
	}
}

func TestCapabilitySet_NilAdvertisesNothing(t *testing.T) {
	var nilSet CapabilitySet
	if nilSet.Has("node.ssh") {
		t.Fatal("nil set must be empty")
	}
	if !NewCapabilitySet("node.ssh").Has("node.ssh") {
		t.Fatal("constructed set must contain its names")
	}
}
