package cloudflare

import (
	"slices"
	"testing"
)

func TestNodeIngress_RoutesAreSortedBetweenSSHAndCatchAll(t *testing.T) {
	got := NodeIngress("ssh-n.example.com", []RouteRule{{"b.example.com", 9000}, {"a.example.com", 8080}})
	want := []IngressRule{
		{Hostname: "ssh-n.example.com", Service: ServiceSSH},
		{Hostname: "a.example.com", Service: "http://127.0.0.1:8080"},
		{Hostname: "b.example.com", Service: "http://127.0.0.1:9000"},
		{Service: ServiceNotFound},
	}
	if !slices.Equal(got, want) {
		t.Errorf("NodeIngress = %+v, want %+v", got, want)
	}
}

func TestSSHIngress_IsNodeIngressWithoutRoutes(t *testing.T) {
	want := []IngressRule{{Hostname: "h.example.com", Service: ServiceSSH}, {Service: ServiceNotFound}}
	if got := SSHIngress("h.example.com"); !slices.Equal(got, want) {
		t.Errorf("SSHIngress = %+v", got)
	}
}

func TestNodeIngress_DoesNotReorderItsInput(t *testing.T) {
	routes := []RouteRule{{"b.example.com", 1}, {"a.example.com", 2}}
	NodeIngress("h.example.com", routes)
	if routes[0].Hostname != "b.example.com" {
		t.Errorf("input was sorted in place: %+v", routes)
	}
}

func TestRouteNames_AreTheADRMarkers(t *testing.T) {
	if got, want := RouteAccessAppName("I", "R"), "supermgmt I route R"; got != want {
		t.Errorf("RouteAccessAppName = %q", got)
	}
	if got, want := RouteDNSComment("I", "R"), "supermgmt:I:route:R"; got != want {
		t.Errorf("RouteDNSComment = %q", got)
	}
}
