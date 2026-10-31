package cloudflare

import (
	"fmt"
	"strings"
)

// Ownership is carried by deterministic names (ADR-0037): Cloudflare offers no
// settable marker on tunnels, and names are what every list endpoint can be
// asked for. Instance and node IDs are full UUIDs, so a name that matches but
// belongs to someone else is a conflict, never an adoption.

// TunnelName is the name of a node's tunnel.
func TunnelName(instanceID, nodeID string) string { return "sm-" + instanceID + "-" + nodeID }

// AccessAppName is the name of a node's Access application.
func AccessAppName(instanceID, nodeID string) string {
	return "supermgmt " + instanceID + " " + nodeID
}

// RouteAccessAppName is the name of an app route's Access application.
func RouteAccessAppName(instanceID, routeID string) string {
	return "supermgmt " + instanceID + " route " + routeID
}

// RouteDNSComment is the ownership marker on an app route's DNS record.
func RouteDNSComment(instanceID, routeID string) string {
	return "supermgmt:" + instanceID + ":route:" + routeID
}

// ServicePolicyName is the name of the instance's Service Auth policy.
func ServicePolicyName(instanceID string) string { return "supermgmt service " + instanceID }

// OwnersPolicyName is the name of the instance's owners Allow policy.
func OwnersPolicyName(instanceID string) string { return "supermgmt owners " + instanceID }

// ServiceTokenName is the name of the instance's Access service token.
func ServiceTokenName(instanceID string) string { return "supermgmt-" + instanceID }

// DNSComment is the ownership marker on a node's DNS record.
func DNSComment(instanceID, nodeID string) string {
	return "supermgmt:" + instanceID + ":" + nodeID
}

// TunnelTarget is the CNAME target of a tunnel.
func TunnelTarget(tunnelID string) string { return tunnelID + ".cfargotunnel.com" }

// TunnelHostname is the public hostname of a node: ssh-<node>.<zone>.
func TunnelHostname(nodeName, zone string) (string, error) {
	host := strings.ToLower("ssh-" + nodeName + "." + zone)
	if strings.Contains(nodeName, ".") || !validHostname(host) {
		return "", fmt.Errorf("cloudflare: node %q in zone %q does not make a valid hostname", nodeName, zone)
	}
	return host, nil
}

// validHostname accepts lower-case DNS names of at least two labels; every
// label is 1-63 of [a-z0-9-] and neither starts nor ends with a hyphen.
func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
