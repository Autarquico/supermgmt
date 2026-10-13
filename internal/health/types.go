// Package health validates and runs app health checks (spec §21; ADR-0029).
// A check's destination is never taken from user input: it is resolved from a
// host port the frozen Compose model publishes, under the rules of the check's
// origin.
package health

import (
	"net/netip"
	"time"
)

// Origin says where a check was defined; it decides which destinations are
// allowed (spec §21).
type Origin string

const (
	OriginManifest     Origin = "manifest"      // repository manifest: node scope, loopback only
	OriginControlPlane Origin = "control_plane" // app_target.deployment_policy.health
)

// Check types supported for app targets in M4 (Q10). command-template and
// systemd-active are rejected for app targets.
const (
	TypeHTTP         = "http"
	TypeHTTPS        = "https" // control_plane scope only
	TypeTCP          = "tcp"
	TypeDockerHealth = "docker-health"
)

// Execution scopes (spec §21).
const (
	ScopeNode         = "node"
	ScopeControlPlane = "control_plane"
)

// Check is one health check after §19 precedence. Port and Path apply to node
// scope; URL to control_plane scope only.
type Check struct {
	Origin   Origin        `json:"origin"`
	Type     string        `json:"type"`
	Scope    string        `json:"scope"`
	Port     uint16        `json:"port"`
	Path     string        `json:"path"`
	Timeout  time.Duration `json:"timeout"`
	Interval time.Duration `json:"interval"`
	Attempts int           `json:"attempts"`
	URL      string        `json:"url"`
}

// Destination is where a node-scope check connects, always taken from a
// frozen compose.HostPort.
type Destination struct {
	Addr netip.Addr
	Port uint16
}

// Result is one control-plane check run.
type Result struct {
	Healthy bool
	Status  int    // HTTP status, 0 when no response
	Detail  string // why it is unhealthy; never a response body
}
