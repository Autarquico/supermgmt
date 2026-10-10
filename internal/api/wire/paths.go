package wire

import (
	"net/url"
	"strings"
)

// Prefix is the API version prefix (spec §23).
const Prefix = "/api/v1"

// Route paths in net/http ServeMux pattern syntax. The server registers them
// with a method ("GET " + PathNodes); the client fills placeholders with Path.
// Each M1 route maps to exactly one catalog action or exemption (ADR-0014);
// that table lives in internal/api/routes.go.
const (
	PathHealthLive  = "/health/live"
	PathHealthReady = "/health/ready"

	PathMe       = Prefix + "/me"
	PathPresence = Prefix + "/presence"
	PathSSHKey   = Prefix + "/ssh-key"

	PathPlans      = Prefix + "/plans"
	PathPlan       = Prefix + "/plans/{id}"
	PathPlanSubmit = Prefix + "/plans/{id}/submit"

	PathApprovals  = Prefix + "/approvals"
	PathJobs       = Prefix + "/jobs"
	PathJob        = Prefix + "/jobs/{id}"
	PathJobApprove = Prefix + "/jobs/{id}/approve"
	PathJobReject  = Prefix + "/jobs/{id}/reject"
	PathJobCancel  = Prefix + "/jobs/{id}/cancel"
	PathJobResolve = Prefix + "/jobs/{id}/resolve"

	PathProviders = Prefix + "/providers"

	PathNodes           = Prefix + "/nodes"
	PathNodesSSH        = Prefix + "/nodes/ssh"
	PathNodesSSHHostKey = Prefix + "/nodes/ssh/host-key"
	PathNode            = Prefix + "/nodes/{id}"
	PathNodeProbe       = Prefix + "/nodes/{id}/probe"
	PathNodeServices    = Prefix + "/nodes/{id}/services"
	PathNodeConnectInfo = Prefix + "/nodes/{id}/connect-info"
	PathNodeSessions    = Prefix + "/nodes/{id}/sessions"
	PathNodeSessionEnd  = Prefix + "/nodes/{id}/sessions/{sid}/end"

	PathService        = Prefix + "/services/{id}"
	PathServiceLogs    = Prefix + "/services/{id}/logs"
	PathServiceStart   = Prefix + "/services/{id}/actions/start"
	PathServiceStop    = Prefix + "/services/{id}/actions/stop"
	PathServiceRestart = Prefix + "/services/{id}/actions/restart"

	PathEvents = Prefix + "/events"
)

// Path fills the {placeholders} of pattern, in order, with path-escaped
// values. A placeholder without a value is left as is, so the server rejects
// the request instead of acting on a wrong resource.
func Path(pattern string, values ...string) string {
	var b strings.Builder
	rest := pattern
	for _, v := range values {
		open := strings.IndexByte(rest, '{')
		closing := strings.IndexByte(rest, '}')
		if open < 0 || closing < open {
			break
		}
		b.WriteString(rest[:open])
		b.WriteString(url.PathEscape(v))
		rest = rest[closing+1:]
	}
	b.WriteString(rest)
	return b.String()
}
