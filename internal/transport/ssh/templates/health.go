package templates

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
)

// healthEnv is the environment of every node-side health check (spec §21).
const healthEnv = "env -i PATH=/usr/bin:/bin "

var healthPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,255}$`)

// ValidateHealthAddr accepts an IP literal in canonical form, without zone:
// no hostname is ever resolved on the node. Whether the address is one the
// check may target is decided by internal/health, from the frozen model.
func ValidateHealthAddr(s string) error {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.String() != s || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
		return fmt.Errorf("not a canonical unicast IP literal")
	}
	return nil
}

// ValidateHealthPort accepts a TCP port in 1..65535 in canonical decimal.
func ValidateHealthPort(s string) error { return decimalInRange(s, 1, 65535, "TCP port") }

// ValidateHealthTimeout accepts a timeout in whole seconds, 1..60.
func ValidateHealthTimeout(s string) error { return decimalInRange(s, 1, 60, "timeout in seconds") }

func decimalInRange(s string, lo, hi int, what string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi || strconv.Itoa(n) != s {
		return fmt.Errorf("not a %s in %d..%d", what, lo, hi)
	}
	return nil
}

var (
	paramHealthAddr    = Param{Name: "addr", Validate: ValidateHealthAddr}
	paramHealthPort    = Param{Name: "port", Validate: ValidateHealthPort}
	paramHealthTimeout = Param{Name: "timeout", Validate: ValidateHealthTimeout}
	paramHealthPath    = Param{Name: "path", Validate: Matching(healthPathPattern)}
	paramHealthTarget  = Param{Name: "container", Validate: ValidateContainer}
)

// healthHTTPScript is the spec §21 curl command: `-q` first so no .curlrc is
// read, no proxy, no redirect followed, 2xx judged by the caller from the
// printed status code. An IPv6 literal is bracketed in the URL.
const healthHTTPScript = `case $1 in *:*) host="[$1]";; *) host=$1;; esac
exec curl -q --noproxy '*' --proto =http,https --max-redirs 0 --max-time "$4" --silent --show-error --output /dev/null --write-out '%{http_code}' "http://$host:$2$3"`

// healthTCPScript is the spec §21 tcp check; success is exit 0.
const healthTCPScript = `exec timeout "$3" bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' bash "$1" "$2"`

// healthTemplates holds the node-scope health checks (spec §21). health.http
// needs curl and health.tcp needs bash and timeout on the node (capabilities
// health.http and health.tcp).
var healthTemplates = []Template{
	{
		Name: "health.http", MaxBytes: 256, MaxLines: 2,
		Params: []Param{paramHealthAddr, paramHealthPort, paramHealthPath, paramHealthTimeout},
		Body:   healthEnv + shellScript("sh", healthHTTPScript, "addr", "port", "path", "timeout"),
	},
	{
		Name: "health.tcp", MaxBytes: 256, MaxLines: 2,
		Params: []Param{paramHealthAddr, paramHealthPort, paramHealthTimeout},
		Body:   healthEnv + shellScript("sh", healthTCPScript, "addr", "port", "timeout"),
	},
	{
		// Prints the Docker health status, or "none" when the container defines
		// no health check.
		Name: "health.docker", MaxBytes: 256, MaxLines: 2, Params: []Param{paramHealthTarget},
		Body: "docker inspect --type container --format " +
			goTemplateArg("{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}") + " {{container}}",
	},
}
