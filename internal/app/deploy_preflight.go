package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// preflightHeadroom is the free space that must remain after the images are
// pulled (spec §20.2 step 5).
const preflightHeadroom int64 = 1 << 30

// Causes of a PREFLIGHT_FAILED that only the preflight step produces
// (details.cause; the shared ones live in internal/deployments).
const (
	causePreflightDiskLow          = "DISK_SPACE_LOW"
	causePreflightDiskUnknown      = "DISK_UNKNOWN"
	causePreflightPortInUse        = "PORT_IN_USE"
	causePreflightHealthCapability = "HEALTH_CAPABILITY_MISSING"
	causePreflightUnreadable       = "NODE_STATE_UNREADABLE"
)

// Node capabilities the preflight requires (spec §7, ADR-0030).
const (
	capabilityComposeDeploy = "docker.compose.deploy"
	capabilityDockerHealth  = "docker.read"
)

// preflightInput is what the read-only preflight (spec §20.2 step 5) checks,
// all of it taken from the persisted plan and the node's recorded capabilities.
type preflightInput struct {
	Project      string
	Owner        domain.ID // app_target_id
	DeployRoot   string
	Images       []string // repo@digest of every bound image
	HostPorts    []compose.HostPort
	Health       []health.Check
	Capabilities map[string]bool // node capability name -> available
}

// runPreflight reads the node and refuses the deployment, before anything is
// pulled, backed up or written, when the node cannot take it. Every check is
// read-only. A node that cannot answer is an error of its own, never a pass.
func runPreflight(ctx context.Context, ex transport.Executor, in preflightInput) error {
	if !in.Capabilities[capabilityComposeDeploy] {
		return preflightFailed(deployments.CauseComposeUnsupported, "the node cannot run Compose deployments")
	}
	if err := preflightHealthCapabilities(in); err != nil {
		return err
	}
	containers, err := preflightProjectContainers(ctx, ex, in.Project)
	if err != nil {
		return err
	}
	if err := preflightOwnership(containers, in.Owner); err != nil {
		return err
	}
	if err := preflightResourceOwnership(ctx, ex, in.Project, in.Owner); err != nil {
		return err
	}
	if err := preflightPorts(ctx, ex, in.HostPorts, containers); err != nil {
		return err
	}
	need, err := preflightBytesNeeded(ctx, ex, in.Images)
	if err != nil {
		return err
	}
	return preflightDisk(ctx, ex, in.DeployRoot, need)
}

func preflightFailed(cause, format string, args ...any) error {
	e := smerr.FromReason(smerr.ReasonPreflightFailed, fmt.Sprintf(format, args...))
	e.Details = map[string]any{"cause": cause}
	return e
}

// preflightRead runs one read-only template and returns its complete stdout.
// A command that fails, or whose output was cut, is a failed preflight: a
// partial read must not pass a check.
func preflightRead(ctx context.Context, ex transport.Executor, name string, args map[string]string) ([]byte, error) {
	cmd, err := templates.Render(name, args)
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", name, err)
	}
	res, err := ex.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("run %s: %w", name, err)
	}
	if res.ExitStatus != 0 || res.Truncated {
		return nil, preflightFailed(causePreflightUnreadable, "%s did not return a complete answer", name)
	}
	return res.Stdout, nil
}

func preflightHealthCapabilities(in preflightInput) error {
	for _, c := range in.Health {
		if c.Scope != health.ScopeNode {
			continue
		}
		name := preflightHealthCapability(c.Type)
		if name == "" || !in.Capabilities[name] {
			return preflightFailed(causePreflightHealthCapability, "the node lacks the capability for %s health checks", c.Type)
		}
	}
	return nil
}

func preflightHealthCapability(checkType string) string {
	switch checkType {
	case health.TypeHTTP:
		return "health.http"
	case health.TypeTCP:
		return "health.tcp"
	case health.TypeDockerHealth:
		return capabilityDockerHealth
	}
	return ""
}

// preflightContainer is the part of `docker inspect` the preflight reads.
type preflightContainer struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		PortBindings map[string][]struct {
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
}

func preflightProjectContainers(ctx context.Context, ex transport.Executor, project string) ([]preflightContainer, error) {
	out, err := preflightRead(ctx, ex, "compose.project_containers", map[string]string{"project": project})
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}
	var containers []preflightContainer
	if err := json.Unmarshal(out, &containers); err != nil {
		return nil, preflightFailed(causePreflightUnreadable, "the project's containers could not be read")
	}
	return containers, nil
}

// preflightOwnership refuses a project name that something else already uses:
// every container of the project must carry this target's owner label (§20.5).
func preflightOwnership(containers []preflightContainer, owner domain.ID) error {
	for _, c := range containers {
		if c.Config.Labels[compose.LabelOwner] != owner.String() {
			return smerr.FromReason(smerr.ReasonProjectNotOwned, "the project name is in use by resources this app target does not own")
		}
	}
	return nil
}

// preflightResource is a volume or network as `docker volume|network inspect`
// reports it.
type preflightResource struct {
	Name   string            `json:"Name"`
	Labels map[string]string `json:"Labels"`
}

// preflightResourceOwnership refuses a volume or network that bears the
// project's names without this target's owner label (spec §20.5, ADR-0029).
func preflightResourceOwnership(ctx context.Context, ex transport.Executor, project string, owner domain.ID) error {
	out, err := preflightRead(ctx, ex, "compose.project_resources", map[string]string{"project": project})
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		_, payload, ok := strings.Cut(line, " ")
		var r preflightResource
		if !ok || json.Unmarshal([]byte(payload), &r) != nil {
			return preflightFailed(causePreflightUnreadable, "the project's volumes and networks could not be read")
		}
		if preflightBearsProjectName(r, project) && r.Labels[compose.LabelOwner] != owner.String() {
			return smerr.FromReason(smerr.ReasonProjectNotOwned, "the project name is in use by resources this app target does not own")
		}
	}
	return nil
}

func preflightBearsProjectName(r preflightResource, project string) bool {
	return r.Labels["com.docker.compose.project"] == project || strings.HasPrefix(r.Name, project+"_")
}

// preflightPorts refuses a host port (TCP or UDP) some other process holds. A
// port the project's own containers publish is owned and passes, because
// compose up recreates them.
func preflightPorts(ctx context.Context, ex transport.Executor, ports []compose.HostPort, containers []preflightContainer) error {
	if len(ports) == 0 {
		return nil
	}
	out, err := preflightRead(ctx, ex, "compose.listeners", nil)
	if err != nil {
		return err
	}
	listeners := parsePreflightListeners(string(out))
	owned := preflightOwnedPorts(containers)
	for _, p := range ports {
		if !owned[preflightPortKey(p.Proto, p.Port)] && preflightListenerHolds(listeners, p) {
			return preflightFailed(causePreflightPortInUse, "host port %d on %s is held by another process", p.Port, p.Addr)
		}
	}
	return nil
}

type preflightListener struct {
	addr     netip.Addr // invalid for a wildcard
	wildcard bool
	port     uint16
	proto    string // tcp | udp
}

// preflightPortKey names a host port of one protocol; an empty protocol is TCP.
func preflightPortKey(proto string, port uint16) string {
	return preflightProto(proto) + "/" + strconv.Itoa(int(port))
}

// parsePreflightListeners reads `ss -H -ltn` followed by `ss -H -lun`: the first
// column is the state (UNCONN marks a UDP socket) and the fourth the local
// address as 127.0.0.1:80, [::1]:80, *:80 or [::]:80. Lines it cannot read are
// skipped.
func parsePreflightListeners(out string) []preflightListener {
	var ls []preflightListener
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		host, portText, ok := preflightCutLastColon(fields[3])
		port, err := strconv.ParseUint(portText, 10, 16)
		if !ok || err != nil {
			continue
		}
		host = strings.Trim(host, "[]")
		if i := strings.IndexByte(host, '%'); i >= 0 {
			host = host[:i]
		}
		l := preflightListener{port: uint16(port), proto: "tcp"}
		if fields[0] == "UNCONN" {
			l.proto = "udp"
		}
		addr, err := netip.ParseAddr(host)
		switch {
		case host == "*" || (err == nil && addr.IsUnspecified()):
			l.wildcard = true
		case err == nil:
			l.addr = addr
		default:
			continue
		}
		ls = append(ls, l)
	}
	return ls
}

func preflightCutLastColon(s string) (before, after string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// preflightListenerHolds reports whether a listener occupies the published address:
// the same address, or a wildcard (conservatively, of either family).
func preflightListenerHolds(ls []preflightListener, p compose.HostPort) bool {
	return slices.ContainsFunc(ls, func(l preflightListener) bool {
		return l.port == p.Port && l.proto == preflightProto(p.Proto) && (l.wildcard || l.addr == p.Addr || p.Addr.IsUnspecified())
	})
}

func preflightProto(proto string) string {
	if proto == "" {
		return "tcp"
	}
	return proto
}

// preflightOwnedPorts keys the host ports of the project's containers by
// protocol; PortBindings keys read "<container port>/<proto>".
func preflightOwnedPorts(containers []preflightContainer) map[string]bool {
	owned := map[string]bool{}
	for _, c := range containers {
		for key, bindings := range c.HostConfig.PortBindings {
			_, proto, _ := strings.Cut(key, "/")
			for _, b := range bindings {
				if port, err := strconv.ParseUint(b.HostPort, 10, 16); err == nil {
					owned[preflightPortKey(proto, uint16(port))] = true
				}
			}
		}
	}
	return owned
}

// preflightBytesNeeded is the sum of the sizes of the images the node does not
// hold yet. An image that is missing and whose size cannot be established
// fails the preflight (fail closed; ADR-0029, Q14).
func preflightBytesNeeded(ctx context.Context, ex transport.Executor, images []string) (int64, error) {
	var total int64
	for _, image := range preflightDistinct(images) {
		present, err := preflightImagePresent(ctx, ex, image)
		if err != nil {
			return 0, err
		}
		if present {
			continue
		}
		size, err := preflightImageSize(ctx, ex, image)
		if err != nil {
			return 0, err
		}
		total += size
	}
	return total, nil
}

func preflightDistinct(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func preflightImagePresent(ctx context.Context, ex transport.Executor, image string) (bool, error) {
	cmd, err := templates.Render("compose.image_inspect", map[string]string{"image": image})
	if err != nil {
		return false, fmt.Errorf("render compose.image_inspect: %w", err)
	}
	res, err := ex.Run(ctx, cmd)
	if err != nil {
		return false, fmt.Errorf("run compose.image_inspect: %w", err)
	}
	return res.ExitStatus == 0, nil
}

func preflightImageSize(ctx context.Context, ex transport.Executor, image string) (int64, error) {
	unknown := func() error {
		return preflightFailed(deployments.CauseImageSizeUnknown, "the size of %s could not be established", image)
	}
	cmd, err := templates.Render("compose.image_size", map[string]string{"image": image})
	if err != nil {
		return 0, fmt.Errorf("render compose.image_size: %w", err)
	}
	res, err := ex.Run(ctx, cmd)
	if err != nil {
		return 0, fmt.Errorf("run compose.image_size: %w", err)
	}
	if res.ExitStatus != 0 || res.Truncated {
		return 0, unknown()
	}
	size, err := templates.ParseImageSize(res.Stdout)
	if err != nil {
		return 0, unknown()
	}
	return size, nil
}

// preflightDisk requires free space of at least the images plus 1 GiB on the
// Docker root directory and on the deploy root (equal passes).
func preflightDisk(ctx context.Context, ex transport.Executor, deployRoot string, imageBytes int64) error {
	root, err := preflightRead(ctx, ex, "compose.docker_root", nil)
	if err != nil {
		return err
	}
	dockerRoot := strings.TrimSpace(string(root))
	if templates.ValidateCleanPath(dockerRoot) != nil {
		return preflightFailed(causePreflightDiskUnknown, "the Docker root directory could not be established")
	}
	required := imageBytes + preflightHeadroom
	for _, dir := range preflightDistinct([]string{dockerRoot, deployRoot}) {
		free, err := preflightDiskFree(ctx, ex, dir)
		if err != nil {
			return err
		}
		if free < required {
			return preflightFailed(causePreflightDiskLow, "%s has %d bytes free, %d are required", dir, free, required)
		}
	}
	return nil
}

// preflightDiskFree reads the available bytes of `df -PB1 <dir>`: the third column
// from the end of its last line (the filesystem name may contain spaces).
func preflightDiskFree(ctx context.Context, ex transport.Executor, dir string) (int64, error) {
	unknown := preflightFailed(causePreflightDiskUnknown, "the free space of %s could not be established", dir)
	out, err := preflightRead(ctx, ex, "compose.disk_free", map[string]string{"path": dir})
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	fields := strings.Fields(lines[len(lines)-1])
	if len(lines) < 2 || len(fields) < 6 {
		return 0, unknown
	}
	free, err := strconv.ParseInt(fields[len(fields)-3], 10, 64)
	if err != nil || free < 0 {
		return 0, unknown
	}
	return free, nil
}
