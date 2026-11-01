package app

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// Causes of a PREFLIGHT_FAILED that only a move produces.
const (
	causeMoveSourceNotRunning  = "SOURCE_NOT_RUNNING"
	causeMoveVolumeMissing     = "SOURCE_VOLUME_MISSING"
	causeMoveVolumeExists      = "DEST_VOLUME_EXISTS"
	causeMoveMemoryLow         = "MEMORY_LOW"
	causeMoveCPUShort          = "CPU_SHORT"
	causeMovePlatform          = "PLATFORM_UNSUPPORTED"
	causeMoveSourceStillActive = "SOURCE_STILL_ACTIVE"
)

// volumeSpaceMargin is the share of the volumes' size added to the bytes B needs for them (10%).
const volumeSpaceMargin = 10

// ---- re-checks under the claim locks -----------------------------------------------------------------------------

// recheck repeats the request-time admission under the locks the job holds (spec §3): the target still runs on A,
// both nodes are still the planned kind of node, no other work is open for the target, nobody else uses the project
// on B and both nodes can still deploy. The move's own deployment on B is the one open deployment allowed.
func (r *moveRun) recheck(ctx context.Context) error {
	q := r.h.cfg.DB.Reader()
	target, err := database.GetAppTarget(ctx, q, r.target.ID)
	if err != nil {
		return err
	}
	if target.NodeID != r.move.SourceNodeID {
		return smerr.New(smerr.CodeConflict, "", "the target no longer runs on the move's source node")
	}
	source, err := database.GetNode(ctx, q, r.move.SourceNodeID)
	if err != nil {
		return err
	}
	dest, err := database.GetNode(ctx, q, r.move.DestNodeID)
	if err != nil {
		return err
	}
	if err := requireMoveNodes(source, dest); err != nil {
		return err
	}
	if err := requireNoOtherOpenDeployment(ctx, q, target.ID, r.move.DestDeploymentID); err != nil {
		return err
	}
	if err := requireNoOtherOpenMove(ctx, q, target.ID, &r.move.ID); err != nil {
		return err
	}
	if err := requireProjectFreeOn(ctx, q, target, dest); err != nil {
		return err
	}
	if err := requireNoTargetRoutes(ctx, q, target.ID); err != nil {
		return err
	}
	for _, node := range []domain.Node{source, dest} {
		if err := requireCapability(ctx, q, node, capabilityComposeDeploy); err != nil {
			return err
		}
	}
	return nil
}

// requireNoOtherOpenDeployment is requireNoOpenDeployment for a target whose move has a deployment of its own.
func requireNoOtherOpenDeployment(ctx context.Context, q database.Querier, targetID domain.ID, own *domain.ID) error {
	for _, state := range deployments.AllStates() {
		if state.Terminal() {
			continue
		}
		open, err := database.ListDeployments(ctx, q, database.DeploymentFilter{AppTargetID: targetID, State: state}, 2)
		if err != nil {
			return err
		}
		for _, d := range open {
			if own == nil || d.ID != *own {
				return smerr.New(smerr.CodeConflict, "", fmt.Sprintf(
					"the target has a %s %s in state %s: let it finish or cancel it before moving", d.Kind, d.ID, state))
			}
		}
	}
	return nil
}

func requireCapability(ctx context.Context, q database.Querier, node domain.Node, capability string) error {
	c, err := database.GetNodeCapability(ctx, q, node.ID, capability)
	if smerr.CodeOf(err) == smerr.CodeNotFound || err == nil && !c.Available {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("node %s lacks the capability %s", node.Name, capability))
	}
	return err
}

// ---- preflight ---------------------------------------------------------------------------------------------------

// preflight reads A and B and changes neither (spec §3).
func (r *moveRun) preflight(ctx context.Context, fz frozenDeployment) error {
	if err := r.preflightSource(ctx); err != nil {
		return err
	}
	return r.preflightDest(ctx, fz)
}

// preflightSource checks that A runs the known-good deployment: every project container carries the target's owner
// label and the deployment's label, and every volume of the map exists.
func (r *moveRun) preflightSource(ctx context.Context) error {
	containers, err := r.containers(ctx, r.a)
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return preflightFailed(causeMoveSourceNotRunning, "node %s runs no container of the project", r.a.node.Name)
	}
	for _, c := range containers {
		if c.Labels[compose.LabelOwner] != r.target.ID.String() || c.Labels[compose.LabelDeployment] != r.good.deployment.ID.String() {
			return preflightFailed(causeMoveSourceNotRunning, "node %s does not run the known-good deployment %s", r.a.node.Name, r.good.deployment.ID)
		}
	}
	names, err := r.volumeNames(ctx)
	if err != nil || len(names) == 0 {
		return err
	}
	found, err := r.existingVolumes(ctx, r.a, names)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, ok := found[name]; !ok {
			return preflightFailed(causeMoveVolumeMissing, "volume %s does not exist on node %s", name, r.a.node.Name)
		}
	}
	return nil
}

// preflightDest checks that B can host the move: the deployment preflight, the platform of every image, memory and
// CPU for the services' limits, space for the volumes, and no volume of the map that this move did not create.
func (r *moveRun) preflightDest(ctx context.Context, fz frozenDeployment) error {
	if err := r.requirePlatform(ctx, fz); err != nil {
		return err
	}
	err := runPreflight(ctx, r.b.ex, preflightInput{
		Project: r.target.ComposeProject, Owner: r.target.ID, DeployRoot: r.b.root,
		Images: distinctImageRefs(fz.frozen.Images), HostPorts: fz.frozen.HostPorts,
		Health: fz.healthRun("").Checks, Capabilities: r.b.caps,
	})
	if err != nil {
		return err
	}
	if err := r.requireResources(ctx); err != nil {
		return err
	}
	if err := r.requireVolumeSpace(ctx, fz); err != nil {
		return err
	}
	return r.requireNoStrayVolumes(ctx)
}

// requirePlatform sizes every image, even one B already holds: the size read fails when the image has no variant for
// B's platform.
func (r *moveRun) requirePlatform(ctx context.Context, fz frozenDeployment) error {
	for _, image := range distinctImageRefs(fz.frozen.Images) {
		if _, err := preflightImageSize(ctx, r.b.ex, image); err != nil {
			if isTyped(err) {
				return preflightFailed(causeMovePlatform, "image %s has no variant for node %s or its size is unknown", image, r.b.node.Name)
			}
			return err
		}
	}
	return nil
}

// requireResources compares the limits the model sets with B's memory and CPUs. A service without a limit counts
// for nothing.
func (r *moveRun) requireResources(ctx context.Context) error {
	model, err := readSnapshotJSON[composeSnapshot](ctx, r.h.cfg.DB.Reader(), r.good.plan.Content.ComposeHash)
	if err != nil {
		return err
	}
	memory, cpus, err := resourceLimits(model.Effective)
	if err != nil {
		return preflightFailed(causePreflightUnreadable, "%v", err)
	}
	if memory == 0 && cpus == 0 {
		return nil
	}
	out, err := preflightRead(ctx, r.b.ex, "docker.info_resources", nil)
	if err != nil {
		return err
	}
	info, err := templates.ParseInfoResources(out)
	if err != nil {
		return preflightFailed(causePreflightUnreadable, "node %s: %v", r.b.node.Name, err)
	}
	if memory > info.MemTotal {
		return preflightFailed(causeMoveMemoryLow, "the services' memory limits add up to %d bytes, node %s has %d", memory, r.b.node.Name, info.MemTotal)
	}
	if cpus > float64(info.NCPU) {
		return preflightFailed(causeMoveCPUShort, "a service is limited to %g CPUs, node %s has %d", cpus, r.b.node.Name, info.NCPU)
	}
	return nil
}

// requireVolumeSpace checks that B's Docker root holds the images it lacks, A's volumes with a 10% margin and the
// deployment headroom. Docker reports image sizes as manifest layer bytes, not unpacked size, so the margin of an
// image is the headroom alone.
func (r *moveRun) requireVolumeSpace(ctx context.Context, fz frozenDeployment) error {
	_, volumeBytes, err := r.sourceSizes(ctx)
	if err != nil {
		return err
	}
	imageBytes, err := preflightBytesNeeded(ctx, r.b.ex, distinctImageRefs(fz.frozen.Images))
	if err != nil {
		return err
	}
	root, err := preflightDockerRoot(ctx, r.b.ex)
	if err != nil {
		return err
	}
	free, err := preflightDiskFree(ctx, r.b.ex, root)
	if err != nil {
		return err
	}
	required := imageBytes + volumeBytes + volumeBytes/volumeSpaceMargin + preflightHeadroom
	if free < required {
		return preflightFailed(causePreflightDiskLow,
			"%s has %d bytes free, %d are required for the images (manifest layer bytes, not unpacked size), the volumes and a margin", root, free, required)
	}
	return nil
}

// requireNoStrayVolumes refuses a volume of the map that exists on B without this move having created it: it is a
// conflict, never adopted or deleted.
func (r *moveRun) requireNoStrayVolumes(ctx context.Context) error {
	names, err := r.volumeNames(ctx)
	if err != nil || len(names) == 0 {
		return err
	}
	found, err := r.existingVolumes(ctx, r.b, names)
	if err != nil {
		return err
	}
	rows, err := database.ListAppMoveVolumes(ctx, r.h.cfg.DB.Reader(), r.move.ID)
	if err != nil {
		return err
	}
	ours := map[string]bool{}
	for _, v := range rows {
		ours[v.VolumeName] = v.CreatedByMove
	}
	for _, name := range names {
		if _, exists := found[name]; exists && !ours[name] {
			return preflightFailed(causeMoveVolumeExists, "volume %s already exists on node %s and this move did not create it", name, r.b.node.Name)
		}
	}
	return nil
}

// ---- reads -------------------------------------------------------------------------------------------------------

// volumeNames are the names of the move's volume map.
func (r *moveRun) volumeNames(ctx context.Context) ([]string, error) {
	rows, err := database.ListAppMoveVolumes(ctx, r.h.cfg.DB.Reader(), r.move.ID)
	names := make([]string, len(rows))
	for i, v := range rows {
		names[i] = v.VolumeName
	}
	return names, err
}

// containers reads the project's containers on n.
func (r *moveRun) containers(ctx context.Context, n moveNode) ([]templates.ContainerState, error) {
	out, err := preflightRead(ctx, n.ex, "compose.ps_state", map[string]string{"project": r.target.ComposeProject})
	if err != nil {
		return nil, err
	}
	containers, err := templates.ParsePsState(out, r.target.ComposeProject)
	if err != nil {
		return nil, preflightFailed(causePreflightUnreadable, "node %s: %v", n.node.Name, err)
	}
	return containers, nil
}

// existingVolumes reads which of names exist on n.
func (r *moveRun) existingVolumes(ctx context.Context, n moveNode, names []string) (map[string]templates.Volume, error) {
	out, err := preflightRead(ctx, n.ex, "docker.volume_inspect_many", map[string]string{"volumes": strings.Join(names, ",")})
	if err != nil {
		return nil, err
	}
	volumes, err := templates.ParseVolumeInspectMany(out)
	if err != nil {
		return nil, preflightFailed(causePreflightUnreadable, "node %s: %v", n.node.Name, err)
	}
	found := make(map[string]templates.Volume, len(volumes))
	for _, v := range volumes {
		found[v.Name] = v
	}
	return found, nil
}

// sourceSizes reads the size of each of the move's volumes on A, and their total. A volume whose size is not known
// is an error.
func (r *moveRun) sourceSizes(ctx context.Context) (map[string]int64, int64, error) {
	names, err := r.volumeNames(ctx)
	if err != nil || len(names) == 0 {
		return nil, 0, err
	}
	out, err := preflightRead(ctx, r.a.ex, "docker.volume_sizes", nil)
	if err != nil {
		return nil, 0, err
	}
	all, err := templates.ParseVolumeSizes(out)
	if err != nil {
		return nil, 0, preflightFailed(causePreflightUnreadable, "node %s: %v", r.a.node.Name, err)
	}
	sizes := make(map[string]int64, len(names))
	var total int64
	for _, name := range names {
		size, ok := all[name]
		if !ok {
			return nil, 0, preflightFailed(causeMoveVolumeMissing, "the size of volume %s on node %s is unknown", name, r.a.node.Name)
		}
		sizes[name] = size
		total += size
	}
	return sizes, total, nil
}

// requireExited reads the project's containers on n and refuses unless there is at least one and every one has
// exited: only then can a volume be copied without a writer.
func (r *moveRun) requireExited(ctx context.Context, n moveNode) error {
	containers, err := r.containers(ctx, n)
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return preflightFailed(causeMoveSourceStillActive, "node %s reports no container of the project", n.node.Name)
	}
	for _, c := range containers {
		if c.State != "exited" {
			return preflightFailed(causeMoveSourceStillActive, "container %s on node %s is %s, not exited", c.Name, n.node.Name, c.State)
		}
	}
	return nil
}

// ---- limits of the model -----------------------------------------------------------------------------------------

// limitModel is the part of a frozen Compose model that sets resource limits.
type limitModel struct {
	Services map[string]struct {
		MemLimit json.RawMessage `json:"mem_limit"`
		CPUs     json.RawMessage `json:"cpus"`
		Deploy   struct {
			Resources struct {
				Limits struct {
					Memory json.RawMessage `json:"memory"`
					CPUs   json.RawMessage `json:"cpus"`
				} `json:"limits"`
			} `json:"resources"`
		} `json:"deploy"`
	} `json:"services"`
}

// resourceLimits sums the memory limits of the services and returns the largest CPU limit. A limit it cannot read is
// an error, not zero.
func resourceLimits(effective json.RawMessage) (memory int64, cpus float64, err error) {
	var model limitModel
	if err := json.Unmarshal(effective, &model); err != nil {
		return 0, 0, fmt.Errorf("the model's resource limits are unreadable: %w", err)
	}
	for _, name := range sortedKeys(model.Services) {
		s := model.Services[name]
		for _, raw := range []json.RawMessage{s.MemLimit, s.Deploy.Resources.Limits.Memory} {
			bytes, err := limitBytes(raw)
			if err != nil {
				return 0, 0, fmt.Errorf("service %s: %w", name, err)
			}
			memory += bytes
			if bytes > 0 {
				break // the two spell one limit
			}
		}
		for _, raw := range []json.RawMessage{s.CPUs, s.Deploy.Resources.Limits.CPUs} {
			n, err := limitCPUs(raw)
			if err != nil {
				return 0, 0, fmt.Errorf("service %s: %w", name, err)
			}
			cpus = max(cpus, n)
		}
	}
	return memory, cpus, nil
}

var byteUnits = map[string]int64{"": 1, "b": 1, "k": 1 << 10, "kb": 1 << 10, "m": 1 << 20, "mb": 1 << 20, "g": 1 << 30, "gb": 1 << 30}

// limitBytes reads a memory limit written as a number of bytes or as a string such as "512m". Absent means none.
func limitBytes(raw json.RawMessage) (int64, error) {
	text, present := jsonLimitText(raw)
	if !present {
		return 0, nil
	}
	digits := strings.TrimRight(text, "bBkKmMgG")
	n, err := strconv.ParseInt(digits, 10, 64)
	unit, known := byteUnits[strings.ToLower(text[len(digits):])]
	if err != nil || n < 0 || !known || n > (1<<62)/unit {
		return 0, fmt.Errorf("memory limit %q is not a size", text)
	}
	return n * unit, nil
}

func limitCPUs(raw json.RawMessage) (float64, error) {
	text, present := jsonLimitText(raw)
	if !present {
		return 0, nil
	}
	n, err := strconv.ParseFloat(text, 64)
	if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("cpu limit %q is not a number", text)
	}
	return n, nil
}

// jsonLimitText is a limit's JSON as plain text; present is false when it is absent or null.
func jsonLimitText(raw json.RawMessage) (text string, present bool) {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return "", false
	}
	return strings.Trim(t, `"`), true
}
