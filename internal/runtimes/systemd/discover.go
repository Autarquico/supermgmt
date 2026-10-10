package systemd

import (
	"context"
	"path"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
)

// defaultExcludes keep the UI free of the machinery every systemd host runs;
// they apply only when the filter names no Include pattern (spec §16).
var defaultExcludes = []string{
	"systemd-*", "user@*", "user-runtime-dir@*", "*getty@*", "console-getty",
	"modprobe@*", "dpkg-*", "e2scrub*", "blk-availability", "lvm2-*",
}

// Discover lists loaded service units. Include and Exclude are shell globs on
// the unit name, with or without the `.service` suffix; Exclude wins.
func (Adapter) Discover(ctx context.Context, ex transport.Executor, f runtimes.Filter) (runtimes.Discovered, error) {
	selection, err := newSelection(f)
	if err != nil {
		return runtimes.Discovered{}, err
	}
	version, err := readVersion(ctx, ex)
	if err != nil {
		return runtimes.Discovered{}, err
	}
	out, err := succeeded(ctx, ex, "systemd.list_units", nil)
	if err != nil {
		return runtimes.Discovered{}, err
	}
	var services []runtimes.DiscoveredService
	for _, u := range parseUnits(out) {
		if u.load == "loaded" && selection.admits(u.name) {
			services = append(services, u.service())
		}
	}
	return runtimes.Discovered{
		Runtime: runtimes.DiscoveredRuntime{
			Type: domain.RuntimeSystemd, NativeID: "systemd", Version: version, Status: "running",
			Metadata: map[string]any{"units_listed": len(services)},
		},
		Services: services,
	}, nil
}

func readVersion(ctx context.Context, ex transport.Executor) (string, error) {
	out, err := succeeded(ctx, ex, "systemd.version", nil)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(out)
	if len(fields) < 2 || fields[0] != "systemd" {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "systemctl did not report a systemd version")
	}
	return sanitize(fields[1]), nil
}

type unitLine struct{ name, load, active, sub, description string }

func (u unitLine) service() runtimes.DiscoveredService {
	return runtimes.DiscoveredService{
		Kind: domain.ServiceSystemdUnit, NativeID: u.name, Name: u.name, Status: u.active,
		Metadata: map[string]any{"sub_state": u.sub, "load_state": u.load, "description": u.description},
	}
}

// parseUnits reads `systemctl list-units --plain --no-legend` lines:
// UNIT LOAD ACTIVE SUB DESCRIPTION. Malformed lines are skipped.
func parseUnits(out string) []unitLine {
	var units []unitLine
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "●"))
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		units = append(units, unitLine{
			name: sanitize(fields[0]), load: fields[1], active: fields[2], sub: fields[3],
			description: sanitize(strings.Join(fields[4:], " ")),
		})
	}
	return units
}

type selection struct{ include, exclude []string }

func newSelection(f runtimes.Filter) (selection, error) {
	s := selection{include: f.Include, exclude: f.Exclude}
	if len(f.Include) == 0 {
		s.exclude = append(append([]string{}, defaultExcludes...), f.Exclude...)
	}
	for _, pattern := range append(append([]string{}, s.include...), s.exclude...) {
		if _, err := path.Match(pattern, ""); err != nil {
			return selection{}, smerr.New(smerr.CodeInvalidArgument, "", "invalid filter pattern "+pattern)
		}
	}
	return s, nil
}

func (s selection) admits(unit string) bool {
	if matchesAny(s.exclude, unit) {
		return false
	}
	return len(s.include) == 0 || matchesAny(s.include, unit)
}

func matchesAny(patterns []string, unit string) bool {
	short := strings.TrimSuffix(unit, ".service")
	for _, p := range patterns {
		if ok, _ := path.Match(p, unit); ok {
			return true
		}
		if ok, _ := path.Match(p, short); ok {
			return true
		}
	}
	return false
}
