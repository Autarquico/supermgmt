package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/textsafe"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
)

// Stats reads CPU and memory of every running container in one sample. A
// Docker older than 23 does not know `--format json`: it prints the word
// "json" instead of objects, which reads as the capability being unavailable.
func (Adapter) Stats(ctx context.Context, ex transport.Executor) ([]runtimes.ContainerStats, error) {
	res, err := read(ctx, ex, "docker.stats", nil)
	if err != nil {
		return nil, err
	}
	if res.ExitStatus != 0 {
		return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "docker stats is unavailable")
	}
	if res.Truncated {
		return nil, smerr.New(smerr.CodeInternal, "", "docker stats output exceeds the template limit")
	}
	return parseStats(res.Stdout)
}

type statsLine struct {
	ID       string `json:"ID"`
	Name     string `json:"Name"`
	CPUPerc  string `json:"CPUPerc"`
	MemUsage string `json:"MemUsage"`
}

// parseStats reads one JSON object per line. A line that is not an object
// means the format is unsupported; a container whose figures do not read
// (`--` while it starts or stops) is left out.
func parseStats(out []byte) ([]runtimes.ContainerStats, error) {
	var stats []runtimes.ContainerStats
	for _, raw := range bytes.Split(out, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var l statsLine
		if err := json.Unmarshal(raw, &l); err != nil {
			return nil, smerr.New(smerr.CodeCapabilityUnavailable, "", "docker stats does not support json output")
		}
		cpu, okCPU := parsePercent(l.CPUPerc)
		used, limit, okMem := parseMemUsage(l.MemUsage)
		if okCPU && okMem {
			stats = append(stats, runtimes.ContainerStats{
				ID: textsafe.Line(l.ID), Name: textsafe.Line(l.Name),
				CPUPercent: cpu, MemUsedBytes: used, MemLimitBytes: limit,
			})
		}
	}
	return stats, nil
}

func parsePercent(s string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(s), "%"), 64)
	return v, err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

// parseMemUsage reads "1.5MiB / 2GiB".
func parseMemUsage(s string) (used, limit uint64, ok bool) {
	u, l, found := strings.Cut(s, " / ")
	if !found {
		return 0, 0, false
	}
	used, okUsed := parseSize(u)
	limit, okLimit := parseSize(l)
	return used, limit, okUsed && okLimit
}

var sizeUnits = map[string]float64{
	"B": 1, "kB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
	"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
}

// parseSize reads "1.5MiB": a plain decimal number followed by a unit.
func parseSize(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i <= 0 {
		return 0, false
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	mult, known := sizeUnits[s[i:]]
	bytes := n * mult
	if err != nil || !known || math.IsNaN(bytes) || bytes < 0 || bytes >= 1<<63 {
		return 0, false
	}
	return uint64(bytes), true
}
