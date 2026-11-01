package templates

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// The decoders of the reads an app move makes. Each fails closed: an unknown,
// missing, duplicated or overflowing value is an error, never a default.

// InfoResources is what docker.info_resources reports of a node.
type InfoResources struct {
	NCPU     int
	MemTotal int64
}

// ParseInfoResources decodes docker.info_resources: one JSON object with a
// positive NCPU and MemTotal.
func ParseInfoResources(stdout []byte) (InfoResources, error) {
	var raw struct {
		NCPU     *int   `json:"NCPU"`
		MemTotal *int64 `json:"MemTotal"`
	}
	if err := decodeOne(stdout, &raw, true); err != nil {
		return InfoResources{}, fmt.Errorf("docker info: %w", err)
	}
	if raw.NCPU == nil || raw.MemTotal == nil || *raw.NCPU <= 0 || *raw.MemTotal <= 0 {
		return InfoResources{}, errors.New("docker info: NCPU and MemTotal must be present and positive")
	}
	return InfoResources{NCPU: *raw.NCPU, MemTotal: *raw.MemTotal}, nil
}

// ParseVolumeSizes decodes docker.volume_sizes into bytes per volume name.
// Docker prints sizes with three significant digits ("3MB", "1.23GB"), so each
// is rounded up by one percent: the sizes feed a space check, which must not
// come out short. A volume whose size Docker does not know ("N/A") is an error.
func ParseVolumeSizes(stdout []byte) (map[string]int64, error) {
	var raw struct {
		Volumes *[]struct {
			Name string `json:"Name"`
			Size string `json:"Size"`
		} `json:"Volumes"`
	}
	if err := decodeOne(stdout, &raw, false); err != nil {
		return nil, fmt.Errorf("docker system df: %w", err)
	}
	if raw.Volumes == nil {
		return nil, errors.New("docker system df: no Volumes section")
	}
	sizes := make(map[string]int64, len(*raw.Volumes))
	for _, v := range *raw.Volumes {
		if err := ValidateVolume(v.Name); err != nil {
			return nil, fmt.Errorf("docker system df: volume %q: %w", v.Name, err)
		}
		if _, dup := sizes[v.Name]; dup {
			return nil, fmt.Errorf("docker system df: volume %q twice", v.Name)
		}
		n, err := parseHumanBytes(v.Size)
		if err != nil {
			return nil, fmt.Errorf("docker system df: volume %q: %w", v.Name, err)
		}
		sizes[v.Name] = n
	}
	return sizes, nil
}

var humanUnits = map[string]float64{"B": 1, "kB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "PB": 1e15}

func parseHumanBytes(s string) (int64, error) {
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i <= 0 {
		return 0, fmt.Errorf("unrecognized size %q", s)
	}
	unit, ok := humanUnits[s[i:]]
	value, err := strconv.ParseFloat(s[:i], 64)
	if !ok || err != nil || value < 0 || math.IsInf(value, 0) {
		return 0, fmt.Errorf("unrecognized size %q", s)
	}
	total := math.Ceil(value * unit * 1.01)
	if total >= math.MaxInt64 {
		return 0, fmt.Errorf("size %q overflows", s)
	}
	return int64(total), nil
}

// Volume is one entry of docker.volume_inspect_many.
type Volume struct {
	Name   string
	Driver string
	Labels map[string]string
}

// ParseVolumeInspectMany decodes docker.volume_inspect_many: a JSON array of
// the volumes that exist.
func ParseVolumeInspectMany(stdout []byte) ([]Volume, error) {
	var raw []struct {
		Name   string            `json:"Name"`
		Driver string            `json:"Driver"`
		Labels map[string]string `json:"Labels"`
	}
	if err := decodeOne(stdout, &raw, false); err != nil {
		return nil, fmt.Errorf("docker volume inspect: %w", err)
	}
	if raw == nil {
		return nil, errors.New("docker volume inspect: not an array")
	}
	seen := map[string]bool{}
	volumes := make([]Volume, 0, len(raw))
	for _, v := range raw {
		if err := ValidateVolume(v.Name); err != nil || v.Driver == "" || seen[v.Name] {
			return nil, fmt.Errorf("docker volume inspect: unusable volume %q", v.Name)
		}
		seen[v.Name] = true
		volumes = append(volumes, Volume{Name: v.Name, Driver: v.Driver, Labels: v.Labels})
	}
	return volumes, nil
}

// ContainerState is one line of compose.ps_state.
type ContainerState struct {
	ID      string
	Name    string
	Service string
	State   string // created, running, paused, restarting, removing, exited or dead
	Labels  map[string]string
}

const composeProjectLabel, composeServiceLabel = "com.docker.compose.project", "com.docker.compose.service"

var containerStates = map[string]bool{
	"created": true, "running": true, "paused": true, "restarting": true, "removing": true, "exited": true, "dead": true,
}

// ParsePsState decodes compose.ps_state for project: one JSON object per line.
// Every container must carry the project's Compose label and a service.
func ParsePsState(stdout []byte, project string) ([]ContainerState, error) {
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, nil
	}
	var out []ContainerState
	for line := range strings.SplitSeq(strings.TrimSuffix(string(stdout), "\n"), "\n") {
		var raw struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			State  string `json:"State"`
			Labels string `json:"Labels"`
		}
		if err := decodeOne([]byte(line), &raw, false); err != nil {
			return nil, fmt.Errorf("docker ps: %w", err)
		}
		labels, err := parseLabels(raw.Labels)
		if err != nil {
			return nil, fmt.Errorf("docker ps: container %.12s: %w", raw.ID, err)
		}
		c := ContainerState{ID: raw.ID, Name: raw.Names, Service: labels[composeServiceLabel], State: raw.State, Labels: labels}
		if raw.ID == "" || ValidateContainer(raw.ID) != nil || ValidateContainer(raw.Names) != nil || c.Service == "" ||
			!containerStates[raw.State] || labels[composeProjectLabel] != project {
			return nil, fmt.Errorf("docker ps: unusable container %.12s", raw.ID)
		}
		out = append(out, c)
	}
	return out, nil
}

// parseLabels splits docker ps's "k=v,k=v" labels. A segment without "=" means
// a comma inside a value, which cannot be told apart from a separator: refused.
func parseLabels(s string) (map[string]string, error) {
	labels := map[string]string{}
	if s == "" {
		return labels, nil
	}
	for seg := range strings.SplitSeq(s, ",") {
		k, v, ok := strings.Cut(seg, "=")
		if !ok || k == "" {
			return nil, errors.New("labels are ambiguous")
		}
		if _, dup := labels[k]; dup {
			return nil, errors.New("a label twice")
		}
		labels[k] = v
	}
	return labels, nil
}

// decodeOne decodes exactly one JSON value, with nothing after it.
func decodeOne(data []byte, v any, strict bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}
