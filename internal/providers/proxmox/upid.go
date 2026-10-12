package proxmox

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// correlationMargin widens the dispatch window on both sides (ADR-0025).
const correlationMargin = 120 * time.Second

var (
	nodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
	taskTypePattern = regexp.MustCompile(`^[a-z0-9]+$`)
)

// ParseUPID decodes
// UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:
// where pid, pstart and starttime are hexadecimal. Anything else is an error:
// a task id that is not understood must never be guessed at.
func ParseUPID(s string) (UPID, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 9 || parts[0] != "UPID" || parts[8] != "" {
		return UPID{}, fmt.Errorf("proxmox: malformed UPID %q", s)
	}
	node, typ, id, user := parts[1], parts[5], parts[6], parts[7]
	if !nodeNamePattern.MatchString(node) || !taskTypePattern.MatchString(typ) || user == "" {
		return UPID{}, fmt.Errorf("proxmox: malformed UPID %q", s)
	}
	var hex [3]int64
	for i, field := range parts[2:5] {
		n, err := strconv.ParseInt(field, 16, 64)
		if err != nil || n < 0 || field == "" || strings.HasPrefix(field, "+") {
			return UPID{}, fmt.Errorf("proxmox: malformed UPID %q", s)
		}
		hex[i] = n
	}
	return UPID{
		Raw: s, Node: node, PID: hex[0], PStart: hex[1], StartTime: time.Unix(hex[2], 0).UTC(),
		Type: typ, ID: id, User: user,
	}, nil
}

// TaskType is the UPID task type a power verb produces on a guest type.
func TaskType(t GuestType, verb string) (string, error) {
	prefix := map[GuestType]string{GuestQEMU: "qm", GuestLXC: "vz"}[t]
	if prefix == "" || !validVerb(verb) {
		return "", fmt.Errorf("proxmox: no task type for %q on %q", verb, t)
	}
	return prefix + verb, nil
}

// CorrelationWindow is the range of task start times a dispatch made at
// dispatchedAt may have produced (ADR-0025).
func CorrelationWindow(dispatchedAt time.Time, httpTimeout time.Duration) (from, until time.Time) {
	return dispatchedAt.Add(-correlationMargin), dispatchedAt.Add(httpTimeout + correlationMargin)
}

// Correlate finds the one task a dispatch without a recorded UPID started:
// the type, guest id and user must match exactly (no substrings) and the start
// time must lie inside the window. A task listed twice counts once, and one in want.Known never counts. Zero or
// several matches return CorrelatedNone or CorrelatedMany and a zero UPID.
func Correlate(tasks []TaskStatus, want Want) (UPID, CorrelationResult) {
	id := strconv.Itoa(want.VMID)
	seen := map[string]bool{}
	for _, known := range want.Known {
		seen[known] = true
	}
	var found []UPID
	for _, t := range tasks {
		u := t.UPID
		if u.Type != want.Type || u.ID != id || u.User != want.User || seen[u.Raw] {
			continue
		}
		if u.StartTime.Before(want.From) || u.StartTime.After(want.Until) {
			continue
		}
		seen[u.Raw] = true
		found = append(found, u)
	}
	switch len(found) {
	case 0:
		return UPID{}, CorrelatedNone
	case 1:
		return found[0], CorrelatedOne
	}
	return UPID{}, CorrelatedMany
}
