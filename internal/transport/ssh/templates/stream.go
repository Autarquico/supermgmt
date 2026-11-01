package templates

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// StreamKind says which end of the session the caller moves: the stdout of an
// export or the stdin of an import.
type StreamKind int

const (
	StreamNone StreamKind = iota
	StreamExport
	StreamImport
)

// MaxStreamDeadline bounds the node-side timeout of a stream.
const MaxStreamDeadline = 24 * time.Hour

var (
	volumePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	deadlinePattern = regexp.MustCompile(`^[1-9][0-9]{0,5}s$`)
)

// ValidateVolume accepts a Docker volume name.
func ValidateVolume(s string) error {
	if !volumePattern.MatchString(s) {
		return fmt.Errorf("not a volume name")
	}
	return nil
}

func validateDeadline(s string) error {
	_, err := parseDeadlineArg(s)
	return err
}

// DeadlineArg is the `deadline` argument of a streaming template for d, rounded
// up to whole seconds.
func DeadlineArg(d time.Duration) string { return seconds(d) }

func parseDeadlineArg(s string) (time.Duration, error) {
	if !deadlinePattern.MatchString(s) {
		return 0, fmt.Errorf("deadline must be whole seconds such as 600s")
	}
	n, _ := strconv.Atoi(s[:len(s)-1])
	if d := time.Duration(n) * time.Second; d <= MaxStreamDeadline {
		return d, nil
	}
	return 0, fmt.Errorf("deadline exceeds %s", MaxStreamDeadline)
}

var streamParams = []Param{
	paramContainer,
	{Name: "mount", Validate: ValidateCleanPath},
	{Name: "deadline", Validate: validateDeadline},
}

// streamTemplates holds the volume copy of an app move (spec app-move §5):
// docker cp between a container's mount and a tar on the session. The tar of
// an export is rooted at the mount's contents; an import extracts it into the
// mount. Both run under `timeout`, so neither outlives its deadline when the
// daemon loses the session.
var streamTemplates = []Template{
	{
		Name: "docker.volume_export", Params: streamParams, Stream: StreamExport, MaxBytes: 4 << 10,
		Body: "timeout -k " + killArg + " {{deadline}} docker cp {{container}}:{{mount}}/. -",
	},
	{
		Name: "docker.volume_import", Params: streamParams, Stream: StreamImport, MaxBytes: 4 << 10,
		Body: "timeout -k " + killArg + " {{deadline}} docker cp - {{container}}:{{mount}}",
	},
}

var killArg = seconds(KillAfter)
