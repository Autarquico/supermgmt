package templates

import (
	"fmt"
	"strconv"
	"strings"
)

// markerStateScript reports where a marker stands. "absent" is claimed only
// when the markers directory is readable and searchable: an inaccessible
// directory is "unavailable", never evidence that nothing was started.
// The marker name arrives as $1.
const markerStateScript = `
d=@MARKERS@; m="$d/$1"
if [ ! -d "$d" ] || [ ! -x "$d" ]; then echo unavailable
elif [ ! -e "$m" ]; then echo absent
elif [ -f "$m.done" ]; then printf "done %s\n" "$(head -n 1 "$m.done")"
else echo started; fi
`

// markerTemplates holds the marker presence and .done reads used as completion evidence (spec §20.4).
var markerTemplates = []Template{{
	Name:     "marker.state",
	Body:     "sh -c " + Quote(strings.ReplaceAll(markerStateScript, "@MARKERS@", MarkerDir)) + " sh {{marker}}",
	Params:   []Param{{Name: "marker", Validate: Matching(markerPattern)}},
	MaxBytes: 256,
	MaxLines: 2,
}}

// MarkerKind is where a mutating command stands according to its marker.
type MarkerKind string

const (
	// MarkerUnavailable: the markers directory cannot be read. No conclusion.
	MarkerUnavailable MarkerKind = "unavailable"
	// MarkerAbsent: the directory is readable and the marker does not exist,
	// so the command never began (spec §20.4).
	MarkerAbsent MarkerKind = "absent"
	// MarkerStarted: the marker exists, there is no .done yet.
	MarkerStarted MarkerKind = "started"
	// MarkerDone: .done exists and holds ExitStatus.
	MarkerDone MarkerKind = "done"
)

// MarkerState is the parsed output of the marker.state template.
type MarkerState struct {
	Kind       MarkerKind
	ExitStatus int // meaningful only for MarkerDone
}

// CompletionProof reports ADR-0015's completion proof: .done holding exit 0.
func (s MarkerState) CompletionProof() bool { return s.Kind == MarkerDone && s.ExitStatus == 0 }

// ParseMarkerState parses marker.state output strictly; anything else is an
// error, so garbage can never be read as "absent" or as a proof.
func ParseMarkerState(stdout []byte) (MarkerState, error) {
	line := strings.TrimSuffix(string(stdout), "\n")
	switch MarkerKind(line) {
	case MarkerUnavailable, MarkerAbsent, MarkerStarted:
		return MarkerState{Kind: MarkerKind(line)}, nil
	case MarkerDone:
		// A bare "done" carries no status; only "done <n>" is valid, below.
	}
	if status, ok := strings.CutPrefix(line, "done "); ok {
		n, err := strconv.Atoi(status)
		if err == nil && n >= 0 && n <= 255 && strconv.Itoa(n) == status {
			return MarkerState{Kind: MarkerDone, ExitStatus: n}, nil
		}
	}
	return MarkerState{}, fmt.Errorf("unrecognized marker state %q", line)
}
