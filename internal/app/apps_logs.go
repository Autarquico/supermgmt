package app

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	// followOverlap is how many lines a follow poll reads again before the ones it has not delivered: a
	// credential that spans lines (a PEM block) and was split by the previous poll is whole again in this one.
	// A block longer than this is not caught when it is split.
	followOverlap = 200
	// searchWindow is how many recent lines a search reads and examines.
	searchWindow = 2000
	// searchMatches is the most matching lines a search returns.
	searchMatches = 200
	// errorWindow is how many recent lines of a component are examined for its recent error count.
	errorWindow = 200
)

var errorLine = regexp.MustCompile(`(?i)\b(error|fatal|panic)\b`)

// logCursor says where a follow stands: the line stamped Since and the Skip lines from it on were delivered.
// The next poll reads from Since, which is up to followOverlap lines back, and drops Skip lines.
type logCursor struct {
	Since time.Time `json:"s"`
	Skip  int       `json:"k"`
}

func (c logCursor) encode() string {
	raw, _ := json.Marshal(c) // two plain fields cannot fail
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeLogCursor(s string) (logCursor, error) {
	invalid := smerr.New(smerr.CodeInvalidArgument, "", "invalid cursor")
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return logCursor{}, invalid
	}
	var c logCursor
	if err := json.Unmarshal(raw, &c); err != nil || c.Skip < 0 || c.Skip > runtimes.MaxLogLines || c.Since.IsZero() {
		return logCursor{}, invalid
	}
	return c, nil
}

// stampOf reads the RFC 3339 timestamp Docker puts first on every line.
func stampOf(line string) (time.Time, bool) {
	token, _, _ := strings.Cut(line, " ")
	t, err := time.Parse(time.RFC3339Nano, token)
	return t.UTC(), err == nil
}

// scrubbedLine is a line after redaction and the index of the raw line it started at.
type scrubbedLine struct {
	raw  int
	text string
}

var lineMarker = regexp.MustCompile("\x00([0-9]+)\x00")

// scrubLines redacts the lines as one text, so a credential that spans lines cannot survive, and says which
// raw line each surviving line started at. A redacted block collapses into the line it began on. Raw lines
// carry no control characters, so the markers cannot clash with their text.
func scrubLines(raw []string) []scrubbedLine {
	var b strings.Builder
	for i, line := range raw {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("\x00" + strconv.Itoa(i) + "\x00" + line)
	}
	scrubbed := audit.ScrubCredentials(b.String())
	marks := lineMarker.FindAllStringSubmatchIndex(scrubbed, -1)
	out := make([]scrubbedLine, 0, len(marks))
	for k, m := range marks {
		end := len(scrubbed)
		if k+1 < len(marks) {
			end = marks[k+1][0]
		}
		index, _ := strconv.Atoi(scrubbed[m[2]:m[3]])
		out = append(out, scrubbedLine{raw: index, text: strings.TrimSuffix(scrubbed[m[1]:end], "\n")})
	}
	return out
}

func texts(lines []scrubbedLine) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.text
	}
	return out
}

// recent is the first read of a follow: the last lines, and the cursor from which to continue.
func (a appLogReader) recent(lines int) (wire.AppLogs, error) {
	chunk, err := a.tail(lines)
	if err != nil {
		return wire.AppLogs{}, err
	}
	out := a.result(texts(scrubLines(chunk.Lines)))
	out.Truncated = chunk.Truncated
	cursor, ok := nextCursor(chunk.Lines, time.Unix(0, 0).UTC())
	out.Cursor, out.Gap = cursor.encode(), !ok
	return out, nil
}

// follow reads what came after cursor. The lines of the overlap are read and redacted together with the new
// ones and only the new ones are returned.
func (a appLogReader) follow(cursor string, lines int) (wire.AppLogs, error) {
	at, err := decodeLogCursor(cursor)
	if err != nil {
		return wire.AppLogs{}, err
	}
	chunk, err := a.since(at.Since, lines)
	if err != nil {
		return wire.AppLogs{}, err
	}
	skip, gap := at.Skip, chunk.Truncated
	if skip > 0 {
		first, ok := stampOf(firstOf(chunk.Lines))
		if len(chunk.Lines) < skip || !ok || !first.Equal(at.Since) {
			skip, gap = 0, true // the lines the cursor stood on are gone: rotated, or cut by the line limit
		}
	} else if len(chunk.Lines) >= lines {
		gap = true // more lines than asked for may have been written since
	}
	var fresh []string
	for _, l := range scrubLines(chunk.Lines) {
		if l.raw >= skip {
			fresh = append(fresh, l.text)
		}
	}
	out := a.result(fresh)
	next, ok := nextCursor(chunk.Lines, at.Since)
	out.Cursor, out.Gap, out.Truncated = next.encode(), gap || !ok, chunk.Truncated
	return out, nil
}

func firstOf(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

// nextCursor stands on the line followOverlap lines from the end, moved back to the first line of its
// timestamp, because Docker's boundary is inclusive and lines of a burst share a timestamp. Without a
// timestamp to stand on it keeps fallback and says so.
func nextCursor(lines []string, fallback time.Time) (cursor logCursor, ok bool) {
	if len(lines) == 0 {
		return logCursor{Since: fallback}, true
	}
	start := max(len(lines)-followOverlap, 0)
	since, found := stampOf(lines[start])
	for !found && start > 0 {
		start--
		since, found = stampOf(lines[start])
	}
	if !found {
		return logCursor{Since: fallback}, false
	}
	for start > 0 {
		if before, ok := stampOf(lines[start-1]); !ok || !before.Equal(since) {
			break
		}
		start--
	}
	return logCursor{Since: since, Skip: len(lines) - start}, true
}

// search looks for term in the recent window after redaction: the term is never sent to the node, and a
// secret cannot be probed for because what matches is what is left.
func (a appLogReader) search(term string) (wire.AppLogs, error) {
	if term == "" || textsafe.Line(term) != term {
		return wire.AppLogs{}, smerr.New(smerr.CodeInvalidArgument, "", "search term must be a non-empty single line without control characters")
	}
	chunk, err := a.tail(searchWindow)
	if err != nil {
		return wire.AppLogs{}, err
	}
	needle := strings.ToLower(term)
	var matches []string
	for _, l := range scrubLines(chunk.Lines) {
		if strings.Contains(strings.ToLower(l.text), needle) {
			matches = append(matches, l.text)
		}
	}
	truncated := chunk.Truncated
	if len(matches) > searchMatches {
		matches, truncated = matches[len(matches)-searchMatches:], true
	}
	out := a.result(matches)
	out.Truncated = truncated
	out.Window = windowOf(chunk.Lines)
	return out, nil
}

func windowOf(lines []string) *wire.LogWindow {
	w := &wire.LogWindow{Lines: len(lines)}
	for _, l := range lines {
		if t, ok := stampOf(l); ok {
			w.From = &t
			break
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if t, ok := stampOf(lines[i]); ok {
			w.To = &t
			break
		}
	}
	return w
}

// recentErrors counts the lines of the recent window that read as errors.
func recentErrors(lines []string) int {
	n := 0
	for _, l := range lines {
		if errorLine.MatchString(l) {
			n++
		}
	}
	return n
}
