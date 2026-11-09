package app

import (
	"cmp"
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

var (
	tailArg  = regexp.MustCompile(`--tail '(\d+)'`)
	sinceArg = regexp.MustCompile(`--since '([^']+)'`)
	idArg    = regexp.MustCompile(`-- '([0-9a-f]+)'`)
)

// writeLog makes the node answer both log templates from the lines it holds per container, the way Docker
// does: --since is inclusive and --tail keeps the last lines of what is left.
func (f *appsFixture) writeLog(container string, lines *[]string) {
	if f.held == nil {
		f.held = map[string]*[]string{}
		read := func(c templates.Command) (transport.Result, error) {
			held := f.held[idArg.FindStringSubmatch(c.Line)[1]]
			if held == nil {
				return transport.Result{}, nil
			}
			n, _ := strconv.Atoi(tailArg.FindStringSubmatch(c.Line)[1])
			var out []string
			for _, l := range *held {
				if m := sinceArg.FindStringSubmatch(c.Line); m != nil {
					since, _ := time.Parse(time.RFC3339Nano, m[1])
					if at, _ := stampOf(l); at.Before(since) {
						continue
					}
				}
				out = append(out, l)
			}
			out = out[max(len(out)-n, 0):]
			return transport.Result{Stdout: []byte(strings.Join(out, "\n") + "\n")}, nil
		}
		f.node.on("docker.logs", read).on("docker.logs_since", read)
	}
	f.held[container] = lines
}

func (f *appsFixture) logs(q wire.AppLogQuery) wire.AppLogs {
	f.t.Helper()
	q.Component = cmp.Or(q.Component, "web")
	got, err := f.inv.AppLogs(context.Background(), f.caller(f.alice), f.nodeID(), "shop", q)
	mustf(f.t, err, "AppLogs")
	return got
}

func stampedRange(from, to int) []string {
	var out []string
	for i := from; i < to; i++ {
		out = append(out, stamped(i%60, "line "+strconv.Itoa(i)))
	}
	return out
}

func TestFollowAtTheDefaultWindowDeliversTheNewLineAndNoGap(t *testing.T) {
	f := newAppsFixture(t)
	var held []string
	for i := range 200 {
		held = append(held, time.Date(2026, 11, 9, 10, i, 0, 0, time.UTC).Format(time.RFC3339Nano)+" line "+strconv.Itoa(i))
	}
	f.writeLog(webID, &held)
	first := f.logs(wire.AppLogQuery{})
	held = append(held, time.Date(2026, 11, 9, 14, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)+" the new line")

	next := f.logs(wire.AppLogQuery{Cursor: first.Cursor})

	if len(next.Lines) != 1 || !strings.HasSuffix(next.Lines[0], "the new line") || next.Gap {
		t.Errorf("follow = %d lines %q gap %v, want only the new line and no gap", len(next.Lines), next.Lines, next.Gap)
	}
}

func TestFollowThatTheNodeCutInsideABurstOfOneStampReportsAGap(t *testing.T) {
	f := newAppsFixture(t)
	var held []string
	for i := range 200 {
		held = append(held, stamped(1, "burst "+strconv.Itoa(i)))
	}
	f.writeLog(webID, &held)
	first := f.logs(wire.AppLogQuery{})
	held = append(held, stamped(1, "burst 200"))

	next := f.logs(wire.AppLogQuery{Cursor: first.Cursor})

	delivered := strings.Join(next.Lines, "\n")
	if !next.Gap && !strings.Contains(delivered, "burst 200") {
		t.Errorf("a new line was lost without a gap: lines %q", next.Lines)
	}
}

func TestFollowWithMoreNewLinesThanAskedDeliversTheNewestWithAGapAndNoRepeats(t *testing.T) {
	f := newAppsFixture(t)
	held := stampedRange(0, 5)
	f.writeLog(webID, &held)
	first := f.logs(wire.AppLogQuery{Lines: 3})
	held = append(held, stampedRange(5, 15)...)

	next := f.logs(wire.AppLogQuery{Lines: 3, Cursor: first.Cursor})

	if !next.Gap || len(next.Lines) != 3 || !strings.HasSuffix(next.Lines[2], "line 14") || !strings.HasSuffix(next.Lines[0], "line 12") {
		t.Errorf("lines %q gap %v, want the newest three and a gap", next.Lines, next.Gap)
	}
}

const pemBody = "MIIEpDUMMYPEMBODYLINE"

func keyLog(from int) []string {
	return []string{
		stamped(from, "starting"), stamped(from+1, "-----BEGIN RSA PRIVATE KEY-----"), stamped(from+2, pemBody+"1"),
		stamped(from+3, pemBody+"2"), stamped(from+4, "-----END RSA PRIVATE KEY-----"), stamped(from+5, "after"),
	}
}

func TestNoPEMBodyLineLeavesWhateverTheTailWindowOrCursor(t *testing.T) {
	f := newAppsFixture(t)
	held := keyLog(0)
	f.writeLog(webID, &held)
	forged := logCursor{Since: time.Date(2026, 11, 9, 10, 0, 2, 0, time.UTC)}.encode()
	cases := map[string]wire.AppLogs{
		"recent cut inside the block": f.logs(wire.AppLogQuery{Lines: 3}),
		"recent cut at the end line":  f.logs(wire.AppLogQuery{Lines: 2}),
		"cursor inside the block":     f.logs(wire.AppLogQuery{Cursor: forged, Lines: 5}),
		"search":                      f.logs(wire.AppLogQuery{Search: "DUMMYPEM"}),
		"search for after":            f.logs(wire.AppLogQuery{Search: "after"}),
	}
	for name, got := range cases {
		if strings.Contains(strings.Join(got.Lines, "\n"), pemBody) {
			t.Errorf("%s leaked the key: %q", name, got.Lines)
		}
	}
}

func TestAWindowThatCutsABlockIsRedactedFromTheOverlapRead(t *testing.T) {
	f := newAppsFixture(t)
	held := keyLog(0)
	f.writeLog(webID, &held)

	got := f.logs(wire.AppLogQuery{Lines: 2})

	if len(got.Lines) != 2 || !strings.HasSuffix(got.Lines[0], audit.Redacted) || !strings.HasSuffix(got.Lines[1], "after") {
		t.Errorf("lines = %q, want the end line as a marker and the line after the block", got.Lines)
	}
}

func TestScrubLinesMasksFromTheStartOfAChunkThroughAnENDWithNoBEGIN(t *testing.T) {
	got := scrubLines([]string{"b3Blbn", "QUFB", "-----END OPENSSH PRIVATE KEY----- tail", "next"})

	if len(got) != 4 || got[0].text != audit.Redacted || got[1].text != audit.Redacted || got[2].text != audit.Redacted+" tail" || got[3].text != "next" {
		t.Errorf("lines = %+v", got)
	}
	whole := scrubLines([]string{"-----BEGIN RSA PRIVATE KEY-----", "body", "-----END RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "x"})
	if strings.Contains(strings.Join(texts(whole), "\n"), "body") {
		t.Errorf("a block with its BEGIN was not masked: %+v", whole)
	}
}

func TestALineEndingInASensitiveKeyDoesNotTakeTheNextLineAsItsValue(t *testing.T) {
	got := scrubLines([]string{stamped(1, "Enter password:"), stamped(2, "next line"), stamped(3, "third")})

	if len(got) != 3 || got[0].text != stamped(1, "Enter password:") || got[1].raw != 1 || got[1].text != stamped(2, "next line") || got[2].text != stamped(3, "third") {
		t.Fatalf("lines = %+v", got)
	}
}

func TestFollowDeliversTheLineAfterOneEndingInASensitiveKey(t *testing.T) {
	f := newAppsFixture(t)
	held := []string{stamped(1, "Enter password:")}
	f.writeLog(webID, &held)
	first := f.logs(wire.AppLogQuery{})
	held = append(held, stamped(2, "next line"))

	next := f.logs(wire.AppLogQuery{Cursor: first.Cursor})

	if len(next.Lines) != 1 || next.Lines[0] != stamped(2, "next line") || next.Gap {
		t.Errorf("lines %q gap %v", next.Lines, next.Gap)
	}
}

func TestAChunkWithAHeaderMentionKeepsTheOrdinaryLinesAround(t *testing.T) {
	got := scrubLines([]string{
		"boot", "pem: expected -----BEGIN RSA PRIVATE KEY----- header, got garbage", "request handled", "request handled again",
	})

	if len(got) != 4 || got[0].text != "boot" || got[1].text != "pem: expected "+audit.Redacted || got[2].text != "request handled" || got[3].text != "request handled again" {
		t.Errorf("lines = %+v", got)
	}
}

func TestALoneENDLineHidesNoOrdinaryLineBeforeIt(t *testing.T) {
	got := scrubLines([]string{"boot", "request handled", "saw -----END PRIVATE KEY-----", "request handled again"})

	if len(got) != 4 || got[0].text != "boot" || got[1].text != "request handled" || got[3].text != "request handled again" {
		t.Errorf("lines = %+v", got)
	}
}

func TestABlockEndsAtTheFirstLineThatIsNotKeyMaterial(t *testing.T) {
	got := scrubLines([]string{"-----BEGIN PRIVATE KEY-----", pemBody, "not key material", pemBody + "x"})

	if got[1].text != audit.Redacted || got[2].text != "not key material" || got[3].text != pemBody+"x" {
		t.Errorf("lines = %+v", got)
	}
}

func TestAHeaderMentionDoesNotBlindRecentFollowOrSearch(t *testing.T) {
	f := newAppsFixture(t)
	held := []string{
		stamped(0, "boot"), stamped(1, "pem: expected -----BEGIN RSA PRIVATE KEY----- header"), stamped(2, "request handled"),
	}
	f.writeLog(webID, &held)

	first := f.logs(wire.AppLogQuery{})
	held = append(held, stamped(3, "request handled again"))
	next := f.logs(wire.AppLogQuery{Cursor: first.Cursor})
	found := f.logs(wire.AppLogQuery{Search: "request handled"})

	if len(first.Lines) != 3 || !strings.HasSuffix(first.Lines[2], "request handled") {
		t.Errorf("recent = %q", first.Lines)
	}
	if len(next.Lines) != 1 || !strings.HasSuffix(next.Lines[0], "request handled again") {
		t.Errorf("follow = %q, want the new line within one poll", next.Lines)
	}
	if len(found.Lines) != 2 {
		t.Errorf("search = %q, want both request lines", found.Lines)
	}
}
