package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

const (
	maxInputLine = 1 << 20
	markerCells  = 3 // "| " plus one cell of margin against terminals that wrap early
	minRowCells  = 10
	tabCells     = 8
)

// readLines delivers the lines of r; the channel closes at the end of input.
// inputErr, valid once the channel is closed, says if that was a failure, such
// as a line too long to read.
func readLines(r io.Reader) (lines <-chan string, inputErr func() error) {
	ch := make(chan string)
	var failure error
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), maxInputLine)
		for sc.Scan() {
			ch <- sc.Text()
		}
		failure = sc.Err()
	}()
	return ch, func() error { return failure }
}

type assistantRepl struct {
	out      io.Writer
	session  assistantSession
	lines    <-chan string
	inputErr func() error
	approver *approver
	greeting string
	width    int  // terminal columns, 0 when output is not a terminal
	failed   bool // the session was refused or ended on its own
}

// run converses until /exit or the end of input. It fails when the session was
// refused or ended by itself, so a script can tell it from a normal end.
func (r *assistantRepl) run(ctx context.Context) error {
	note(r.out, "%s", r.greeting)
	r.loop(ctx)
	if r.failed {
		return &childExitError{code: exitInternal}
	}
	return nil
}

func (r *assistantRepl) loop(ctx context.Context) {
	for {
		_, _ = fmt.Fprint(r.out, "> ")
		line, ok := nextLine(ctx, r.lines)
		if !ok {
			_, _ = fmt.Fprintln(r.out)
			if ctx.Err() == nil {
				if err := r.inputErr(); err != nil {
					note(r.out, "input ended: a line was longer than %d KiB or could not be read", maxInputLine>>10)
				}
			}
			return
		}
		switch line = strings.TrimSpace(line); line {
		case "":
		case "/exit":
			return
		default:
			if r.converse(ctx, line) {
				return
			}
		}
	}
}

// converse sends text and keeps going while the operator's decisions give the
// model something to be told. It reports whether the session is over.
func (r *assistantRepl) converse(ctx context.Context, text string) (over bool) {
	for text != "" {
		note(r.out, "working...")
		if err := r.session.Send(text); err != nil {
			t := r.drain(ctx)
			if !t.explained {
				note(r.out, "the assistant is gone: %s", textsafe.Line(err.Error()))
			}
			r.failed = true
			return true
		}
		t := r.drain(ctx)
		if t.over || ctx.Err() != nil {
			return true
		}
		if text = r.approver.settle(ctx, t.signals); ctx.Err() != nil {
			return true
		}
	}
	return false
}

// modelTurn is what one model turn left behind.
type modelTurn struct {
	signals   []assistant.Signal
	over      bool // the session ended
	explained bool // the operator was told why
}

// drain prints one turn and collects the approval signals it raised. When the
// session ends it waits for the event channel to close, so nothing it reports
// is lost.
func (r *assistantRepl) drain(ctx context.Context) modelTurn {
	var t modelTurn
	seen := map[domain.ID]bool{}
	for {
		if ctx.Err() != nil {
			t.over = true
			return t
		}
		select {
		case <-ctx.Done():
			t.over = true
			return t
		case ev, ok := <-r.session.Events():
			if !ok {
				if ctx.Err() == nil {
					r.failed = true
				}
				t.over = true
				return t
			}
			if r.handle(ev, seen, &t) {
				return t
			}
		}
	}
}

// handle reports whether the turn is complete.
func (r *assistantRepl) handle(ev assistant.Event, seen map[domain.ID]bool, t *modelTurn) bool {
	switch ev.Kind {
	case assistant.KindText:
		r.say(ev.Text)
	case assistant.KindToolCall:
		r.say("[tool] " + ev.Text)
	case assistant.KindToolResult:
		r.say("[result] " + ev.Text)
	case assistant.KindApproval:
		if ev.Approval != nil && !seen[ev.Approval.JobID] {
			seen[ev.Approval.JobID] = true
			t.signals = append(t.signals, *ev.Approval)
		}
	case assistant.KindTurnDone:
		return true
	case assistant.KindError:
		note(r.out, "error: %s", textsafe.Line(ev.Text))
		if ev.Fatal {
			r.failed, t.explained = true, true
		}
	case assistant.KindEnded:
		if !t.explained {
			note(r.out, "%s", textsafe.Line(ev.Text))
		}
		r.failed = r.failed || ev.Err != nil
		t.explained = true
	}
	return false
}

// say prints what the model or a remote system wrote. Every row it takes on the
// terminal carries the marker, so that nothing in it can pass for one of ours (a
// card or a note), however the terminal wraps or tabs it.
func (r *assistantRepl) say(text string) {
	cells := 0
	if r.width > 0 {
		cells = max(r.width-markerCells, minRowCells)
	}
	for _, line := range strings.Split(text, "\n") {
		for _, row := range wrapCells(line, cells) {
			_, _ = fmt.Fprintf(r.out, "| %s\n", row)
		}
	}
}

// wrapCells cuts line into rows that fit in cells terminal columns, at a space
// where there is one. A glyph beyond the Latin range is counted as two columns
// and a tab as eight, which can only make a row shorter than needed. Without a
// width (cells is 0) the line stays whole.
func wrapCells(line string, cells int) []string {
	if cells <= 0 {
		return []string{line}
	}
	var rows []string
	runes := []rune(line)
	for {
		used, cut, space := 0, 0, -1
		for cut < len(runes) && used+runeCells(runes[cut]) <= cells {
			used += runeCells(runes[cut])
			if runes[cut] == ' ' {
				space = cut
			}
			cut++
		}
		if cut == len(runes) {
			return append(rows, string(runes))
		}
		if space > 0 {
			cut = space
		}
		if cut == 0 {
			cut = 1
		}
		rows = append(rows, string(runes[:cut]))
		runes = runes[cut:]
	}
}

func runeCells(r rune) int {
	switch {
	case r == '\t':
		return tabCells
	case r >= 0x1100:
		return 2
	}
	return 1
}

// note prints a line of sm's own, marked [sm].
func note(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, "[sm] "+format+"\n", args...)
}

// nextLine is the next input line; false at the end of input or on cancel.
func nextLine(ctx context.Context, lines <-chan string) (string, bool) {
	select {
	case <-ctx.Done():
		return "", false
	case line, ok := <-lines:
		return line, ok
	}
}
