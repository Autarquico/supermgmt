package m1

import (
	"regexp"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/tui"
)

// tuiDriver runs the TUI model without a terminal, the way Bubble Tea's
// runtime does: keys and replies go through Update, and the commands Update
// returns run afterwards. It stands in for the operator's screen.
type tuiDriver struct {
	t *testing.T
	m *tui.Model
}

func newTUI(t *testing.T, api tui.API, width, height int) *tuiDriver {
	t.Helper()
	d := &tuiDriver{t: t, m: tui.New(api, tui.Options{Timeout: 5 * time.Second, Location: time.UTC})}
	d.send(tea.WindowSizeMsg{Width: width, Height: height})
	d.run(d.m.Init())
	return d
}

func (d *tuiDriver) send(msg tea.Msg) tea.Cmd {
	_, cmd := d.m.Update(msg)
	return cmd
}

// run executes a command tree to completion, feeding every reply to Update.
func (d *tuiDriver) run(cmd tea.Cmd) {
	d.t.Helper()
	if cmd == nil {
		return
	}
	switch msg := cmd().(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			d.run(c)
		}
	default:
		d.run(d.send(msg))
	}
}

func keyPress(name string) tea.KeyPressMsg {
	switch name {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	}
	r := []rune(name)
	return tea.KeyPressMsg{Code: r[0], Text: name}
}

// press sends one key and runs what it triggers.
func (d *tuiDriver) press(name string) {
	d.t.Helper()
	d.run(d.send(keyPress(name)))
}

// pressTimed sends one key and returns how long Update plus the frame render
// took: the latency the operator feels. The commands the key triggers run
// afterwards, off that clock, as they do in Bubble Tea.
func (d *tuiDriver) pressTimed(name string) time.Duration {
	d.t.Helper()
	start := monotonicNow()
	cmd := d.send(keyPress(name))
	_ = d.m.View()
	elapsed := time.Since(start)
	d.run(cmd)
	return elapsed
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;:?]*[ -/]*[@-~]|\x1b\\][^\a\x1b]*(\a|\x1b\\\\)")

// screen is the current frame without styling.
func (d *tuiDriver) screen() string { return ansi.ReplaceAllString(d.m.View().Content, "") }

func (d *tuiDriver) screenHas(text string) bool { return strings.Contains(d.screen(), text) }

// waitScreen reloads until text is on screen (the real program polls).
func (d *tuiDriver) waitScreen(text string, within time.Duration) {
	d.t.Helper()
	deadline := monotonicNow().Add(within)
	for monotonicNow().Before(deadline) {
		if d.screenHas(text) {
			return
		}
		d.press("r")
		time.Sleep(200 * time.Millisecond)
	}
	d.t.Fatalf("%q never appeared on screen:\n%s", text, d.screen())
}
