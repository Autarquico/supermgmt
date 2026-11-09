package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/autarquico/supermgmt/internal/assistant"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	// armDelay is how long a card must have been on screen with no key pressed
	// before a decision key counts: a key typed before the card appeared, or while
	// the operator is typing, cannot answer it.
	armDelay = 500 * time.Millisecond
	// stallAfter is the silence after which the operator is told how to stop a session.
	stallAfter = 60 * time.Second
	// askLimit bounds a message: the child's stdin is a pipe a stalled child stops draining.
	askLimit = 4000
	// checkTimeout and cardTimeout bound the work that is more than one API call.
	checkTimeout = 10 * time.Second
	cardTimeout  = 10 * time.Second

	maxTranscript = 2000 // logical lines kept; the oldest go first
	trimChunk     = 200  // dropped together, so a full transcript does not rewrap on every line
	maxLineRunes  = 4096 // longer lines are cut at ingest
)

// cardStep is where the decision on the open card stands.
type cardStep int

const (
	stepChoose cardStep = iota
	stepConfirmApprove
	stepDeciding
)

// assistantCard is the approval card the operator is deciding.
type assistantCard struct {
	seq   int
	token int // identifies the arming that may still arm the card; every key press starts a new one
	card  assistant.Card
	armed bool
	step  cardStep
}

// lifetime owns the child process: whoever starts a conversation hands it over
// here, and Run closes it before it returns, even when the start was still in
// flight at quit.
type lifetime struct {
	mu     sync.Mutex
	conv   assistant.Conversation
	closed bool
}

// adopt takes the conversation; it is false once shutdown ran, and the caller
// must close the conversation itself.
func (l *lifetime) adopt(c assistant.Conversation) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.conv = c
	return true
}

func (l *lifetime) release(c assistant.Conversation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conv == c {
		l.conv = nil
	}
}

func (l *lifetime) shutdown() {
	l.mu.Lock()
	l.closed = true
	c := l.conv
	l.conv = nil
	l.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// assistantState is the assistant screen: its input, its transcript and the
// conversation behind it. Only Update and View touch it.
type assistantState struct {
	life lifetime

	ask     textinput.Model // its own input: the palette's is reset whenever it opens
	vp      viewport.Model
	entries []entry
	rows    []string // entries wrapped to rowsW, ready to show
	rowsW   int

	conv      assistant.Conversation // nil until the first message, and after the child ends
	gen       int                    // identifies the conversation events belong to
	ident     assistant.Identity
	working   bool // from a message sent until the model's turn and the decisions it raised are over
	explained bool // the operator was told why the session failed

	opened, unavailable, greeted bool
	lastCheckErr                 string
	checkSeq                     int

	signals  []assistant.Signal
	seen     map[domain.ID]bool
	queue    []domain.ID // approvals still to be shown
	outcomes []string    // what the model is told once every decision is made
	cardSeq  int
	card     *assistantCard
	// cardStart is where the open card begins in entries: trimming never cuts into it.
	cardStart int

	activity   int // counts what the child did and what was asked of it
	stallNoted bool
	stallSeq   int // identifies the stall timer that may still speak
}

func newAssistantState() assistantState {
	ask := textinput.New()
	styles := ask.Styles()
	styles.Cursor.Blink = false // a solid cursor: no blink timers to drive
	ask.SetStyles(styles)
	ask.Prompt = "> "
	ask.Placeholder = "ask something"
	ask.CharLimit = askLimit
	return assistantState{ask: ask, vp: viewport.New(), seen: map[domain.ID]bool{}}
}

// Messages of the assistant screen.
type (
	assistantCheckedMsg struct {
		seq   int
		ident assistant.Identity
		err   error
	}
	assistantStartedMsg struct {
		conv  assistant.Conversation
		ident assistant.Identity
		text  string
		err   error
	}
	assistantEventMsg struct {
		gen int
		ev  assistant.Event
	}
	assistantEndedMsg struct{ gen int } // the event channel closed
	assistantSentMsg  struct {
		gen int
		err error
	}
	assistantCardMsg struct {
		seq     int
		card    assistant.Card
		ok      bool   // a card is to be shown
		note    string // what to tell the operator when it is not
		outcome string // what to tell the model, "" for nothing
	}
	assistantArmedMsg   struct{ seq, token int }
	assistantStallMsg   struct{ seq, activity int }
	assistantDecidedMsg struct {
		seq           int
		note, outcome string
	}
)

// assistantUpdate handles the messages of the assistant screen.
func (m *Model) assistantUpdate(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case assistantCheckedMsg:
		m.onAssistantChecked(msg)
	case assistantStartedMsg:
		return m.onAssistantStarted(msg)
	case assistantEventMsg:
		return m.onAssistantEvent(msg)
	case assistantEndedMsg:
		return m.onAssistantEnded(msg)
	case assistantSentMsg:
		return m.onAssistantSent(msg)
	case assistantCardMsg:
		return m.onAssistantCard(msg)
	case assistantArmedMsg:
		// Only the latest arming counts, and only while the card is on the operator's screen.
		if c := m.asst.card; c != nil && c.seq == msg.seq && c.token == msg.token && m.screen == screenAssistant {
			c.armed = true
		}
	case assistantStallMsg:
		return m.onAssistantStall(msg)
	case assistantDecidedMsg:
		return m.onAssistantDecided(msg)
	}
	return nil
}

// ---- opening ----------------------------------------------------------------

func (m *Model) openAssistant() tea.Cmd {
	a := &m.asst
	cmds := []tea.Cmd{m.jump(screenAssistant)}
	if !a.opened {
		a.opened = true
		m.appendEntries(
			entry{kind: kindDim, text: "Ask in plain language. The assistant works through SuperMgmt's tools as its own client, never as you."},
			entry{kind: kindDim, text: "A change that needs approval comes back here as a card for you to decide."},
			entry{kind: kindDim, text: "esc leaves this screen; the conversation keeps going."})
	}
	if a.card == nil {
		_ = a.ask.Focus()
	} else {
		cmds = append(cmds, m.armCard(a.card)) // the card is first seen now
	}
	switch {
	case m.opts.Assistant == nil:
		if !a.unavailable {
			a.unavailable = true
			m.appendEntries(noteEntries(kindFail, "this TUI was started without an assistant")...)
		}
	case a.conv == nil && !a.working:
		cmds = append(cmds, m.checkAssistant())
	}
	return tea.Batch(cmds...)
}

// checkAssistant runs the launcher's refusals so the operator sees them on
// opening, before any message; it starts nothing.
func (m *Model) checkAssistant() tea.Cmd {
	m.asst.checkSeq++
	seq, launcher, parent := m.asst.checkSeq, m.opts.Assistant, m.ctx
	return func() tea.Msg {
		ident, err := within(parent, checkTimeout, launcher.Check)
		return assistantCheckedMsg{seq: seq, ident: ident, err: err}
	}
}

func (m *Model) onAssistantChecked(msg assistantCheckedMsg) {
	a := &m.asst
	if msg.seq != a.checkSeq || a.conv != nil || a.working {
		return
	}
	if msg.err != nil {
		if text := msg.err.Error(); text != a.lastCheckErr {
			a.lastCheckErr = text
			m.appendEntries(noteEntries(kindFail, text)...)
		}
		return
	}
	a.lastCheckErr = ""
	if !a.greeted {
		a.greeted = true
		m.appendEntries(noteEntries(kindNote, greeting(msg.ident))...)
	}
}

func greeting(id assistant.Identity) string {
	account := "your claude subscription"
	if id.Auth == assistant.AuthAPIKey {
		account = "your Anthropic API key, billed per use"
	}
	return fmt.Sprintf("assistant on %s (client %s, %s).", id.Instance, id.ClientName, account)
}

// ---- keys -------------------------------------------------------------------

// assistantKey takes every key on the assistant screen before the global ones:
// the input owns the keyboard, so typing q or a digit is text. Only ctrl+c
// (quit the TUI) and esc (leave the screen) are not.
func (m *Model) assistantKey(key tea.KeyPressMsg) tea.Cmd {
	a := &m.asst
	switch {
	case key.String() == "ctrl+c":
		return tea.Quit
	case key.String() == "ctrl+x" && a.card == nil && a.working && a.conv != nil:
		m.appendEntries(noteEntries(kindNote, "session stopped")...)
		return m.endSession()
	}
	if a.card != nil {
		return m.cardKey(key)
	}
	switch key.String() {
	case "esc":
		a.ask.Blur()
		return m.jump(screenDashboard)
	case "enter":
		return m.submitAsk()
	case "pgup", "pgdown":
		a.vp, _ = a.vp.Update(key)
		return nil
	}
	var cmd tea.Cmd
	a.ask, cmd = a.ask.Update(key)
	return cmd
}

func (m *Model) onPaste(msg tea.PasteMsg) tea.Cmd {
	var cmd tea.Cmd
	switch {
	case m.prompt != nil:
		m.input, cmd = m.input.Update(msg)
	case m.screen == screenAssistant && m.asst.card == nil:
		m.asst.ask, cmd = m.asst.ask.Update(msg)
	}
	return cmd
}

func (m *Model) submitAsk() tea.Cmd {
	a := &m.asst
	text := strings.TrimSpace(a.ask.Value())
	switch {
	case text == "":
		return nil
	case m.opts.Assistant == nil:
		m.notice = notice{text: "this TUI was started without an assistant", isErr: true}
		return nil
	case a.working:
		m.notice = notice{text: "the assistant is still working; wait for its answer"}
		return nil
	}
	a.ask.Reset()
	a.working, a.explained = true, false
	a.vp.GotoBottom()
	m.appendEntries(userEntries(text)...)
	if a.conv != nil {
		return tea.Batch(sendCmd(a.conv, a.gen, text), m.watchForStall())
	}
	return m.startAssistant(text)
}

// watchForStall starts the timer that, once, tells the operator how to stop a
// session that has been silent for stallAfter. A long turn is legitimate, so
// nothing is killed.
func (m *Model) watchForStall() tea.Cmd {
	a := &m.asst
	a.stallSeq++
	m.touch()
	return stallTick(a.stallSeq, a.activity)
}

// touch records that the child did, or was asked, something.
func (m *Model) touch() {
	m.asst.activity++
	m.asst.stallNoted = false
}

func stallTick(seq, activity int) tea.Cmd {
	return tea.Tick(stallAfter, func(time.Time) tea.Msg { return assistantStallMsg{seq: seq, activity: activity} })
}

func (m *Model) onAssistantStall(msg assistantStallMsg) tea.Cmd {
	a := &m.asst
	if msg.seq != a.stallSeq || !a.working {
		return nil
	}
	if a.card != nil || msg.activity != a.activity { // the operator holds the turn, or it spoke since
		return stallTick(msg.seq, a.activity)
	}
	if !a.stallNoted {
		a.stallNoted = true
		m.appendEntries(noteEntries(kindNote, fmt.Sprintf("no output from the assistant for %ds; ctrl+x stops it", int(stallAfter.Seconds())))...)
	}
	return stallTick(msg.seq, a.activity)
}

// startAssistant checks the registration again, launches the session and
// sends the first message; both happen off the update loop. The session lives
// under the program's context, not under the call's timeout.
func (m *Model) startAssistant(text string) tea.Cmd {
	launcher, parent, life := m.opts.Assistant, m.ctx, &m.asst.life
	return func() tea.Msg {
		ident, err := within(parent, checkTimeout, launcher.Check)
		if err != nil {
			return assistantStartedMsg{text: text, err: err}
		}
		conv, err := launcher.Start(parent)
		if err != nil {
			return assistantStartedMsg{text: text, err: err}
		}
		if !life.adopt(conv) {
			_ = conv.Close()
			return assistantStartedMsg{text: text, err: errors.New("the TUI is closing")}
		}
		return assistantStartedMsg{conv: conv, ident: ident, text: text}
	}
}

func (m *Model) onAssistantStarted(msg assistantStartedMsg) tea.Cmd {
	a := &m.asst
	if msg.err != nil {
		a.working = false
		if a.ask.Value() == "" {
			a.ask.SetValue(msg.text)
		}
		m.appendEntries(noteEntries(kindFail, msg.err.Error())...)
		return nil
	}
	a.lastCheckErr = "" // the session started: an earlier failed check no longer describes it
	a.conv, a.ident = msg.conv, msg.ident
	a.gen++
	if m.send != nil {
		go forwardAssistant(msg.conv, a.gen, m.send)
	}
	return tea.Batch(sendCmd(msg.conv, a.gen, msg.text), m.watchForStall())
}

// forwardAssistant turns the child's events into messages; Program.Send
// returns once the program is over, and the channel closes after KindEnded, so
// it cannot outlive the session.
func forwardAssistant(conv assistant.Conversation, gen int, send func(tea.Msg)) {
	for ev := range conv.Events() {
		send(assistantEventMsg{gen: gen, ev: ev})
	}
	send(assistantEndedMsg{gen: gen})
}

// sendCmd writes one turn; it can block on a stalled child, so it never runs in Update.
func sendCmd(conv assistant.Conversation, gen int, text string) tea.Cmd {
	return func() tea.Msg { return assistantSentMsg{gen: gen, err: conv.Send(text)} }
}

func (m *Model) onAssistantSent(msg assistantSentMsg) tea.Cmd {
	if msg.gen != m.asst.gen || msg.err == nil {
		return nil
	}
	m.appendEntries(noteEntries(kindFail, "the assistant is gone: "+msg.err.Error())...)
	return m.endSession()
}

// ---- events -----------------------------------------------------------------

func (m *Model) onAssistantEvent(msg assistantEventMsg) tea.Cmd {
	a := &m.asst
	if msg.gen != a.gen || a.conv == nil {
		return nil
	}
	ev := msg.ev
	m.touch()
	switch ev.Kind {
	case assistant.KindText:
		m.appendEntries(modelEntries(ev.Text)...)
	case assistant.KindToolCall:
		m.appendEntries(modelEntries("[tool] " + ev.Text)...)
	case assistant.KindToolResult:
		m.appendEntries(modelEntries("[result] " + ev.Text)...)
	case assistant.KindApproval:
		if ev.Approval != nil && !a.seen[ev.Approval.JobID] {
			a.seen[ev.Approval.JobID] = true
			a.signals = append(a.signals, *ev.Approval)
		}
	case assistant.KindTurnDone:
		return m.settleTurn()
	case assistant.KindError:
		m.appendEntries(noteEntries(kindFail, "error: "+ev.Text)...)
		a.explained = a.explained || ev.Fatal
	case assistant.KindEnded:
		if !a.explained && ev.Text != "" {
			kind := kindNote
			if ev.Err != nil {
				kind = kindFail
			}
			m.appendEntries(noteEntries(kind, ev.Text)...)
		}
		return m.endSession()
	}
	return nil
}

func (m *Model) onAssistantEnded(msg assistantEndedMsg) tea.Cmd {
	if msg.gen != m.asst.gen || m.asst.conv == nil {
		return nil
	}
	m.appendEntries(noteEntries(kindFail, "the assistant ended")...)
	return m.endSession()
}

// endSession forgets the conversation and closes it off the update loop. What
// was waiting on it is dropped; a card already on screen stays decidable, the
// decision just has nobody to tell.
func (m *Model) endSession() tea.Cmd {
	a := &m.asst
	conv := a.conv
	a.conv, a.working = nil, false
	a.gen++
	a.cardSeq++
	if n := len(a.queue); n > 0 {
		m.appendEntries(noteEntries(kindNote, fmt.Sprintf("%d more approval(s) were waiting and were not shown; decide them in Approvals (4)", n))...)
	}
	a.signals, a.seen, a.queue, a.outcomes = nil, map[domain.ID]bool{}, nil, nil
	if conv == nil {
		return nil
	}
	return func() tea.Msg {
		_ = conv.Close()
		a.life.release(conv)
		return nil
	}
}

// ---- approvals --------------------------------------------------------------

// settleTurn starts on the approvals the finished turn raised, one card at a time.
func (m *Model) settleTurn() tea.Cmd {
	a := &m.asst
	for _, s := range a.signals {
		a.queue = append(a.queue, s.JobID)
	}
	a.signals, a.seen = nil, map[domain.ID]bool{}
	return m.nextCard()
}

// nextCard loads the next waiting approval; when none is left it tells the
// model what was decided, once, in one turn.
func (m *Model) nextCard() tea.Cmd {
	a := &m.asst
	if len(a.queue) == 0 {
		if text := strings.Join(a.outcomes, "\n"); text != "" && a.conv != nil {
			a.outcomes = nil
			m.touch()
			return sendCmd(a.conv, a.gen, text)
		}
		a.outcomes, a.working = nil, false
		return nil
	}
	id := a.queue[0]
	a.queue = a.queue[1:]
	a.cardSeq++
	seq, ident, api, parent := a.cardSeq, a.ident, m.api, m.ctx
	return func() tea.Msg {
		msg, err := within(parent, cardTimeout, func(ctx context.Context) (assistantCardMsg, error) {
			return loadCard(ctx, api, ident, id), nil
		})
		if err != nil {
			msg = assistantCardMsg{note: fmt.Sprintf("the assistant mentioned job %s, which could not be read: %s", id, describe(err))}
		}
		msg.seq = seq
		return msg
	}
}

// loadCard is what the CLI does before it asks: the job must be the assistant
// client's own and waiting, and its plan readable. It makes several API calls.
func loadCard(ctx context.Context, api API, ident assistant.Identity, id domain.ID) assistantCardMsg {
	approval, problem := assistant.LoadApproval(ctx, api, id, ident.ClientID, ident.ClientName)
	if problem != "" {
		return assistantCardMsg{note: problem}
	}
	card, ok := assistant.NewCard(ctx, api, approval)
	if !ok {
		return assistantCardMsg{
			note:    fmt.Sprintf("job %s is waiting for approval but its plan cannot be read; it was not offered (use `sm approvals --plan`)", id),
			outcome: assistant.UnaskedOutcome(id, "its plan could not be shown to the operator"),
		}
	}
	return assistantCardMsg{card: card, ok: true}
}

func (m *Model) onAssistantCard(msg assistantCardMsg) tea.Cmd {
	a := &m.asst
	if msg.seq != a.cardSeq || a.card != nil {
		return nil
	}
	if !msg.ok {
		m.appendEntries(noteEntries(kindNote, msg.note)...)
		if msg.outcome != "" {
			a.outcomes = append(a.outcomes, msg.outcome)
		}
		return m.nextCard()
	}
	a.card = &assistantCard{seq: msg.seq, card: msg.card}
	a.ask.Blur()
	a.cardStart = len(a.entries)
	added := m.appendEntries(m.cardEntries(msg.card)...)
	a.vp.SetYOffset(len(a.rows) - added) // the card is read from its top
	if m.screen != screenAssistant {
		return nil // openAssistant arms it when the operator first sees it
	}
	return m.armCard(a.card)
}

// armCard starts the arming again: the card ignores decision keys until
// armDelay has passed with no key pressed, and a tick of an earlier arming no
// longer counts.
func (m *Model) armCard(c *assistantCard) tea.Cmd {
	c.armed = false
	c.token++
	seq, token := c.seq, c.token
	return tea.Tick(armDelay, func(time.Time) tea.Msg { return assistantArmedMsg{seq: seq, token: token} })
}

// scrollCard scrolls the transcript for the keys that do.
func (m *Model) scrollCard(key tea.KeyPressMsg) {
	a := &m.asst
	switch key.String() {
	case "pgup", "pgdown", "j", "k", "up", "down":
		a.vp, _ = a.vp.Update(key)
	case "g":
		a.vp.GotoTop()
	case "G":
		a.vp.GotoBottom()
	}
}

// cardKey handles a key while a card is open. A decision key counts only when
// the card has been on screen for armDelay with no key pressed; any other key
// starts that wait again. The approval is two steps, and the second counts only
// as a key pressed for it: a pause after A, then y; any other key, y during
// the pause included, goes back.
func (m *Model) cardKey(key tea.KeyPressMsg) tea.Cmd {
	c := m.asst.card
	if c.step == stepDeciding {
		m.scrollCard(key)
		return nil
	}
	if c.step == stepConfirmApprove {
		if c.armed && key.String() == "y" {
			return m.decide(c, func(ctx context.Context, api API) (string, string) {
				return assistant.Approve(ctx, api, c.card.Approval)
			})
		}
		c.step = stepChoose // armed or not, no other key approves
		m.scrollCard(key)
		return m.armCard(c)
	}
	if !c.armed {
		m.scrollCard(key)
		return m.armCard(c)
	}
	switch key.String() {
	case "A":
		c.step = stepConfirmApprove
	case "R":
		return tea.Batch(m.openPrompt("reject reason:", "why is this plan rejected?  esc cancels", func(m *Model, reason string) tea.Cmd {
			if reason == "" {
				m.notice = notice{text: "a reason is required to reject", isErr: true}
				return nil
			}
			if m.asst.card != c || c.step != stepChoose {
				return nil
			}
			return m.decide(c, func(ctx context.Context, api API) (string, string) {
				return assistant.Reject(ctx, api, c.card.Approval, reason)
			})
		}), m.armCard(c))
	case "esc":
		return m.leavePending(c)
	default:
		m.scrollCard(key)
	}
	return m.armCard(c)
}

// decide records the decision under the human's connection; the outcome goes
// to the model, not to the notice line.
func (m *Model) decide(c *assistantCard, call func(ctx context.Context, api API) (note, outcome string)) tea.Cmd {
	c.step = stepDeciding
	id, seq, api, timeout, parent := c.card.Approval.Job.ID, c.seq, m.api, m.opts.Timeout, m.ctx
	return func() tea.Msg {
		type result struct{ note, outcome string }
		r, err := within(parent, timeout, func(ctx context.Context) (result, error) {
			note, outcome := call(ctx, api)
			return result{note, outcome}, nil
		})
		if err != nil {
			return assistantDecidedMsg{
				seq:     seq,
				note:    fmt.Sprintf("job %s: the decision may not have been recorded (%s); check Approvals", id, describe(err)),
				outcome: assistant.FailedOutcome(id),
			}
		}
		return assistantDecidedMsg{seq: seq, note: r.note, outcome: r.outcome}
	}
}

func (m *Model) onAssistantDecided(msg assistantDecidedMsg) tea.Cmd {
	a := &m.asst
	if a.card == nil || a.card.seq != msg.seq {
		return nil
	}
	a.card = nil
	if m.screen == screenAssistant {
		_ = a.ask.Focus()
	}
	a.vp.GotoBottom()
	m.appendEntries(noteEntries(kindNote, msg.note)...)
	a.outcomes = append(a.outcomes, msg.outcome)
	return m.nextCard()
}

// leavePending leaves the open card undecided, as the CLI does for one job:
// the model is told so, it stays in Approvals, and the next card opens.
func (m *Model) leavePending(c *assistantCard) tea.Cmd {
	a := &m.asst
	a.card = nil
	_ = a.ask.Focus()
	id := c.card.Approval.Job.ID
	a.vp.GotoBottom()
	m.appendEntries(noteEntries(kindNote, fmt.Sprintf("job %s stays pending; decide it later in Approvals (4)", id))...)
	a.outcomes = append(a.outcomes, assistant.PendingOutcome(id))
	return m.nextCard()
}

// closeAssistant ends the child before the program returns, so no process or
// temporary directory outlives the TUI.
func (m *Model) closeAssistant() { m.asst.life.shutdown() }
