package assistant

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/textsafe"
)

// maxLineBytes bounds one line of the child's stdout; a longer line ends the
// session rather than growing memory.
const maxLineBytes = 1 << 20

var errLineTooLong = fmt.Errorf("the assistant sent a line longer than %d bytes", maxLineBytes)

// readLine returns the next line without its newline. At EOF it returns what
// is left, then io.EOF.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
		if len(line)+len(chunk) > maxLineBytes {
			return nil, errLineTooLong
		}
		line = append(line, chunk...)
		if !isPrefix {
			return line, nil
		}
	}
}

type streamMessage struct {
	Type       string   `json:"type"`
	Subtype    string   `json:"subtype"`
	Error      string   `json:"error"`
	Tools      []string `json:"tools"`
	MCPServers []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"mcp_servers"`
	Message struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
	IsError bool   `json:"is_error"`
	Result  string `json:"result"`
}

type contentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

const (
	authenticationFailed = "authentication_failed" // the `error` field claude sets on its signed-out message
	maxToolInputRunes    = 200
	maxToolResultRunes   = 120
	maxTextRunes         = 32 << 10 // one text block of the model; a front end lays it out, so it is bounded
	tabWidth             = 4
)

var (
	errSpokeBeforeInit = errors.New("the assistant spoke before reporting its session")
	errUnknownShape    = errors.New("the assistant sent a message in a shape sm does not know")
)

// parser turns the stream-json output of `claude` into events. It tolerates
// unknown message types and fields; a line that is not JSON, or a message
// whose content has an unknown shape, is fatal, never guessed at.
type parser struct {
	ready     bool
	auth      Auth
	toolNames map[string]string // tool_use id -> tool name
}

func newParser(auth Auth) *parser {
	return &parser{auth: auth, toolNames: map[string]string{}}
}

// parse handles one line. A non-nil error is fatal: the caller stops the child.
func (p *parser) parse(line []byte) ([]Event, error) {
	var msg streamMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, errors.New("the assistant sent a line that is not JSON")
	}
	switch msg.Type {
	case "system":
		if msg.Subtype == "init" {
			return nil, p.init(msg)
		}
		return nil, nil
	case "assistant", "user", "result":
		if !p.ready {
			return nil, errSpokeBeforeInit
		}
	default:
		return nil, nil
	}
	switch msg.Type {
	case "assistant":
		return p.assistant(msg)
	case "user":
		return p.toolResults(msg)
	default:
		if msg.IsError {
			// An error result ends the turn without a success result after it.
			return []Event{
				{Kind: KindError, Text: display(msg.Result), Err: errors.New("claude reported an error")},
				{Kind: KindTurnDone},
			}, nil
		}
		return []Event{{Kind: KindTurnDone}}, nil
	}
}

// init asserts that the session has no tool but SuperMgmt's and exactly one
// MCP server, connected. It pins the effect of the argument vector.
func (p *parser) init(msg streamMessage) error {
	for _, tool := range msg.Tools {
		if !strings.HasPrefix(tool, mcpToolPrefix) {
			return fmt.Errorf("the session has a tool that is not SuperMgmt's: %s", display(tool))
		}
	}
	statuses := make([]string, 0, len(msg.MCPServers))
	for _, server := range msg.MCPServers {
		if server.Name != mcpServerName {
			return fmt.Errorf("the session has an MCP server that is not SuperMgmt's: %s", display(server.Name))
		}
		statuses = append(statuses, display(server.Status))
	}
	if len(statuses) != 1 || statuses[0] != "connected" {
		if len(statuses) == 0 {
			statuses = append(statuses, "none reported")
		}
		return fmt.Errorf("sm could not start its MCP tools for this session (server status: %s). "+
			"The usual causes are an expired assistant token, a server without mcp.token_over_https, or a stopped daemon; see docs/assistant.md",
			strings.Join(statuses, ", "))
	}
	p.ready = true
	return nil
}

func (p *parser) assistant(msg streamMessage) ([]Event, error) {
	if msg.Error == authenticationFailed {
		if p.auth == AuthAPIKey {
			return nil, ErrAPIKeyRejected
		}
		return nil, ErrNotSignedIn // claude's own text for this is a /login hint that does not work here
	}
	content, err := blocks(msg.Message.Content)
	if err != nil {
		return nil, err
	}
	var events []Event
	for _, block := range content {
		switch block.Type {
		case "text":
			events = append(events, Event{Kind: KindText, Text: modelText(block.Text)})
		case "tool_use":
			p.toolNames[block.ID] = block.Name
			line := display(strings.TrimPrefix(block.Name, mcpToolPrefix))
			if input := summarise(block.Input, maxToolInputRunes); input != "" {
				line += " " + input
			}
			events = append(events, Event{Kind: KindToolCall, Text: line})
		}
	}
	return events, nil
}

func (p *parser) toolResults(msg streamMessage) ([]Event, error) {
	content, err := blocks(msg.Message.Content)
	if err != nil {
		return nil, err
	}
	var events []Event
	for _, block := range content {
		if block.Type != "tool_result" {
			continue
		}
		name := p.toolNames[block.ToolUseID]
		delete(p.toolNames, block.ToolUseID)
		text, ok := resultText(block.Content)
		if !ok {
			if block.IsError {
				events = append(events, toolResultEvent(name, "failed"))
			}
			continue
		}
		if line := describeResult(name, text, block.IsError); line != "" {
			events = append(events, toolResultEvent(name, line))
		}
		if signal, ok := approvalSignal(name, text); ok {
			events = append(events, Event{Kind: KindApproval, Approval: &signal})
		}
	}
	return events, nil
}

// describeResult is what the operator sees of a tool result: the failure of any
// tool, and the status and job of a write tool. Display only; the approval
// signal is read separately and strictly.
func describeResult(name, text string, failed bool) string {
	if failed {
		line := "failed"
		if detail := truncate(strings.Join(strings.Fields(display(text)), " "), maxToolResultRunes); detail != "" {
			line += ": " + detail
		}
		return line
	}
	if !isWriteTool(name) {
		return ""
	}
	var result struct {
		Status string `json:"status"`
		JobID  string `json:"job_id"`
	}
	if json.Unmarshal([]byte(text), &result) != nil || result.Status == "" {
		return ""
	}
	line := truncate(display(result.Status), 40)
	if _, err := domain.ParseID(result.JobID); err == nil {
		line += " (job " + result.JobID + ")"
	}
	return line
}

func toolResultEvent(name, line string) Event {
	label := display(strings.TrimPrefix(name, mcpToolPrefix))
	if label == "" {
		label = "tool"
	}
	return Event{Kind: KindToolResult, Text: label + ": " + line}
}

// blocks decodes message content. Absent content and a plain string (which
// carries no blocks) are tolerated; any other shape is an error.
func blocks(raw json.RawMessage) ([]contentBlock, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || trimmed[0] == '"' {
		return nil, nil
	}
	var out []contentBlock
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return nil, errUnknownShape
	}
	return out, nil
}

// resultText is the text of a tool result that is a plain string or exactly
// one text block; anything else cannot be a write result.
func resultText(raw json.RawMessage) (string, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, true
	}
	parts, err := blocks(raw)
	if err != nil || len(parts) != 1 || parts[0].Type != "text" {
		return "", false
	}
	return parts[0].Text, true
}

// summarise is raw compacted to one line, sanitised and cut to max runes;
// empty for an absent, null or empty value.
func summarise(raw json.RawMessage, max int) string {
	var buf bytes.Buffer
	if len(raw) == 0 || json.Compact(&buf, raw) != nil {
		return ""
	}
	switch out := display(buf.String()); out {
	case "{}", "null", `""`:
		return ""
	default:
		return truncate(out, max)
	}
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "..."
}

func display(s string) string { return textsafe.Sanitize(bytes.TrimSpace([]byte(s))) }

// modelText is the text of the model for a front end to lay out: sanitised,
// tabs spent as spaces (a tab has no width a layout can count), and bounded.
func modelText(s string) string {
	text := strings.ReplaceAll(display(s), "\t", strings.Repeat(" ", tabWidth))
	if r := []rune(text); len(r) > maxTextRunes {
		return string(r[:maxTextRunes]) + " [cut]"
	}
	return text
}
