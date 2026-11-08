package assistant

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

const (
	eventBuffer    = 64
	stderrTail     = 4096
	closeGraceTime = 2 * time.Second
	waitDelay      = time.Second
)

// Session is one conversation with a locked-down `claude` child.
type Session struct {
	cfg    Config
	events chan Event

	mu    sync.Mutex // guards stdin writes and closing
	stdin io.WriteCloser

	quit     chan struct{} // closed by Close
	quitOnce sync.Once

	cmd     *exec.Cmd
	stdout  io.Closer // closed after a kill: a descendant holding the pipe must not stall the reap
	dir     string
	stopped atomic.Bool   // sm ended the child itself (fatal error or Close)
	done    chan struct{} // closed when the child has been reaped
}

// New validates cfg. Nothing is launched until Start.
func New(cfg Config) (*Session, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Session{
		cfg:    cfg,
		events: make(chan Event, eventBuffer),
		quit:   make(chan struct{}),
		done:   make(chan struct{}),
	}, nil
}

// Events delivers what the child does; it is closed after KindEnded.
func (s *Session) Events() <-chan Event { return s.events }

// Start launches the child in a fresh private directory. The child reports
// its tools and servers only once it receives the first message, so the init
// check runs then: a session that fails it is killed and reports KindError
// before any of its output is shown.
func (s *Session) Start(ctx context.Context) error {
	claude, err := s.claudePath()
	if err != nil {
		return err
	}
	env, err := childEnv(s.cfg.Auth, s.cfg.Env)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "sm-assistant-")
	if err != nil {
		return fmt.Errorf("assistant: private directory: %w", err)
	}
	if err := s.launch(ctx, claude, dir, env); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	return nil
}

func (s *Session) launch(ctx context.Context, claude, dir string, env []string) error {
	mcpPath, err := writeMCPConfig(dir, s.cfg)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, claude, claudeArgs(s.cfg, mcpPath)...) //nolint:gosec // claude is the operator's own binary, the arguments are built here
	cmd.Dir, cmd.Env = dir, env
	cmd.WaitDelay = waitDelay // a grandchild holding stderr must not stall the reap
	stderr := &tailBuffer{max: stderrTail}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("assistant: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("assistant: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("assistant: start claude: %w", err)
	}
	s.cmd, s.stdout, s.dir, s.stdin = cmd, stdout, dir, stdin
	go s.run(stdout, stderr)
	return nil
}

func (s *Session) claudePath() (string, error) {
	if s.cfg.Claude != "" {
		return s.cfg.Claude, nil
	}
	path, err := exec.LookPath("claude")
	if err != nil {
		return "", ErrClaudeNotFound
	}
	return path, nil
}

// Send writes one user turn.
func (s *Session) Send(text string) error {
	line, err := json.Marshal(map[string]any{
		"type":    "user",
		"message": map[string]any{"role": "user", "content": text},
	})
	if err != nil {
		return fmt.Errorf("assistant: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.quit:
		return ErrClosed
	default:
	}
	if s.stdin == nil {
		return errors.New("assistant: the session was not started")
	}
	if _, err := s.stdin.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("assistant: send: %w", err)
	}
	return nil
}

// Close ends the child (stdin first, then a kill after a grace time) and
// removes the private directory. It is safe to call more than once.
func (s *Session) Close() error {
	s.quitOnce.Do(func() {
		close(s.quit)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.stdin != nil {
			_ = s.stdin.Close()
		}
	})
	if s.cmd == nil {
		return nil
	}
	select {
	case <-s.done:
	case <-time.After(closeGraceTime):
		s.kill()
		<-s.done
	}
	return nil
}

// run reads the child's stream until it ends or turns fatal, then reaps the
// child, reports KindEnded and closes the channel.
func (s *Session) run(stdout io.Reader, stderr *tailBuffer) {
	defer close(s.done)
	defer close(s.events)
	defer func() { _ = os.RemoveAll(s.dir) }()

	if fatal := s.pump(bufio.NewReader(stdout)); fatal != nil {
		if !s.closing() { // Close breaks the pipe under pump; that is not news
			s.emit(Event{Kind: KindError, Fatal: true, Text: display(fatal.Error()), Err: fatal})
		}
		s.kill()
	}
	waitErr := s.cmd.Wait()
	ended := Event{Kind: KindEnded, Text: "the assistant ended"}
	if !s.stopped.Load() { // a kill sm made itself is not a crash
		ended.Err = waitErr
		if waitErr != nil {
			ended.Text = fmt.Sprintf("the assistant ended (%s)", waitErr)
		}
	}
	if hint := display(stderr.String()); hint != "" {
		ended.Text += ": " + hint
	}
	s.emit(ended)
}

func (s *Session) pump(r *bufio.Reader) error {
	p := newParser(s.cfg.Auth)
	for {
		line, err := readLine(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(line) == 0 {
			continue
		}
		events, err := p.parse(line)
		if err != nil {
			return err
		}
		for _, e := range events {
			s.emit(e)
		}
	}
}

// kill stops the child and closes its stdout so that pump returns even when a
// descendant keeps the pipe open.
func (s *Session) kill() {
	s.stopped.Store(true)
	_ = s.cmd.Process.Kill()
	_ = s.stdout.Close()
}

func (s *Session) closing() bool {
	select {
	case <-s.quit:
		return true
	default:
		return false
	}
}

// emit blocks until the consumer takes the event or Close is called.
func (s *Session) emit(e Event) {
	select {
	case s.events <- e:
	case <-s.quit:
	}
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(b []byte) (int, error) {
	t.buf = append(t.buf, b...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(b), nil
}

func (t *tailBuffer) String() string { return string(t.buf) }
