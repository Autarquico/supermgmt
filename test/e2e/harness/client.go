//go:build e2e

package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Client is the `sm` binary of the person's laptop: the test machine, with its own HOME and no
// OS credential tool on PATH, so its sessions live in a 0600 file under the test directory.
type Client struct {
	t   testing.TB
	bin string
	env []string
}

// NewClient prepares an isolated environment for the host `sm`.
func NewClient(t testing.TB) *Client {
	t.Helper()
	home := t.TempDir()
	empty := filepath.Join(home, "empty-path")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	return &Client{t: t, bin: HostSM(t), env: []string{
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_DATA_HOME=" + filepath.Join(home, "data"),
		"XDG_STATE_HOME=" + filepath.Join(home, "state"),
		"XDG_RUNTIME_DIR=" + home,
		"PATH=" + empty, // no keychain, no browser opener
		"SUPERMGMT_NO_AUTOSTART=1",
		"NO_COLOR=1",
	}}
}

// Run executes `sm` and returns its result.
func (c *Client) Run(ctx context.Context, stdin string, args ...string) Result {
	c.t.Helper()
	res, err := Run(ctx, "", c.env, stdin, c.bin, args...)
	if err != nil {
		c.t.Fatalf("sm %v: %v", args, err)
	}
	return res
}

// Must runs `sm` and fails the test on a non-zero exit.
func (c *Client) Must(ctx context.Context, stdin string, args ...string) Result {
	c.t.Helper()
	res := c.Run(ctx, stdin, args...)
	if res.Code != 0 {
		c.t.Fatalf("sm %s exited %d\n%s", strings.Join(args, " "), res.Code, res.Output())
	}
	return res
}

// AddProfile registers a remote server (and its CA) and makes it current.
func (c *Client) AddProfile(ctx context.Context, name, url, caFile string) {
	c.t.Helper()
	args := []string{"profile", "add", name, "--url", url}
	if caFile != "" {
		args = append(args, "--ca-file", caFile)
	}
	c.Must(ctx, "", args...)
	c.Must(ctx, "", "profile", "use", name)
}

// Proc is a running `sm` whose output is watched line by line (the login URL and codes).
type Proc struct {
	cmd   *exec.Cmd
	lines chan string
	done  chan struct{}
	mu    sync.Mutex
	out   strings.Builder
	errs  strings.Builder
}

// sink collects one stream and publishes its complete lines.
type sink struct {
	p       *Proc
	buf     *strings.Builder
	partial string
}

func (s *sink) Write(b []byte) (int, error) {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	s.buf.Write(b)
	s.partial += string(b)
	for {
		line, rest, found := strings.Cut(s.partial, "\n")
		if !found {
			return len(b), nil
		}
		s.partial = rest
		select {
		case s.p.lines <- line:
		default: // nobody is listening and the backlog is full: the buffer still has it
		}
	}
}

// Start launches `sm` in the background.
func (c *Client) Start(ctx context.Context, stdin string, args ...string) *Proc {
	c.t.Helper()
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Env = c.env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	p := &Proc{cmd: cmd, lines: make(chan string, 4096), done: make(chan struct{})}
	cmd.Stdout = &sink{p: p, buf: &p.out}
	cmd.Stderr = &sink{p: p, buf: &p.errs}
	if err := cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	go func() {
		_ = cmd.Wait()
		close(p.done)
		close(p.lines)
	}()
	c.t.Cleanup(func() { _ = cmd.Process.Kill() })
	return p
}

// WaitLine returns the submatches of the first output line (stdout or stderr) matching re.
func (p *Proc) WaitLine(t testing.TB, re *regexp.Regexp, timeout time.Duration) []string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				t.Fatalf("sm exited before printing %v\nstderr:\n%s", re, p.Stderr())
			}
			if m := re.FindStringSubmatch(line); m != nil {
				return m
			}
		case <-deadline:
			t.Fatalf("no line matching %v within %s\nstderr:\n%s", re, timeout, p.Stderr())
		}
	}
}

// TryLine waits up to timeout for an output line matching re and reports whether one came.
func (p *Proc) TryLine(re *regexp.Regexp, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				return false
			}
			if re.MatchString(line) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// Wait returns the result once the process ends; it kills the process after timeout.
func (p *Proc) Wait(timeout time.Duration) (Result, error) {
	select {
	case <-p.done:
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		return Result{}, fmt.Errorf("sm did not finish within %s\nstderr:\n%s", timeout, p.Stderr())
	}
	return Result{Stdout: p.stdout(), Stderr: p.Stderr(), Code: p.cmd.ProcessState.ExitCode()}, nil
}

func (p *Proc) stdout() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

// Stderr is everything printed to stderr so far.
func (p *Proc) Stderr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.errs.String()
}

// StoredToken reads the session the client keeps for a profile (the 0600 file store).
func (c *Client) StoredToken(profile string) string {
	c.t.Helper()
	var home string
	for _, kv := range c.env {
		if v, ok := strings.CutPrefix(kv, "XDG_CONFIG_HOME="); ok {
			home = v
		}
	}
	raw, err := os.ReadFile(filepath.Join(home, "supermgmt", "credentials.json"))
	if err != nil {
		c.t.Fatalf("read the credential file: %v", err)
	}
	var doc struct {
		Tokens map[string]string `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		c.t.Fatal(err)
	}
	return doc.Tokens[profile]
}

// JSON runs `sm --json ...` and decodes stdout into out.
func (c *Client) JSON(ctx context.Context, stdin string, out any, args ...string) Result {
	c.t.Helper()
	res := c.Must(ctx, stdin, append([]string{"--json"}, args...)...)
	if err := json.Unmarshal([]byte(res.Stdout), out); err != nil {
		c.t.Fatalf("decode `sm --json %s`: %v\n%s", strings.Join(args, " "), err, res.Stdout)
	}
	return res
}
