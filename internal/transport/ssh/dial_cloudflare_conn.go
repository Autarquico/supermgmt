package ssh

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	stderrKeep       = 4 << 10 // bytes of the child's stderr kept for diagnostics
	diagnosticRunes  = 300
	diagnosticsWaitF = time.Second
)

type childSpec struct {
	path, hostname, home string
	token                AccessToken
	grace                time.Duration
}

// childConn is the stdio of one `cloudflared access ssh` child as a net.Conn.
// Pipes are plain os.Files, so deadlines unblock I/O and no copy goroutines
// make Wait linger. The child lives until Close, never until the dial context
// ends; one reaper goroutine calls Wait exactly once.
type childConn struct {
	cmd     *exec.Cmd
	in      *os.File // our write end of the child's stdin
	out     *os.File // our read end of the child's stdout
	errRead *os.File // our read end of the child's stderr
	addr    childAddr
	grace   time.Duration
	secrets []string

	exited     chan struct{} // closed after Wait returned
	stderrDone chan struct{}
	tail       tailBuffer

	closeOnce sync.Once
}

type childAddr string

func (childAddr) Network() string  { return "cloudflare" }
func (a childAddr) String() string { return string(a) }

func startChild(s childSpec) (*childConn, error) {
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, smerr.Wrap(err, smerr.CodeInternal, "", "create cloudflared pipes")
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW)
		return nil, smerr.Wrap(err, smerr.CodeInternal, "", "create cloudflared pipes")
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW, outR, outW)
		return nil, smerr.Wrap(err, smerr.CodeInternal, "", "create cloudflared pipes")
	}

	cmd := &exec.Cmd{
		Path: s.path,
		Args: []string{s.path, "access", "ssh", "--hostname", s.hostname},
		// Exactly these, no PATH: cloudflared's browser fallback must not find
		// open or xdg-open, and no log or proxy variable is inherited.
		Env: []string{
			"TUNNEL_SERVICE_TOKEN_ID=" + s.token.ClientID,
			"TUNNEL_SERVICE_TOKEN_SECRET=" + s.token.ClientSecret.Reveal(),
			"HOME=" + s.home,
		},
		Dir: s.home,
		// Its own process group: a terminal SIGINT aimed at the daemon must
		// not reach the carrier; the daemon closes it itself.
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
		Stdin:       inR,
		Stdout:      outW,
		Stderr:      errW,
	}
	startErr := cmd.Start()
	closeAll(inR, outW, errW) // the child owns its ends now
	if startErr != nil {
		closeAll(inW, outR, errR)
		return nil, smerr.Wrap(startErr, smerr.CodeCapabilityUnavailable, "", "start cloudflared")
	}

	c := &childConn{
		cmd: cmd, in: inW, out: outR, errRead: errR, addr: childAddr("cloudflared:" + s.hostname), grace: s.grace,
		secrets: []string{s.token.ClientID, s.token.ClientSecret.Reveal()},
		exited:  make(chan struct{}), stderrDone: make(chan struct{}),
	}
	c.tail.margin = max(len(s.token.ClientID), len(s.token.ClientSecret.Reveal()))
	go func() {
		_ = cmd.Wait()
		close(c.exited)
	}()
	go c.drainStderr()
	return c, nil
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}

func (c *childConn) drainStderr() {
	defer close(c.stderrDone)
	buf := make([]byte, 1024)
	for {
		n, err := c.errRead.Read(buf)
		c.tail.write(buf[:n])
		if err != nil {
			return
		}
	}
}

func (c *childConn) Read(p []byte) (int, error)  { return c.out.Read(p) }
func (c *childConn) Write(p []byte) (int, error) { return c.in.Write(p) }

func (c *childConn) LocalAddr() net.Addr  { return c.addr }
func (c *childConn) RemoteAddr() net.Addr { return c.addr }

func (c *childConn) SetDeadline(t time.Time) error {
	rerr := c.out.SetReadDeadline(t)
	werr := c.in.SetWriteDeadline(t)
	if rerr != nil {
		return rerr
	}
	return werr
}

func (c *childConn) SetReadDeadline(t time.Time) error  { return c.out.SetReadDeadline(t) }
func (c *childConn) SetWriteDeadline(t time.Time) error { return c.in.SetWriteDeadline(t) }

// Close ends the stream and the child: stdin closes, SIGTERM follows, SIGKILL
// after the grace period. It returns once the child is reaped. Safe to call
// concurrently and repeatedly; every call blocks until the first finishes.
func (c *childConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.in.Close()
		_ = c.out.Close()
		select {
		case <-c.exited:
		default:
			_ = c.cmd.Process.Signal(syscall.SIGTERM)
			timer := time.NewTimer(c.grace)
			select {
			case <-c.exited:
			case <-timer.C:
				_ = c.cmd.Process.Kill()
				<-c.exited
			}
			timer.Stop()
		}
		_ = c.errRead.Close() // a grandchild holding stderr open must not hold us
		<-c.stderrDone
	})
	return nil
}

// Diagnostics is what the child said on stderr, scrubbed of the token and of
// anything shaped like a credential, bounded and on one line. Call after Close.
func (c *childConn) Diagnostics() string {
	select {
	case <-c.stderrDone:
	case <-time.After(diagnosticsWaitF):
	}
	return sanitizeDiagnostic(c.tail.String(), c.secrets...)
}

func (c *childConn) pid() int { return c.cmd.Process.Pid }

// sanitizeDiagnostic removes the given secret values and credential-shaped
// text, replaces control characters, and bounds the length.
func sanitizeDiagnostic(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, audit.Redacted)
		}
	}
	s = audit.ScrubCredentials(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > diagnosticRunes {
		s = string(r[:diagnosticRunes]) + "..."
	}
	return s
}

// tailBuffer keeps the last stderrKeep bytes written to it. Once bytes were
// dropped, the first margin bytes are withheld too: a secret cut by the bound
// would otherwise leave a fragment the exact-match scrub cannot recognise.
type tailBuffer struct {
	mu        sync.Mutex
	buf       []byte
	truncated bool
	margin    int
}

func (b *tailBuffer) write(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if over := len(b.buf) - stderrKeep; over > 0 {
		b.truncated = true
		b.buf = append(b.buf[:0], b.buf[over:]...)
	}
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return string(b.buf[min(b.margin, len(b.buf)):])
	}
	return string(b.buf)
}
