package client

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/tui"
)

const (
	sshProgram     = "ssh"
	knownHostsFile = "kh"
	endSessionWait = 5 * time.Second
)

var (
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9:][A-Za-z0-9._:%-]*$`)
	userPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,31}$`)
)

// Remote commands per tool. They are fixed literals, never built from input.
var toolCommand = map[wire.Tool]string{
	wire.ToolShell:      "",
	wire.ToolLazydocker: "lazydocker",
	wire.ToolBtop:       "btop",
	wire.ToolTmux:       "tmux",
}

// Interactive describes one interactive session to open.
type Interactive struct {
	Node domain.ID
	Tool wire.Tool
	// User overrides the endpoint's admin_user (`sm ssh --user`).
	User string
}

// OpenSession issues an audited session and returns the isolated OpenSSH
// command for the handoff (spec §8.4, §17.1; ADR-0015).
func (c *Client) OpenSession(ctx context.Context, node domain.ID, tool string) (tui.Handoff, error) {
	return c.OpenInteractive(ctx, Interactive{Node: node, Tool: wire.Tool(tool)})
}

// OpenInteractive is OpenSession with a user override. Whatever happens
// after the session is issued, its temporary known_hosts is removed and its
// end is posted exactly once: by Done, or right here when the command cannot
// even be built.
func (c *Client) OpenInteractive(ctx context.Context, in Interactive) (tui.Handoff, error) {
	if _, ok := toolCommand[in.Tool]; !ok {
		return tui.Handoff{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("unknown tool %q", in.Tool))
	}
	if in.User != "" && !userPattern.MatchString(in.User) {
		return tui.Handoff{}, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("invalid user %q", in.User))
	}
	opened, err := call[wire.SessionOpened](ctx, c, post(wire.Path(wire.PathNodeSessions, string(in.Node)), wire.OpenSessionRequest{Tool: in.Tool}))
	if err != nil {
		return tui.Handoff{}, err
	}
	session := &liveSession{client: c, node: in.Node, id: opened.Session.ID}
	info := opened.ConnectInfo
	if in.User != "" {
		info.User = in.User
	}
	cmd, err := c.prepare(session, info, in.Tool)
	if err != nil {
		session.finish(0, err) //nolint:contextcheck // ending the session must outlive the caller's context
		return tui.Handoff{}, err
	}
	return tui.Handoff{Cmd: cmd, Done: session.finish}, nil
}

func (c *Client) prepare(session *liveSession, info wire.ConnectInfo, tool wire.Tool) (*exec.Cmd, error) {
	dir, err := os.MkdirTemp(c.opts.TempDir, "sm-kh-")
	if err != nil {
		return nil, fmt.Errorf("create known_hosts directory: %w", err)
	}
	session.tempDir = dir
	path := filepath.Join(dir, knownHostsFile)
	if err := writeKnownHosts(path, info); err != nil {
		return nil, err
	}
	argv, err := interactiveCommand(info, tool, path, findCloudflared)
	if err != nil {
		return nil, err
	}
	return exec.Command(argv[0], argv[1:]...), nil //nolint:gosec,noctx // validated argv, no shell; tea.ExecProcess runs it without a context
}

// liveSession ends an issued session on every path, once.
type liveSession struct {
	client  *Client
	node    domain.ID
	id      domain.ID
	tempDir string
	once    sync.Once
}

// finish removes the temporary known_hosts and posts the session end:
// launch_failed when the command never ran, exited with its code otherwise.
func (s *liveSession) finish(exitCode int, launchErr error) {
	s.once.Do(func() {
		if s.tempDir != "" {
			_ = os.RemoveAll(s.tempDir)
		}
		end := wire.EndSessionRequest{Reason: wire.EndExited, ExitCode: &exitCode}
		if launchErr != nil {
			end = wire.EndSessionRequest{Reason: wire.EndLaunchFailed}
		}
		ctx, cancel := context.WithTimeout(context.Background(), endSessionWait)
		defer cancel()
		path := wire.Path(wire.PathNodeSessionEnd, string(s.node), string(s.id))
		_, _ = call[wire.Session](ctx, s.client, post(path, end)) // best effort: the daemon sweeps abandoned sessions
	})
}

// InteractiveCommand builds the OpenSSH argv (program first) for a handoff.
// It never involves a shell, ignores every user and system ssh configuration,
// and trusts exactly the one host key in knownHostsPath (ADR-0015, spec §8.4):
// -F /dev/null drops ssh_config, the temporary known_hosts is keyed by
// HostKeyAlias, and every proxy, command and multiplexing option is off.
// Host, port, user, alias, key and path are validated again here, since they
// come from a server response.
//
// A cloudflare node replaces ProxyCommand=none with `cloudflared access ssh`,
// run as the user: their own Access login applies and no SuperMgmt token is
// involved. cloudflared is resolved from a fixed directory list, never PATH.
func InteractiveCommand(info wire.ConnectInfo, tool wire.Tool, knownHostsPath string) ([]string, error) {
	return interactiveCommand(info, tool, knownHostsPath, findCloudflared)
}

func interactiveCommand(info wire.ConnectInfo, tool wire.Tool, knownHostsPath string, cloudflared func() (string, error)) ([]string, error) {
	remote, ok := toolCommand[tool]
	if !ok {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("unknown tool %q", tool))
	}
	if err := validateConnectInfo(info); err != nil {
		return nil, err
	}
	if strings.ContainsAny(knownHostsPath, "%\"'\\ \t\r\n") || !filepath.IsAbs(knownHostsPath) {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", "known_hosts path must be absolute without spaces, quotes or %")
	}
	proxy := "none"
	if info.Transport.Effective() == domain.TransportCloudflare {
		path, err := cloudflared()
		if err != nil {
			return nil, err
		}
		if proxy, err = cloudflareProxyCommand(path, info.TunnelHostname); err != nil {
			return nil, err
		}
	}
	argv := []string{
		sshProgram, "-F", "/dev/null",
		"-o", "HostKeyAlias=" + info.HostKeyAlias,
		"-o", "UserKnownHostsFile=" + knownHostsPath,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "ProxyCommand=" + proxy,
		"-o", "ProxyJump=none",
		"-o", "KnownHostsCommand=none",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "PermitLocalCommand=no",
		"-p", strconv.Itoa(info.Port),
		"-l", info.User,
	}
	if remote != "" {
		argv = append(argv, "-t")
	}
	argv = append(argv, "--", info.Host)
	if remote != "" {
		argv = append(argv, remote)
	}
	return argv, nil
}

func validateConnectInfo(info wire.ConnectInfo) error {
	switch {
	case !hostPattern.MatchString(info.Host):
		return invalidConnectInfo("host")
	case info.Port < 1 || info.Port > 65535:
		return invalidConnectInfo("port")
	case !userPattern.MatchString(info.User):
		return invalidConnectInfo("user")
	case !info.Transport.Valid():
		return invalidConnectInfo("transport")
	case info.HostKeyAlias != "sm-"+string(info.NodeID) || !isID(info.NodeID):
		return invalidConnectInfo("host key alias")
	}
	if _, err := authorizedKeyFields(info.HostPublicKey); err != nil {
		return invalidConnectInfo("host key")
	}
	if info.Transport.Effective() == domain.TransportCloudflare && domain.ValidateDNSName(info.TunnelHostname) != nil {
		return invalidConnectInfo("tunnel hostname")
	}
	return nil
}

// cloudflaredDirs is the fixed list searched for the client's own cloudflared,
// the same as the daemon's dialler; PATH is never consulted.
var cloudflaredDirs = []string{"/usr/local/bin", "/opt/homebrew/bin", "/usr/bin"}

func findCloudflared() (string, error) {
	for _, dir := range cloudflaredDirs {
		path := filepath.Join(dir, "cloudflared")
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path, nil
		}
	}
	return "", smerr.New(smerr.CodeCapabilityUnavailable, "",
		"cloudflared is not installed on this machine: install it (it carries your own Cloudflare Access login) to open a session on a tunnel node")
}

// cloudflareProxyCommand renders the ProxyCommand value. OpenSSH runs it
// through the shell, so the path is single-quoted (and refused when it holds
// anything quoting cannot carry), and expands %-tokens in it, so every % is
// doubled. The hostname must be a strict DNS name.
func cloudflareProxyCommand(path, hostname string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsFunc(path, func(r rune) bool { return r == '\'' || r < 0x20 || r == 0x7f }) {
		return "", smerr.New(smerr.CodeInvalidArgument, "", "cloudflared path must be absolute without quotes or control characters")
	}
	if err := domain.ValidateDNSName(hostname); err != nil {
		return "", invalidConnectInfo("tunnel hostname")
	}
	command := "'" + path + "' access ssh --hostname " + hostname
	return strings.ReplaceAll(command, "%", "%%"), nil
}

func isID(id domain.ID) bool {
	_, err := domain.ParseID(string(id))
	return err == nil
}

func invalidConnectInfo(what string) error {
	return smerr.New(smerr.CodeInternal, "", "daemon returned an invalid "+what+" for the connection")
}

// writeKnownHosts writes the single trusted line: "<alias> <type> <base64>".
func writeKnownHosts(path string, info wire.ConnectInfo) error {
	key, err := authorizedKeyFields(info.HostPublicKey)
	if err != nil {
		return invalidConnectInfo("host key")
	}
	line := info.HostKeyAlias + " " + key + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	return nil
}

// authorizedKeyFields normalizes an OpenSSH public key line to "type base64",
// dropping options and comment so nothing else can reach known_hosts.
func authorizedKeyFields(authorized string) (string, error) {
	key, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key))), nil
}
