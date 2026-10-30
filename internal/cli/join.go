package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/join"
)

const maxJoinTokenBytes = 4096

// maxConnectorTokenInput leaves room for the line break after the longest
// connector token; anything longer cannot be one.
const maxConnectorTokenInput = maxJoinTokenBytes + 2

// ttyPath is the controlling terminal: stdin may be the script itself under
// `curl | sudo sh`.
const ttyPath = "/dev/tty"

// tunnelFactory builds the node-side steps of `sm join --tunnel`.
type tunnelFactory func() join.TunnelJoiner

// tokenPrompter reads the connector token from the operator's terminal.
type tokenPrompter func(out io.Writer) (audit.Secret, error)

// joinFactory builds the node-side steps for a server and its optional CA.
type joinFactory func(server string, caPEM []byte) (join.Joiner, error)

// newJoinCmd is `sm join` (spec §13, ADR-0022): run as root on a node, it
// enrolls the node with the server. The token is read from a file or from
// stdin, never from an argument.
func newJoinCmd(_ []string) *cobra.Command {
	return newJoinCmdFull(func(server string, caPEM []byte) (join.Joiner, error) {
		client, err := join.NewClient(server, caPEM)
		if err != nil {
			return join.Joiner{}, err
		}
		return join.Joiner{Host: join.System{}, Enroller: client}, nil
	}, func() join.TunnelJoiner { return join.TunnelJoiner{Host: join.System{}} }, readTokenFromTTY)
}

// noTokenArgs refuses positional arguments without echoing them: one of them
// is probably the token, and an argument is already too public for it.
func noTokenArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usageErrorf("sm join takes no arguments; give the token with --token-file or --token-stdin")
	}
	return nil
}

type joinFlags struct {
	server, tokenFile, caFile, hostname string
	tokenStdin                          bool
	sshPort                             int
	tunnel                              bool
	instance, authorizedKey             string
}

func newJoinCmdWith(factory joinFactory) *cobra.Command {
	return newJoinCmdFull(factory, func() join.TunnelJoiner { return join.TunnelJoiner{Host: join.System{}} }, readTokenFromTTY)
}

func newJoinCmdFull(factory joinFactory, tunnel tunnelFactory, prompt tokenPrompter) *cobra.Command {
	var f joinFlags
	cmd := &cobra.Command{
		Use:   "join (--server URL (--token-file FILE | --token-stdin) | --tunnel --instance ID --authorized-key KEY [--token-stdin])",
		Short: "Enroll this node with a SuperMgmt server, or prepare it for a Cloudflare Tunnel enrollment (run as root)",
		Long: "Without --tunnel, enroll this node with the SuperMgmt server at --server using a join token.\n\n" +
			"With --tunnel, prepare a node that only the Cloudflare Tunnel will reach: install cloudflared with the\n" +
			"connector token, create the dedicated account for the instance's key, and print the host key fingerprint to\n" +
			"compare on the operator's side. No SuperMgmt server is contacted. The connector token is asked for on the\n" +
			"terminal without echo, or read from standard input with --token-stdin; it is never an argument.",
		Args: noTokenArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f.tunnel {
				return f.runTunnel(cmd, tunnel(), prompt)
			}
			if err := f.refuseTunnelOnlyFlags(); err != nil {
				return err
			}
			token, caPEM, err := f.inputs(cmd.InOrStdin())
			if err != nil {
				return err
			}
			joiner, err := factory(f.server, caPEM)
			if err != nil {
				return err
			}
			enrolled, err := joiner.Run(cmd.Context(), join.Request{Token: token, Hostname: f.hostname, SSHPort: f.sshPort})
			if err != nil {
				return err
			}
			asJSON, _ := cmd.Flags().GetBool("json")
			return writeJoined(cmd.OutOrStdout(), enrolled, asJSON)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.server, "server", "", "https URL of the SuperMgmt server")
	fl.StringVar(&f.tokenFile, "token-file", "", "file holding the join token")
	fl.BoolVar(&f.tokenStdin, "token-stdin", false, "read the join token from stdin")
	fl.StringVar(&f.caFile, "ca-file", "", "PEM file of the CA that signed the server certificate (default: system roots)")
	fl.StringVar(&f.hostname, "hostname", "", "node name to enroll as (default: this machine's hostname)")
	fl.IntVar(&f.sshPort, "ssh-port", 0, "port of this node's sshd (default 22)")
	fl.BoolVar(&f.tunnel, "tunnel", false, "prepare this node for a Cloudflare Tunnel enrollment; no server is contacted")
	fl.StringVar(&f.instance, "instance", "", "with --tunnel: the SuperMgmt instance ID that names the managed key")
	fl.StringVar(&f.authorizedKey, "authorized-key", "", "with --tunnel: the instance's public SSH key for the dedicated account")
	return cmd
}

func (f joinFlags) refuseTunnelOnlyFlags() error {
	if f.instance != "" || f.authorizedKey != "" {
		return usageErrorf("--instance and --authorized-key are only for --tunnel")
	}
	return nil
}

// runTunnel is `sm join --tunnel`. Every refusal that needs no token comes
// before the token is asked for, and the token before anything is changed.
func (f joinFlags) runTunnel(cmd *cobra.Command, joiner join.TunnelJoiner, prompt tokenPrompter) error {
	switch {
	case f.server != "" || f.tokenFile != "" || f.caFile != "" || f.hostname != "" || f.sshPort != 0:
		return usageErrorf("--tunnel takes no --server, --token-file, --ca-file, --hostname or --ssh-port: it contacts no server")
	case f.instance == "" || f.authorizedKey == "":
		return usageErrorf("--tunnel needs --instance and --authorized-key (both are in the line SuperMgmt printed)")
	}
	readToken := func() (audit.Secret, error) {
		if f.tokenStdin {
			return readConnectorTokenFromStream(cmd.InOrStdin())
		}
		return prompt(cmd.ErrOrStderr())
	}
	fingerprint, err := joiner.Run(cmd.Context(), join.TunnelRequest{InstanceID: f.instance, AuthorizedKey: f.authorizedKey}, readToken)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Compare this fingerprint with the one SuperMgmt asks you to confirm.\nhost key: %s\n", fingerprint)
	return err
}

// readConnectorTokenFromStream reads the token from standard input, bounded;
// the shape check follows in the caller.
func readConnectorTokenFromStream(r io.Reader) (audit.Secret, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxConnectorTokenInput))
	if err != nil {
		return "", errors.New("read the connector token from standard input failed")
	}
	return audit.Secret(strings.TrimSpace(string(raw))), nil
}

// readTokenFromTTY asks for the connector token on the controlling terminal
// without echo. The terminal is restored on every exit, including a signal.
func readTokenFromTTY(out io.Writer) (audit.Secret, error) {
	tty, err := os.OpenFile(ttyPath, os.O_RDWR, 0)
	if err != nil {
		return "", usageErrorf("no connector token: pass --token-stdin (there is no terminal to ask on)")
	}
	defer func() { _ = tty.Close() }()
	restore, err := disableEcho(int(tty.Fd()))
	if err != nil {
		return "", usageErrorf("cannot turn off terminal echo (%v): pipe the token with --token-stdin instead", err)
	}
	defer restore()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	_, _ = fmt.Fprint(out, "Connector token: ")
	defer func() { _, _ = fmt.Fprintln(out) }()
	type answer struct {
		line string
		err  error
	}
	read := make(chan answer, 1)
	go func() {
		line, err := readBoundedLine(tty, maxConnectorTokenInput)
		read <- answer{line, err}
	}()
	select {
	case a := <-read:
		return audit.Secret(strings.TrimSpace(a.line)), a.err
	case <-ctx.Done():
		return "", errors.New("interrupted while reading the connector token")
	}
}

// readBoundedLine reads one line byte by byte, so nothing past the line break
// is consumed, and refuses one longer than limit without reading on.
func readBoundedLine(r io.Reader, limit int) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n == 1 {
			if buf[0] == '\n' || buf[0] == '\r' {
				return string(line), nil
			}
			if len(line) >= limit {
				return "", usageErrorf("the connector token is longer than %d bytes", limit)
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return string(line), nil
			}
			return "", errors.New("read the connector token from the terminal failed")
		}
	}
}

// inputs validates the flags and reads the token and the CA file.
func (f joinFlags) inputs(stdin io.Reader) (token string, caPEM []byte, err error) {
	switch {
	case f.server == "":
		return "", nil, usageErrorf("--server is required")
	case f.tokenFile == "" && !f.tokenStdin:
		return "", nil, usageErrorf("give the join token with --token-file or --token-stdin; it is never an argument")
	case f.tokenFile != "" && f.tokenStdin:
		return "", nil, usageErrorf("--token-file and --token-stdin are mutually exclusive")
	}
	source := stdin
	if f.tokenFile != "" {
		file, openErr := os.Open(f.tokenFile)
		if openErr != nil {
			return "", nil, usageErrorf("cannot read --token-file: %s", cause(openErr))
		}
		defer func() { _ = file.Close() }()
		source = file
	}
	raw, err := io.ReadAll(io.LimitReader(source, maxJoinTokenBytes))
	if err != nil {
		return "", nil, fmt.Errorf("read the join token: %w", err)
	}
	if f.caFile != "" {
		if caPEM, err = os.ReadFile(f.caFile); err != nil {
			return "", nil, usageErrorf("cannot read --ca-file: %s", cause(err))
		}
	}
	return string(raw), caPEM, nil
}

// cause strips the path an *fs.PathError repeats from the flag value.
func cause(err error) error {
	if inner := errors.Unwrap(err); inner != nil {
		return inner
	}
	return err
}

func writeJoined(w io.Writer, e wire.Enrolled, asJSON bool) error {
	if asJSON {
		return writeJSON(w, e)
	}
	_, err := fmt.Fprintf(w, "joined: node %s as %s\ninstance key: %s (version %d)\n", e.NodeID, e.SSHUser, e.FingerprintSHA256, e.KeyVersion)
	return err
}
