package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/join"
)

const maxTokenBytes = 4096

// joinFactory builds the node-side steps for a server and its optional CA.
type joinFactory func(server string, caPEM []byte) (join.Joiner, error)

// newJoinCmd is `sm join` (spec §13, ADR-0022): run as root on a node, it
// enrolls the node with the server. The token is read from a file or from
// stdin, never from an argument.
func newJoinCmd(_ []string) *cobra.Command {
	return newJoinCmdWith(func(server string, caPEM []byte) (join.Joiner, error) {
		client, err := join.NewClient(server, caPEM)
		if err != nil {
			return join.Joiner{}, err
		}
		return join.Joiner{Host: join.System{}, Enroller: client}, nil
	})
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
}

func newJoinCmdWith(factory joinFactory) *cobra.Command {
	var f joinFlags
	cmd := &cobra.Command{
		Use:   "join --server URL (--token-file FILE | --token-stdin)",
		Short: "Enroll this node with a SuperMgmt server (run as root)",
		Args:  noTokenArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
	return cmd
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
	raw, err := io.ReadAll(io.LimitReader(source, maxTokenBytes))
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
