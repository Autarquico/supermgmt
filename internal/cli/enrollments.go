package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

const (
	maxEnrollmentLifetime = 24 * time.Hour
	defaultEnrollmentTTL  = "1h"
	serverURLPlaceholder  = "https://<server>"
)

func newEnrollmentsCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enrollments",
		Short: "Issue join tokens for nodes that enroll themselves",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newEnrollmentsCreateCmd(env))
	return cmd
}

type enrollmentFlags struct {
	expiresIn   string
	tags        []string
	sourceCIDRs []string
	maxNodes    int
}

func newEnrollmentsCreateCmd(env []string) *cobra.Command {
	var f enrollmentFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Issue a join token (the value is shown once)",
		Long: "Issue a join token for `sm join`. It lives at most 24 hours and can be limited to a number of\n" +
			"nodes, to tags the enrolled nodes receive and to source networks. The token is printed once, alone, on\n" +
			"stdout; the command to run on the node goes to stderr and never contains it.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request, err := f.request(domain.SystemClock{}.Now())
			if err != nil {
				return err
			}
			api, where, err := connect(cmd, env)
			if err != nil {
				return err
			}
			issued, err := api.CreateEnrollment(cmd.Context(), request)
			if err != nil {
				return err
			}
			return emit(cmd, issued, func(w io.Writer) error {
				writeJoinInstructions(cmd.ErrOrStderr(), issued, serverOf(where))
				_, err := fmt.Fprintln(w, issued.Token)
				return err
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.expiresIn, "expires-in", defaultEnrollmentTTL, "lifetime, e.g. 30m or 12h (at most 24h)")
	fl.StringSliceVar(&f.tags, "tag", nil, "tag given to every node that enrolls with this token (repeatable)")
	fl.IntVar(&f.maxNodes, "max-nodes", 1, "how many nodes may enroll with this token")
	fl.StringSliceVar(&f.sourceCIDRs, "source-cidr", nil, "network the enrolling node must come from, e.g. 203.0.113.0/24 (repeatable)")
	return cmd
}

// request resolves the flags to POST /enrollments. Tags and networks are
// checked by the server, which owns their rules.
func (f enrollmentFlags) request(now time.Time) (wire.EnrollmentRequest, error) {
	if f.maxNodes < 1 {
		return wire.EnrollmentRequest{}, usageErrorf("--max-nodes must be at least 1")
	}
	ttl, err := parseLifetime(f.expiresIn)
	if err != nil {
		return wire.EnrollmentRequest{}, err
	}
	if ttl > maxEnrollmentLifetime {
		return wire.EnrollmentRequest{}, usageErrorf("a join token lives at most 24 hours")
	}
	return wire.EnrollmentRequest{
		Tags: nonNilStrings(f.tags), MaxNodes: f.maxNodes, SourceCIDRs: nonNilStrings(f.sourceCIDRs), ExpiresAt: now.Add(ttl).UTC(),
	}, nil
}

// serverOf is the HTTPS URL a node can join, known only for a remote profile.
func serverOf(where target) string {
	if where.remote != nil && where.remote.URL != "" {
		return where.remote.URL
	}
	return serverURLPlaceholder
}

// writeJoinInstructions says what to run on the node. The token is read from
// stdin there: an argument is visible to every process on the machine.
func writeJoinInstructions(w io.Writer, issued wire.EnrollmentIssued, server string) {
	_, _ = fmt.Fprintf(w, "join token %s expires %s; this is the only time its value is shown.\n", issued.ID, formatTime(issued.ExpiresAt))
	_, _ = fmt.Fprintf(w, "On the node, as root, give it the token on standard input (never as an argument):\n")
	_, _ = fmt.Fprintf(w, "  sm join --server %s --token-stdin\n", server)
	_, _ = fmt.Fprintf(w, "or, where sm is not installed yet:\n")
	_, _ = fmt.Fprintf(w, "  sudo ./join.sh --token-stdin --server %s\n", server)
}
