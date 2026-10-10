package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func newNodesCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nodes",
		Short: "List, add, inspect and probe nodes",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newNodesListCmd(env), newNodesGetCmd(env), newNodesAddCmd(env), newNodesRemoveCmd(env), newNodesProbeCmd(env))
	return cmd
}

func newNodesListCmd(env []string) *cobra.Command {
	var q wire.NodeQuery
	var reachability string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List nodes with their latest known state",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if reachability != "" {
				r, err := domain.ParseReachability(reachability)
				if err != nil {
					return usageErrorf("%s", err)
				}
				q.Reachability = r
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			page, err := api.ListNodes(cmd.Context(), q)
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeNodes(w, page) })
		},
	}
	cmd.Flags().IntVar(&q.Limit, "limit", 0, "maximum items per page (default 50, max 500)")
	cmd.Flags().StringVar(&q.Cursor, "cursor", "", "continue after this cursor")
	cmd.Flags().StringVar(&q.Environment, "environment", "", "only nodes in this environment")
	cmd.Flags().StringVar(&q.Tag, "tag", "", "only nodes with this tag")
	cmd.Flags().StringVar(&reachability, "reachability", "", "only nodes with this reachability")
	return cmd
}

func writeNodes(w io.Writer, page wire.Page[wire.Node]) error {
	rows := make([][]string, len(page.Items))
	for i, n := range page.Items {
		rows[i] = []string{
			string(n.ID), n.Name, orDash(n.Environment), string(n.ManagementState),
			string(n.Reachability) + staleSuffix(n.Stale), string(n.Connection.State), endpointOf(n),
		}
	}
	if err := table(w, []string{"ID", "NAME", "ENVIRONMENT", "MANAGEMENT", "REACHABILITY", "CONNECTION", "ENDPOINT"}, rows); err != nil {
		return err
	}
	moreHint(w, page.NextCursor)
	return nil
}

func staleSuffix(stale bool) string {
	if stale {
		return " (stale)"
	}
	return ""
}

func endpointOf(n wire.Node) string {
	if n.Endpoint.Host == "" {
		return n.Kind
	}
	return fmt.Sprintf("%s@%s:%d", n.Endpoint.AdminUser, n.Endpoint.Host, n.Endpoint.Port)
}

func newNodesGetCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <node>",
		Short: "Show one node (id or name)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			node, err := api.GetNode(cmd.Context(), id, false)
			if err != nil {
				return err
			}
			return emit(cmd, node, func(w io.Writer) error { return writeNode(w, node) })
		},
	}
}

func writeNode(w io.Writer, n wire.Node) error {
	pairs := [][2]string{
		{"id", string(n.ID)},
		{"name", n.Name},
		{"kind", n.Kind},
		{"provider", n.Provider},
		{"environment", orDash(n.Environment)},
		{"management", string(n.ManagementState)},
		{"reachability", string(n.Reachability) + staleSuffix(n.Stale)},
		{"connection", string(n.Connection.State)},
		{"endpoint", endpointOf(n)},
		{"host key", orDash(n.Endpoint.HostKeyFingerprintSHA256)},
		{"os", strings.TrimSpace(n.OS + " " + n.Arch)},
		{"tags", orDash(strings.Join(n.Tags, ","))},
		{"capabilities", capabilityList(n.Capabilities)},
		{"setup", setupSummary(n.Setup)},
		{"last seen", formatTimePtr(n.LastSeenAt)},
		{"spec revision", fmt.Sprint(n.SpecRevision)},
	}
	if n.Connection.LastError != "" {
		pairs = append(pairs, [2]string{"last error", n.Connection.LastError})
	}
	return fields(w, pairs)
}

func capabilityList(caps []wire.Capability) string {
	var names []string
	for _, c := range caps {
		if c.Available {
			names = append(names, c.Name)
		}
	}
	return orDash(strings.Join(names, ","))
}

func setupSummary(s *wire.Setup) string {
	if s == nil {
		return "not set up"
	}
	return fmt.Sprintf("v%d, logs %s, docker access %t, %d unit(s)", s.SetupVersion, s.LogsMode, s.DockerAccess, len(s.Units))
}

type addNodeFlags struct {
	local       bool
	assumeYes   bool
	fingerprint string
	port        int
	request     wire.AddSSHNodeRequest
}

func newNodesAddCmd(env []string) *cobra.Command {
	f := &addNodeFlags{}
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add an SSH node (or this machine with --local)",
		Long: "Add an SSH node. The host key is scanned and its SHA256 fingerprint shown; nothing is\n" +
			"trusted until you confirm it: pass --fingerprint SHA256:... (verified out of band) or type\n" +
			"'yes' at the prompt. The confirmed key is pinned for every later connection.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			if f.local {
				return addLocal(cmd, api, f)
			}
			return addSSH(cmd, api, f)
		},
	}
	r := &f.request
	cmd.Flags().BoolVar(&f.local, "local", false, "register this machine (read-only in M1)")
	cmd.Flags().BoolVar(&f.assumeYes, "yes", false, "with --local: consent without prompting")
	cmd.Flags().StringVar(&f.fingerprint, "fingerprint", "", "expected host key fingerprint (SHA256:...)")
	cmd.Flags().StringVar(&r.Name, "name", "", "node name")
	cmd.Flags().StringVar(&r.Host, "host", "", "host name or address")
	cmd.Flags().IntVar(&f.port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&r.AdminUser, "admin-user", "", "your own account on the node (e.g. root or a personal login)")
	cmd.Flags().StringVar(&r.User, "user", "", "automation account (default supermgmt)")
	cmd.Flags().StringVar(&r.CredentialRef, "credential-ref", "", "automation credential (default secret://ssh/default)")
	cmd.Flags().StringVar(&r.AdminCredentialRef, "admin-credential-ref", "", "your credential for admin-user (default ssh-agent://default)")
	cmd.Flags().StringVar(&r.Environment, "environment", "", "environment name")
	cmd.Flags().StringSliceVar(&r.Tags, "tag", nil, "tag (repeatable)")
	return cmd
}

func addLocal(cmd *cobra.Command, api *client.Client, f *addNodeFlags) error {
	if err := confirm(cmd, "SuperMgmt will read system information from this machine.", f.assumeYes); err != nil {
		return err
	}
	direct, err := api.RegisterLocal(cmd.Context())
	if err != nil {
		return err
	}
	return directOutput(cmd, direct, func(p wire.Provider) string { return fmt.Sprintf("registered local provider %s", p.ID) })
}

func addSSH(cmd *cobra.Command, api *client.Client, f *addNodeFlags) error {
	r := f.request
	r.Port = f.port
	if r.Name == "" || r.Host == "" || r.AdminUser == "" {
		return usageErrorf("--name, --host and --admin-user are required")
	}
	scanned, err := api.ScanHostKey(cmd.Context(), wire.ScanHostKeyRequest{Host: r.Host, Port: r.Port})
	if err != nil {
		return err
	}
	if err := confirmHostKey(cmd, r, scanned, f.fingerprint); err != nil {
		return err
	}
	r.HostPublicKey = scanned.AuthorizedKey
	direct, err := api.AddSSHNode(cmd.Context(), r)
	if err != nil {
		return err
	}
	return directOutput(cmd, direct, func(n wire.Node) string { return fmt.Sprintf("added node %s (%s)", n.Name, n.ID) })
}

// confirmHostKey is the first-trust step (spec §12): the user sees the
// scanned fingerprint and either supplies the expected one or types yes.
func confirmHostKey(cmd *cobra.Command, r wire.AddSSHNodeRequest, scanned wire.HostKey, expected string) error {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s:%d presents %s key %s\n", r.Host, r.Port, scanned.Type, scanned.FingerprintSHA256)
	if expected != "" {
		if expected != scanned.FingerprintSHA256 {
			return smerr.New(smerr.CodeSSHHostKeyMismatch, "",
				fmt.Sprintf("%s presents %s, not the expected %s", r.Host, scanned.FingerprintSHA256, expected))
		}
		return nil
	}
	return confirm(cmd, "Trust this host key?", false)
}

func newNodesRemoveCmd(env []string) *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "remove <node>",
		Short: "Retire a node (its history is kept)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			node, err := api.GetNode(cmd.Context(), id, false)
			if err != nil {
				return err
			}
			if err := confirm(cmd, fmt.Sprintf("Retire node %s?", node.Name), assumeYes); err != nil {
				return err
			}
			direct, err := api.RemoveNode(cmd.Context(), id, node.SpecRevision)
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(n wire.Node) string { return fmt.Sprintf("retired node %s (%s)", n.Name, n.ID) })
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newNodesProbeCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "probe <node>",
		Short: "Probe a node now (an audited job)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveNode(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			submission, err := api.ProbeNode(cmd.Context(), id)
			if err != nil {
				return err
			}
			return submissionOutput(cmd, submission)
		},
	}
}

// resolveNode accepts a node id or an exact node name.
func resolveNode(ctx context.Context, api *client.Client, ref string) (domain.ID, error) {
	if id, err := domain.ParseID(ref); err == nil {
		return id, nil
	}
	var match []wire.Node
	q := wire.NodeQuery{PageQuery: wire.PageQuery{Limit: wire.MaxLimit}}
	for {
		page, err := api.ListNodes(ctx, q)
		if err != nil {
			return "", err
		}
		for _, n := range page.Items {
			if n.Name == ref {
				match = append(match, n)
			}
		}
		if page.NextCursor == "" {
			break
		}
		q.Cursor = page.NextCursor
	}
	switch len(match) {
	case 0:
		return "", smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no node named %q", ref))
	case 1:
		return match[0].ID, nil
	}
	return "", smerr.New(smerr.CodeConflict, smerr.ReasonAmbiguousTarget, fmt.Sprintf("%d nodes are named %q; use the id", len(match), ref))
}
