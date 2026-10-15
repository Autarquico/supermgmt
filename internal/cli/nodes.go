package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

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
	cmd.AddCommand(newNodesListCmd(env), newNodesGetCmd(env), newNodesAddCmd(env), newNodesRemoveCmd(env), newNodesProbeCmd(env),
		newNodesSetupCmd(env), newNodesRepinCmd(env), newNodesPowerCmd(env))
	return cmd
}

func newNodesListCmd(env []string) *cobra.Command {
	var q wire.NodeQuery
	var reachability string
	var tree bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List nodes with their latest known state",
		Long: "List nodes with their latest known state. With --tree, show every node grouped by provider and, for\n" +
			"Proxmox, each cluster node with its VMs and containers; the filters apply and paging is followed.",
		Args: noArgs,
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
			if tree {
				return listNodeTree(cmd, api, q)
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
	cmd.Flags().BoolVar(&tree, "tree", false, "group nodes by provider; Proxmox guests under their cluster node")
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
			api, where, err := connect(cmd, env)
			if err != nil {
				return err
			}
			if f.local {
				return addLocal(cmd, api, f)
			}
			if err := addSSH(cmd, api, f); err != nil {
				return err
			}
			if where.remote == nil && isLocalMode(where.configFile, env) && usesAgent(f.request.AdminCredentialRef) {
				if problem := agentProblem(cmd.Context(), env); problem != "" {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s; until then the node stays unreachable\n", problem)
				}
			}
			return nil
		},
	}
	r := &f.request
	cmd.Flags().BoolVar(&f.local, "local", false, "register this machine (read-only)")
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
	all, err := allNodes(ctx, api, wire.NodeQuery{})
	if err != nil {
		return "", err
	}
	var match []wire.Node
	for _, n := range all {
		if n.Name == ref {
			match = append(match, n)
		}
	}
	switch len(match) {
	case 0:
		return "", smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no node named %q", ref))
	case 1:
		return match[0].ID, nil
	}
	return "", smerr.New(smerr.CodeConflict, smerr.ReasonAmbiguousTarget, fmt.Sprintf("%d nodes are named %q; use the id", len(match), ref))
}

// allNodes follows the cursor until every node matching q has been read.
func allNodes(ctx context.Context, api *client.Client, q wire.NodeQuery) ([]wire.Node, error) {
	q.Limit = wire.MaxLimit
	var all []wire.Node
	for {
		page, err := api.ListNodes(ctx, q)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.NextCursor == "" {
			return all, nil
		}
		q.Cursor = page.NextCursor
	}
}

// ---- tree ------------------------------------------------------------------

func listNodeTree(cmd *cobra.Command, api *client.Client, q wire.NodeQuery) error {
	q.Cursor = ""
	nodes, err := allNodes(cmd.Context(), api, q)
	if err != nil {
		return err
	}
	return emit(cmd, wire.Page[wire.Node]{Items: nodes}, func(w io.Writer) error { return writeNodeTree(w, nodes) })
}

// writeNodeTree groups nodes by provider. Under a Proxmox provider each
// cluster node holds the guests that run on it; every other node stands alone.
// Rows are NAME, TYPE, STATE, MANAGEMENT and marks.
func writeNodeTree(w io.Writer, nodes []wire.Node) error {
	byProvider := map[string][]wire.Node{}
	for _, n := range nodes {
		byProvider[n.Provider] = append(byProvider[n.Provider], n)
	}
	var lines []string
	for _, provider := range slices.Sorted(maps.Keys(byProvider)) {
		lines = append(lines, provider)
		lines = append(lines, providerTree(byProvider[provider])...)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, line := range lines {
		_, _ = fmt.Fprintln(tw, line)
	}
	return tw.Flush()
}

func providerTree(nodes []wire.Node) []string {
	clusterNodes := map[string][]wire.Node{} // by PVE node name
	var standalone []wire.Node
	for _, n := range nodes {
		if n.Proxmox == nil {
			standalone = append(standalone, n)
			continue
		}
		clusterNodes[n.Proxmox.PVENode] = append(clusterNodes[n.Proxmox.PVENode], n)
	}
	var branches [][]string
	for _, pveNode := range slices.Sorted(maps.Keys(clusterNodes)) {
		branches = append(branches, clusterBranch(pveNode, clusterNodes[pveNode]))
	}
	slices.SortFunc(standalone, func(a, b wire.Node) int { return strings.Compare(a.Name, b.Name) })
	for _, n := range standalone {
		branches = append(branches, []string{treeRow(n.Name, n.Kind, string(n.Reachability)+staleSuffix(n.Stale), string(n.ManagementState), "")})
	}
	var lines []string
	for i, branch := range branches {
		last := i == len(branches)-1
		for j, line := range branch {
			lines = append(lines, branchPrefix(j == 0, last)+line)
		}
	}
	return lines
}

const proxmoxNodeType = "node"

// clusterBranch is a cluster node row followed by its guests, VMID order.
func clusterBranch(pveNode string, members []wire.Node) []string {
	var head *wire.Node
	var guests []wire.Node
	for _, n := range members {
		if n.Proxmox.Type == proxmoxNodeType {
			head = &n
		} else {
			guests = append(guests, n)
		}
	}
	slices.SortFunc(guests, func(a, b wire.Node) int { return a.Proxmox.VMID - b.Proxmox.VMID })
	lines := []string{treeRow(pveNode, proxmoxNodeType, "unknown", "-", "[node not listed]")}
	if head != nil {
		lines = []string{proxmoxRow(head.Name, *head)}
	}
	for i, g := range guests {
		lines = append(lines, guestPrefix(i == len(guests)-1)+proxmoxRow(g.Name, g))
	}
	return lines
}

// branchPrefix draws the provider-level connector, or the bar that continues
// it down the lines of a branch.
func branchPrefix(first, last bool) string {
	switch {
	case first && last:
		return "\u2514\u2500 "
	case first:
		return "\u251c\u2500 "
	case last:
		return "   "
	}
	return "\u2502  "
}

func guestPrefix(last bool) string {
	if last {
		return "\u2514\u2500 "
	}
	return "\u251c\u2500 "
}

func proxmoxRow(name string, n wire.Node) string {
	g := n.Proxmox
	kind := g.Type
	if g.VMID != 0 {
		kind = fmt.Sprintf("%s/%d", g.Type, g.VMID)
	}
	var marks []string
	if g.Template {
		marks = append(marks, "[template]")
	}
	if g.Absent {
		marks = append(marks, "[absent]")
	}
	if g.Inaccessible {
		marks = append(marks, "[inaccessible]")
	}
	return treeRow(name, kind, g.Status, string(n.ManagementState), strings.Join(marks, " "))
}

func treeRow(name, kind, state, management, marks string) string {
	cells := []string{name, kind, state, management, marks}
	return strings.TrimRight(strings.Join(cells, "\t"), "\t")
}

// ---- power -----------------------------------------------------------------

const (
	actionProxmoxVMPower = "proxmox.vm.power"
	jobPollInterval      = 500 * time.Millisecond
)

var powerVerbs = []string{"start", "shutdown", "reboot", "stop"}

func newNodesPowerCmd(env []string) *cobra.Command {
	var assumeYes, wait bool
	cmd := &cobra.Command{
		Use:   "power <node> <start|shutdown|reboot|stop>",
		Short: "Power a Proxmox VM or container (a job; stop needs approval)",
		Long: "Plan the power action, show what policy says, and submit it once you confirm.\n\n" +
			"start boots the guest, shutdown asks its OS to stop, reboot restarts it. stop cuts the power at once\n" +
			"without a clean shutdown: it is high risk and waits for approval where policy asks for it.\n\n" +
			"With --wait, stay until the job ends (a job waiting for approval keeps you waiting): exit status 0 when\n" +
			"it succeeded.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			verb := args[1]
			if !slices.Contains(powerVerbs, verb) {
				return usageErrorf("unknown power action %q: want %s", verb, strings.Join(powerVerbs, ", "))
			}
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
			if err := checkPowerTarget(node); err != nil {
				return err
			}
			return submitPower(cmd, api, node, verb, assumeYes, wait)
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait until the job ends")
	return cmd
}

// checkPowerTarget refuses early what the daemon would refuse later: only a
// guest that is there can be powered.
func checkPowerTarget(n wire.Node) error {
	switch g := n.Proxmox; {
	case g == nil || g.Type == proxmoxNodeType:
		return usageErrorf("%s is not a Proxmox VM or container", n.Name)
	case g.Template:
		return usageErrorf("%s is a template and cannot be powered", n.Name)
	case g.Absent:
		return usageErrorf("%s is gone from Proxmox (absent)", n.Name)
	case g.Inaccessible:
		return usageErrorf("%s is inaccessible: the token lost the privilege to see it", n.Name)
	}
	return nil
}

func submitPower(cmd *cobra.Command, api *client.Client, node wire.Node, verb string, assumeYes, wait bool) error {
	plan, err := api.CreatePlan(cmd.Context(), wire.CreatePlanRequest{
		Action:     actionProxmoxVMPower,
		Targets:    []wire.ResourceRef{{Type: domain.ResourceNode, ID: node.ID}},
		Parameters: map[string]any{"verb": verb},
	})
	if err != nil {
		return err
	}
	if err := describePlan(cmd, fmt.Sprintf("%s %s", verb, node.Name), plan); err != nil {
		return err
	}
	describePowerRisk(cmd, plan, verb)
	if err := confirm(cmd, "Submit this plan?", assumeYes); err != nil {
		return err
	}
	submission, err := api.SubmitPlan(cmd.Context(), plan.PlanID, plan.PlanHash)
	if err != nil {
		return err
	}
	if submission.Policy.ApprovalRequired {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "to approve: sm jobs approve %s --plan-hash %s\n", submission.Job.ID, plan.PlanHash)
	}
	if !wait {
		return submissionOutput(cmd, submission)
	}
	return waitForJob(cmd, api, submission.Job.ID)
}

// describePowerRisk shows the risk class the plan carries, and what a hard
// stop does to the guest.
func describePowerRisk(cmd *cobra.Command, plan wire.CreatedPlan, verb string) {
	var doc struct {
		Risk domain.RiskClass `json:"risk"`
	}
	_ = json.Unmarshal(plan.Plan, &doc)
	errOut := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(errOut, "risk: %s\n", orDash(string(doc.Risk)))
	if verb == "stop" {
		_, _ = fmt.Fprintln(errOut, "stop cuts the guest's power without a clean shutdown; use shutdown to let its OS stop first")
	}
}

// waitForJob polls the job until it ends and reports how. Interrupted ends the
// wait too: only a person can settle it (`sm jobs resolve`).
func waitForJob(cmd *cobra.Command, api *client.Client, id domain.ID) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { _ = api.HoldPresence(ctx) }()

	ticker := time.NewTicker(jobPollInterval)
	defer ticker.Stop()
	var shown domain.JobState
	for {
		detail, err := api.GetJob(ctx, id)
		if err != nil {
			if ctx.Err() != nil {
				return usageErrorf("stopped waiting: the job continues, see `sm jobs get %s`", id)
			}
			return err
		}
		if state := detail.Job.State; state != shown {
			shown = state
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "job %s is %s\n", id, state)
		}
		if detail.Job.State.Terminal() || detail.Job.State == domain.JobInterrupted {
			return finishWait(cmd, detail)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}

func finishWait(cmd *cobra.Command, detail wire.JobDetail) error {
	job := detail.Job
	err := emit(cmd, detail, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "job %s (%s) %s\n", job.ID, job.Type, job.State)
		return err
	})
	if err != nil {
		return err
	}
	switch {
	case job.State == domain.JobSucceeded:
		return nil
	case job.State == domain.JobInterrupted:
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("job %s was interrupted and its outcome is unknown: see `sm jobs get %s`, then `sm jobs resolve`", job.ID, job.ID))
	case job.Error != nil:
		return smerr.New(job.Error.Code, job.Error.Reason, job.Error.Message)
	}
	return smerr.New(smerr.CodeInternal, "", fmt.Sprintf("job %s %s", job.ID, job.State))
}
