package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const (
	logsModeJournalGroup = "journal-group"
	logsModeBroker       = "broker"
	policyAllow          = "allow"

	dockerAccessWarning = "docker access adds the supermgmt user to the docker group, which is equivalent to root on the node"
)

func newNodesSetupCmd(env []string) *cobra.Command {
	var dockerAccess, assumeYes, noUnits, tunnel bool
	var logsMode string
	var units []string
	cmd := &cobra.Command{
		Use:   "setup <node>",
		Short: "Provision the dedicated supermgmt account on a node (a job; may wait for approval)",
		Long: "Run node.setup: create the supermgmt account on the node over your own admin account (root, or passwordless\n" +
			"sudo), authorize the instance SSH key, grant systemctl on the units it may manage, and verify the result over\n" +
			"a fresh session as that account. Re-run it after `sm ssh-key rotate` to authorize the new key.\n\n" +
			"--unit grants systemctl on a unit: --unit nginx.service allows start, stop and restart; --unit\n" +
			"nginx.service:restart only restart. Repeat it per unit; the list replaces the node's current grants.\n" +
			"Without --unit a re-run keeps the grants the node has; --no-units removes them all.\n\n" +
			"--tunnel also installs cloudflared on the node and moves its SSH reachability behind a Cloudflare Tunnel; undo it\n" +
			"with `sm nodes tunnel disable`.\n\n" +
			"Docker access is explicit: it is off unless you pass --docker-access, and it is root-equivalent on the node.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if logsMode != logsModeJournalGroup && logsMode != logsModeBroker {
				return usageErrorf("--logs-mode must be %s or %s", logsModeJournalGroup, logsModeBroker)
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
			grants, kept, err := wire.SetupUnits(units, noUnits, node.Setup)
			if err != nil {
				return usageErrorf("%s", err)
			}
			if dockerAccess {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", dockerAccessWarning)
			}
			parameters := wire.SetupParameters(dockerAccess, logsMode, grants)
			details := []string{wire.UnitsChange(node.Setup, grants, kept)}
			if tunnel {
				parameters[paramTunnel] = "true"
				details = append([]string{transportPreview(node.Endpoint.TunnelHostname)}, details...)
			}
			req := wire.CreatePlanRequest{
				Action:     actionNodeSetup,
				Targets:    []wire.ResourceRef{{Type: domain.ResourceNode, ID: id}},
				Parameters: parameters,
			}
			return submitPlan(cmd, api, args[0], req, details, assumeYes)
		},
	}
	cmd.Flags().BoolVar(&dockerAccess, "docker-access", false, "also give the account docker access (root-equivalent on the node)")
	cmd.Flags().StringVar(&logsMode, "logs-mode", logsModeJournalGroup, "how logs are read: "+logsModeJournalGroup+" or "+logsModeBroker)
	cmd.Flags().StringArrayVar(&units, "unit", nil, "grant systemctl on a unit: <unit>[:start,stop,restart] (repeatable)")
	cmd.Flags().BoolVar(&noUnits, "no-units", false, "remove every unit grant")
	cmd.Flags().BoolVar(&tunnel, "tunnel", false, "reach the node through a Cloudflare Tunnel (needs the cloudflare: block)")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	return cmd
}

// describePlan tells the user what the plan is and whether policy lets it run,
// and refuses a plan policy denies.
func describePlan(cmd *cobra.Command, subject string, plan wire.CreatedPlan) error {
	if plan.Policy.Decision != policyAllow {
		reason := ""
		if plan.Policy.Reason != "" {
			reason = " (" + string(plan.Policy.Reason) + ")"
		}
		return smerr.New(smerr.CodePolicyDenied, plan.Policy.Reason, fmt.Sprintf("policy: %s%s", plan.Policy.Decision, reason))
	}
	out := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(out, "plan %s for %s\n", shortPlanHash(plan.PlanHash), subject)
	if plan.Policy.ApprovalRequired {
		_, _ = fmt.Fprintf(out, "it needs %d approval(s) before it runs\n", max(plan.Policy.Quorum, 1))
	} else {
		_, _ = fmt.Fprintln(out, "it runs as soon as it is submitted")
	}
	return nil
}

func shortPlanHash(hash string) string { return hash[:min(len(hash), 12)] }

// ---- repin -----------------------------------------------------------------------------

func newNodesRepinCmd(env []string) *cobra.Command {
	var fingerprint string
	cmd := &cobra.Command{
		Use:   "repin <node>",
		Short: "Trust the host key a node presents now (after a legitimate change)",
		Long: "Re-pin a node to the host key it presents now. The new key is scanned and both fingerprints are shown;\n" +
			"nothing changes until you confirm: pass --fingerprint SHA256:... (verified out of band) or type 'yes'.\n" +
			"Never confirm a key you cannot account for: a changed host key is also what an attack looks like.",
		Args: cobra.ExactArgs(1),
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
			scanned, err := api.ScanHostKey(cmd.Context(), wire.ScanHostKeyRequest{Host: node.Endpoint.Host, Port: node.Endpoint.Port})
			if err != nil {
				return err
			}
			if err := confirmRepin(cmd, node, scanned, fingerprint); err != nil {
				return err
			}
			direct, err := api.UpdateNode(cmd.Context(), id, node.SpecRevision, wire.NodePatch{HostPublicKey: &scanned.AuthorizedKey})
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(n wire.Node) string {
				return fmt.Sprintf("node %s is pinned to %s", n.Name, scanned.FingerprintSHA256)
			})
		},
	}
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "the new host key's fingerprint (SHA256:...), verified out of band")
	return cmd
}

func confirmRepin(cmd *cobra.Command, node wire.Node, scanned wire.HostKey, expected string) error {
	errOut := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(errOut, "%s is pinned to %s\n%s:%d now presents %s key %s\n",
		node.Name, orDash(node.Endpoint.HostKeyFingerprintSHA256), node.Endpoint.Host, node.Endpoint.Port, scanned.Type, scanned.FingerprintSHA256)
	if scanned.FingerprintSHA256 == node.Endpoint.HostKeyFingerprintSHA256 {
		return usageErrorf("%s already presents the pinned key: nothing to re-pin", node.Name)
	}
	if expected != "" {
		if expected != scanned.FingerprintSHA256 {
			return smerr.New(smerr.CodeSSHHostKeyMismatch, "",
				fmt.Sprintf("%s presents %s, not the expected %s", node.Endpoint.Host, scanned.FingerprintSHA256, expected))
		}
		return nil
	}
	return confirm(cmd, "Trust the new host key?", false)
}
