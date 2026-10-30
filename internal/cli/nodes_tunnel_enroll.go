package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// `sm nodes add --tunnel` adds a node that is reachable only through Cloudflare Tunnel (ADR-0039). The
// daemon owns the enrollment; this command starts it, shows the operator the line to run on the node and
// the connector token, relays the host key confirmation and waits for the commit. Interrupting it leaves
// the enrollment running, and running it again for the same name reattaches.

// stdinIsTerminal tells whether the operator can be asked a question; tests replace it.
var stdinIsTerminal = func(cmd *cobra.Command) bool { return isTerminal(cmd.InOrStdin()) }

// tunnelFlags are the flags of `sm nodes add` that only --tunnel gives a meaning to.
type tunnelFlags struct {
	enabled   bool
	showToken bool
	cancel    bool
	expiresIn time.Duration
	interval  time.Duration
}

func (t *tunnelFlags) bind(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&t.enabled, "tunnel", false, "add a node reachable only through Cloudflare Tunnel (experimental)")
	cmd.Flags().DurationVar(&t.expiresIn, "expires-in", time.Hour, "with --tunnel: how long the node has to run the line (at most 24h)")
	cmd.Flags().BoolVar(&t.showToken, "show-token", false, "with --tunnel: print the connector token of the open enrollment again")
	cmd.Flags().BoolVar(&t.cancel, "cancel", false, "with --tunnel: cancel the open enrollment and remove its Cloudflare objects")
	cmd.Flags().DurationVar(&t.interval, "interval", defaultWatchInterval, "with --tunnel: how often to poll the enrollment")
}

// tunnelExcluded are the flags that describe a direct SSH node, which --tunnel replaces.
var tunnelExcluded = []string{"host", "port", "admin-user", "admin-credential-ref", "user", "credential-ref", "local"}

// tunnelOnly are the flags that mean nothing without --tunnel.
var tunnelOnly = []string{"expires-in", "show-token", "cancel", "interval"}

// check refuses the flag combinations that make no sense, before any request.
func (t *tunnelFlags) check(cmd *cobra.Command, name, fingerprint string) error {
	changed := func(names []string) []string {
		var out []string
		for _, n := range names {
			if cmd.Flags().Changed(n) {
				out = append(out, "--"+n)
			}
		}
		return out
	}
	if !t.enabled {
		if bad := changed(tunnelOnly); len(bad) > 0 {
			return usageErrorf("%s only apply with --tunnel", strings.Join(bad, ", "))
		}
		return nil
	}
	if bad := changed(tunnelExcluded); len(bad) > 0 {
		return usageErrorf("--tunnel excludes %s: the node is reached through Cloudflare, not by address", strings.Join(bad, ", "))
	}
	switch {
	case name == "":
		return usageErrorf("--name is required")
	case t.showToken && t.cancel:
		return usageErrorf("--show-token and --cancel are mutually exclusive")
	case t.showToken || t.cancel:
		if bad := changed([]string{"environment", "tag", "expires-in", "fingerprint"}); len(bad) > 0 {
			return usageErrorf("%s do not apply to an enrollment that already exists", strings.Join(bad, ", "))
		}
		return nil
	case t.expiresIn <= 0 || t.expiresIn > 24*time.Hour:
		return usageErrorf("--expires-in must be between 1s and 24h")
	case fingerprint == "" && !stdinIsTerminal(cmd):
		return usageErrorf("--fingerprint is required without a terminal: compare the host key the node printed and pass it")
	}
	return nil
}

func addTunnel(cmd *cobra.Command, api *client.Client, f *addNodeFlags) error {
	name := f.request.Name
	switch {
	case f.tunnel.cancel:
		return cancelEnrollment(cmd, api, name)
	case f.tunnel.showToken:
		return showEnrollmentToken(cmd, api, name)
	}
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	go func() { _ = api.HoldPresence(ctx) }()
	run := &enrollRun{cmd: cmd, api: api, ctx: ctx, name: name, interval: f.tunnel.interval, fingerprint: f.fingerprint}
	run.interruptible(cancel)
	defer run.uninterruptible()

	view, attached, err := run.openEnrollment(f)
	if err != nil || view == nil {
		return err
	}
	return run.follow(*view, attached)
}

func cancelEnrollment(cmd *cobra.Command, api *client.Client, name string) error {
	view, err := api.CancelTunnelEnrollment(cmd.Context(), name)
	if err != nil {
		return err
	}
	return emit(cmd, view, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "enrollment %s is %s; its Cloudflare objects are being removed\n", view.Name, view.Phase)
		return err
	})
}

func showEnrollmentToken(cmd *cobra.Command, api *client.Client, name string) error {
	token, err := api.TunnelEnrollmentToken(cmd.Context(), name)
	if err != nil {
		return err
	}
	return emit(cmd, token, func(w io.Writer) error {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "connector token (paste it at the node's prompt):")
		_, err := fmt.Fprintln(w, token.Token)
		return err
	})
}

// enrollRun is one `sm nodes add --tunnel` invocation following an enrollment.
type enrollRun struct {
	cmd         *cobra.Command
	api         *client.Client
	ctx         context.Context //nolint:containedctx // the invocation's interruptible context
	signals     chan os.Signal
	name        string
	interval    time.Duration
	fingerprint string

	shownPhase, shownError string
}

// interruptible turns an interrupt into the cancellation of the wait, so the command can say how to
// reattach. uninterruptible gives the interrupt back to the process, which is what a question needs: the
// default action ends the command and the enrollment keeps running.
func (r *enrollRun) interruptible(cancel context.CancelFunc) {
	r.signals = make(chan os.Signal, 1)
	signal.Notify(r.signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-r.signals:
			cancel()
		case <-r.ctx.Done():
		}
	}()
}

func (r *enrollRun) uninterruptible() { signal.Stop(r.signals) }

// openEnrollment reattaches to the open enrollment of the name or starts one. A nil view means the start
// is waiting for approval and has been reported.
func (r *enrollRun) openEnrollment(f *addNodeFlags) (view *wire.TunnelEnrollment, attached bool, err error) {
	existing, err := r.api.GetTunnelEnrollment(r.ctx, r.name)
	switch {
	case err == nil && openPhase(existing.Phase):
		return &existing, true, nil
	case err != nil && smerr.CodeOf(err) != smerr.CodeNotFound:
		return nil, false, err
	}
	started, err := r.api.StartTunnelEnrollment(r.ctx, wire.StartTunnelEnrollmentRequest{
		Name: r.name, Environment: f.request.Environment, Tags: f.request.Tags, ExpiresIn: f.tunnel.expiresIn.String(),
	})
	if err != nil {
		return nil, false, err
	}
	if started.Applied == nil {
		if err := directOutput(r.cmd, started, func(wire.TunnelEnrollment) string { return "" }); err != nil {
			return nil, false, err
		}
		r.say("after it is approved, run the same command again to continue")
		return nil, false, nil
	}
	return started.Applied, false, nil
}

// follow takes the enrollment through the node line, the host key confirmation and the commit.
func (r *enrollRun) follow(view wire.TunnelEnrollment, attached bool) error {
	if attached {
		r.say("reattached to the enrollment of %s (%s); it expires %s", view.Name, view.Phase, view.ExpiresAt.Local().Format(time.DateTime))
	}
	view, err := r.until(view, func(v wire.TunnelEnrollment) bool { return stageOf(v.Phase) >= stageWaiting })
	if err != nil {
		return err
	}
	if err := r.showLine(view, attached); err != nil {
		return err
	}
	view, err = r.until(view, func(v wire.TunnelEnrollment) bool { return stageOf(v.Phase) >= stageScanned })
	if err != nil {
		return err
	}
	if stageOf(view.Phase) == stageScanned {
		if err := r.confirmKey(view); err != nil {
			return err
		}
	}
	view, err = r.until(view, func(v wire.TunnelEnrollment) bool { return stageOf(v.Phase) >= stageCommitted })
	if err != nil {
		return err
	}
	return emit(r.cmd, view, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "added node %s (%s) through %s\n", view.Name, view.NodeID, view.Hostname)
		return err
	})
}

// showLine prints the line to run on the node and, on the first attach only, the connector token
// separately. The token goes where the operator reads it and nowhere else.
func (r *enrollRun) showLine(view wire.TunnelEnrollment, attached bool) error {
	out := r.cmd.OutOrStdout()
	if wantsJSON(r.cmd) {
		out = r.cmd.ErrOrStderr()
	}
	r.say("\nRun this line on %s (Debian 13 or Ubuntu 24.04, as a user that can sudo); the node will be reached at %s:", view.Name, view.Hostname)
	_, _ = fmt.Fprintf(out, "\n%s\n\n", view.JoinLine)
	if stageOf(view.Phase) != stageWaiting {
		return nil
	}
	if attached {
		r.say("The connector token is not shown again here: `sm nodes add --tunnel --name %s --show-token` prints it while the enrollment is open.", view.Name)
		return nil
	}
	token, err := r.api.TunnelEnrollmentToken(r.ctx, view.Name)
	if err != nil {
		return err
	}
	r.say("The line asks for the connector token. Paste it at the node's prompt; it is shown only here (and by --show-token):")
	_, _ = fmt.Fprintf(out, "\n%s\n\n", token.Token)
	return nil
}

// confirmKey shows the scanned key's fingerprint and confirms it, bound to that exact key: with the
// expected --fingerprint, or after the operator types yes. Anything else ends the enrollment.
func (r *enrollRun) confirmKey(view wire.TunnelEnrollment) error {
	r.say("%s presents %s key %s", view.Hostname, keyType(view.HostPublicKey), view.HostKeyFingerprint)
	if r.fingerprint != "" {
		if r.fingerprint != view.HostKeyFingerprint {
			return r.refuse(fmt.Sprintf("%s presents %s, not the expected %s", view.Hostname, view.HostKeyFingerprint, r.fingerprint))
		}
	} else {
		r.say("Compare it with the host key fingerprint the node printed.")
		r.uninterruptible() // a Ctrl-C at the question ends the command and leaves the enrollment running
		answer, err := r.ask("Trust this host key?")
		signal.Notify(r.signals, os.Interrupt, syscall.SIGTERM)
		if err != nil {
			return err
		}
		if answer != "yes" {
			return r.refuse("the host key was not trusted")
		}
	}
	_, err := r.api.ConfirmTunnelEnrollment(r.ctx, view.Name, view.HostPublicKey)
	return err
}

// refuse ends the enrollment because the operator did not accept the key. The daemon answers
// SSH_HOST_KEY_MISMATCH, which is the outcome, so it is reported as the command's own error.
func (r *enrollRun) refuse(why string) error {
	if err := r.api.RefuseTunnelEnrollment(r.cmd.Context(), r.name); err != nil && smerr.CodeOf(err) != smerr.CodeSSHHostKeyMismatch {
		return fmt.Errorf("%s, and ending the enrollment failed: %w", why, err)
	}
	return smerr.New(smerr.CodeSSHHostKeyMismatch, "", why+": the enrollment is ended and its Cloudflare objects are being removed")
}

// ask reads one line; end of input without an answer is an error, not a refusal.
func (r *enrollRun) ask(question string) (string, error) {
	_, _ = fmt.Fprintf(r.cmd.ErrOrStderr(), "%s Type 'yes' to continue: ", question)
	line, err := bufio.NewReader(r.cmd.InOrStdin()).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return "", usageErrorf("no answer: the enrollment stays open, run the same command again")
	}
	return strings.TrimSpace(line), nil
}

// until polls the enrollment until done, reporting each change of phase. A halted or ended enrollment is
// an error; so is an interruption, which says how to reattach.
func (r *enrollRun) until(view wire.TunnelEnrollment, done func(wire.TunnelEnrollment) bool) (wire.TunnelEnrollment, error) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		r.progress(view)
		if done(view) {
			return view, nil
		}
		if err := enrollmentFailure(view); err != nil {
			return view, err
		}
		select {
		case <-r.ctx.Done():
			return view, r.interrupted()
		case <-ticker.C:
		}
		next, err := r.api.GetTunnelEnrollment(r.ctx, r.name)
		if err != nil {
			if r.ctx.Err() != nil {
				return view, r.interrupted()
			}
			return view, err
		}
		view = next
	}
}

func (r *enrollRun) interrupted() error {
	return usageErrorf("stopped waiting: the enrollment of %s stays open; run `sm nodes add --tunnel --name %s` again to reattach", r.name, r.name)
}

func (r *enrollRun) progress(v wire.TunnelEnrollment) {
	if v.Phase != r.shownPhase {
		r.shownPhase = v.Phase
		r.say("%s: %s", v.Name, describePhase(v))
	}
	if v.Error != "" && v.Error != r.shownError && openPhase(v.Phase) {
		r.shownError = v.Error
		r.say("  %s", v.Error)
	}
}

func (r *enrollRun) say(format string, args ...any) {
	_, _ = fmt.Fprintf(r.cmd.ErrOrStderr(), format+"\n", args...)
}

// ---- phases ----------------------------------------------------------------

// The stages an enrollment walks, in order; phases outside them are being built, halted or ended.
const (
	stageBuilding = iota
	stageWaiting  // dns_created: the Cloudflare side is ready and the node is awaited
	stageScanned
	stageConfirmed
	stageCommitted
	stageNone = -1
)

var stages = map[database.TunnelPhase]int{
	database.PhaseStarted: stageBuilding, database.PhaseTokenReady: stageBuilding, database.PhaseTunnelCreated: stageBuilding,
	database.PhaseIngressSet: stageBuilding, database.PhaseAccessReady: stageBuilding,
	database.PhaseDNSCreated: stageWaiting, database.PhaseScanned: stageScanned,
	database.PhaseConfirmed: stageConfirmed, database.PhaseCommitted: stageCommitted,
}

func stageOf(phase string) int {
	if stage, ok := stages[database.TunnelPhase(phase)]; ok {
		return stage
	}
	return stageNone
}

// openPhase is an enrollment that can still become a node.
func openPhase(phase string) bool {
	return stageOf(phase) != stageNone && stageOf(phase) != stageCommitted
}

func describePhase(v wire.TunnelEnrollment) string {
	switch stageOf(v.Phase) {
	case stageBuilding:
		return "building the Cloudflare side"
	case stageWaiting:
		return "waiting for the node to run the line (expires " + v.ExpiresAt.Local().Format(time.DateTime) + ")"
	case stageScanned:
		return "the node answered through the tunnel"
	case stageConfirmed:
		return "host key confirmed; proving the node and adding it"
	case stageCommitted:
		return "committed"
	}
	return v.Phase
}

// enrollmentFailure is why an enrollment that is not open and not committed will not become a node.
func enrollmentFailure(v wire.TunnelEnrollment) error {
	if stageOf(v.Phase) != stageNone {
		return nil
	}
	if database.TunnelPhase(v.Phase).Halted() {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the enrollment of %s is halted: %s; cancel it with `sm nodes add --tunnel --name %s --cancel`", v.Name, v.Error, v.Name))
	}
	code, why := smerr.CodeConflict, v.Error
	if why == string(smerr.CodeSSHHostKeyMismatch) {
		code = smerr.CodeSSHHostKeyMismatch
	}
	if why == "" {
		why = v.Phase
	}
	return smerr.New(code, "", fmt.Sprintf("the enrollment of %s ended (%s); its Cloudflare objects are removed", v.Name, why))
}

func keyType(authorizedKey string) string {
	typ, _, _ := strings.Cut(authorizedKey, " ")
	return strings.TrimPrefix(typ, "ssh-")
}
