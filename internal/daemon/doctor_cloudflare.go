package daemon

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

// Names of the Cloudflare doctor checks. They appear only when the
// configuration has a cloudflare: block.
const (
	checkCloudflared    = "cloudflare_cloudflared"
	checkCFAPIToken     = "cloudflare_api_token" //nolint:gosec // a check name, not a credential
	checkCFAPIReads     = "cloudflare_api_reads"
	checkCFEditRights   = "cloudflare_edit_rights"
	checkCFServiceToken = "cloudflare_service_token" //nolint:gosec // a check name, not a credential
	checkCFOperations   = "cloudflare_tunnel_operations"
)

// serviceTokenExpiryWarning is how long before expiry the doctor starts to warn.
const serviceTokenExpiryWarning = 30 * 24 * time.Hour

// CloudflareProber is the part of the Cloudflare client the doctor uses: reads only.
type CloudflareProber interface {
	Probe(ctx context.Context, zone string) cloudflare.ProbeReport
}

// CloudflareDoctor is what the Cloudflare checks need. Without Secrets and
// NewProber the run is offline: no network, only cloudflared and the database.
type CloudflareDoctor struct {
	Config config.Cloudflare
	Now    time.Time
	// DB is nil when the database cannot be read (a daemon holds it).
	DB database.Querier
	// Locate finds cloudflared; nil uses the dialler's search.
	Locate func() (string, error)
	// Secrets and NewProber, both set, enable the checks that call Cloudflare.
	Secrets   app.TunnelSecrets
	NewProber func(token audit.Secret) (CloudflareProber, error)
}

// Run returns the checks in a stable order.
func (d CloudflareDoctor) Run(ctx context.Context) []wire.DoctorCheck {
	locate := d.Locate
	if locate == nil {
		locate = ssh.LocateCloudflared
	}
	checks := []wire.DoctorCheck{cloudflaredCheck(locate)}
	online := d.Secrets != nil && d.NewProber != nil
	var nodes []domain.Node
	var nodesErr error
	if d.DB != nil {
		nodes, nodesErr = database.ListNodes(ctx, d.DB)
	}
	if online {
		checks = append(checks, d.apiChecks(ctx, d.provisioned(ctx, nodes, nodesErr))...)
	}
	if d.DB == nil {
		return checks
	}
	if online {
		if nodesErr != nil {
			checks = append(checks, wire.DoctorCheck{Name: checkCFServiceToken, Status: checkFail, Detail: nodesErr.Error()})
		} else {
			checks = append(checks, d.serviceTokenCheck(ctx, nodes))
		}
	}
	return append(checks, CloudflareOperationsCheck(ctx, d.DB))
}

// provisioned reports whether the API token is not needed for now: a node
// dials through the tunnel and no tunnel operation is unfinished. Only then is
// a token Cloudflare rejects a warning instead of a failure.
func (d CloudflareDoctor) provisioned(ctx context.Context, nodes []domain.Node, nodesErr error) bool {
	if d.DB == nil || nodesErr != nil || !usesCloudflare(nodes) {
		return false
	}
	ops, err := database.ListActiveTunnelOperations(ctx, d.DB)
	return err == nil && len(ops) == 0
}

func cloudflaredCheck(locate func() (string, error)) wire.DoctorCheck {
	path, err := locate()
	if err != nil {
		return wire.DoctorCheck{
			Name: checkCloudflared, Status: checkFail,
			Detail: cloudflaredFailure(err, runtime.GOOS),
		}
	}
	return wire.DoctorCheck{Name: checkCloudflared, Status: checkOK, Detail: path}
}

func (d CloudflareDoctor) apiChecks(ctx context.Context, provisioned bool) []wire.DoctorCheck {
	name := strings.TrimPrefix(d.Config.APITokenRef, "secret://")
	token, err := d.Secrets.Get(ctx, secrets.Ref{Name: name})
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return []wire.DoctorCheck{{
			Name: checkCFAPIToken, Status: checkWarn,
			Detail: "not in the secret store at " + d.Config.APITokenRef + ": fine once nodes are provisioned, needed by tunnel jobs",
		}}
	case err != nil:
		return []wire.DoctorCheck{{Name: checkCFAPIToken, Status: checkFail, Detail: "cannot be read: " + err.Error()}}
	}
	prober, err := d.NewProber(token)
	if err != nil {
		return []wire.DoctorCheck{{Name: checkCFAPIToken, Status: checkFail, Detail: "unusable: check cloudflare.api_token_ref"}}
	}
	return apiProbeChecks(prober.Probe(ctx, d.Config.Zone), provisioned)
}

// apiProbeChecks turns a probe into rows: validity, the reads that succeeded,
// and edit rights, which Cloudflare cannot prove without mutating.
func apiProbeChecks(r cloudflare.ProbeReport, provisioned bool) []wire.DoctorCheck {
	failure := checkFail
	if provisioned {
		failure = checkWarn // dialling does not use the API token
	}
	token := wire.DoctorCheck{Name: checkCFAPIToken, Status: checkOK, Detail: "valid and active"}
	rejected := !r.Check(cloudflare.CheckToken).OK()
	if rejected {
		token.Status, token.Detail = failure, r.Check(cloudflare.CheckToken).Err.Error()
		if provisioned {
			token.Detail = "provisioning unavailable (not needed for dialling): " + token.Detail
		}
	}
	var proven, failed []string
	for _, c := range r.Checks {
		switch {
		case c.Name == cloudflare.CheckToken:
		case c.OK():
			proven = append(proven, c.Name)
		default:
			failed = append(failed, fmt.Sprintf("%s (%s)", c.Name, c.Err))
		}
	}
	reads := wire.DoctorCheck{Name: checkCFAPIReads, Status: checkOK, Detail: "can read " + strings.Join(proven, ", ")}
	if len(failed) > 0 {
		reads.Status = checkFail
		if rejected {
			reads.Status = failure
		}
		reads.Detail = "cannot read " + strings.Join(failed, "; ")
		if len(proven) > 0 {
			reads.Detail += "; can read " + strings.Join(proven, ", ")
		}
	}
	edit := wire.DoctorCheck{
		Name: checkCFEditRights, Status: checkWarn,
		Detail: "not verifiable: Cloudflare offers no way to prove tunnel, Access and DNS edit rights without changing something",
	}
	return []wire.DoctorCheck{token, reads, edit}
}

func usesCloudflare(nodes []domain.Node) bool {
	for _, n := range nodes {
		if n.Endpoint.Transport == domain.TransportCloudflare {
			return true
		}
	}
	return false
}

// serviceTokenCheck judges the runtime Access service token the dialler uses:
// missing or expired is a failure while a node depends on it, a warning within
// 30 days of expiry. The stored secret must exist as well. Online only.
func (d CloudflareDoctor) serviceTokenCheck(ctx context.Context, nodes []domain.Node) wire.DoctorCheck {
	needed := usesCloudflare(nodes)
	missing := func(detail string) wire.DoctorCheck {
		if needed {
			return wire.DoctorCheck{Name: checkCFServiceToken, Status: checkFail, Detail: detail + ": a node uses the cloudflare transport; run sm nodes setup <node> --tunnel"}
		}
		return wire.DoctorCheck{Name: checkCFServiceToken, Status: checkOK, Detail: detail + " (no node uses the cloudflare transport yet)"}
	}
	state, err := database.GetCloudflareState(ctx, d.DB)
	switch {
	case smerr.CodeOf(err) == smerr.CodeNotFound:
		return missing("not created yet")
	case err != nil:
		return wire.DoctorCheck{Name: checkCFServiceToken, Status: checkFail, Detail: err.Error()}
	}
	name := strings.TrimPrefix(d.Config.AccessTokenRef, "secret://")
	if _, err := d.Secrets.Get(ctx, secrets.Ref{Name: name}); err != nil {
		return missing("its secret is not in the store at " + d.Config.AccessTokenRef)
	}
	expires := state.Token.ExpiresAt
	check := wire.DoctorCheck{Name: checkCFServiceToken, Status: checkOK, Detail: "no expiry recorded"}
	if expires.IsZero() {
		return check
	}
	check.Detail = "expires " + expires.UTC().Format(time.RFC3339)
	switch remaining := expires.Sub(d.Now); {
	case remaining <= 0:
		check.Status, check.Detail = checkFail, "expired "+expires.UTC().Format(time.RFC3339)+": run sm cloudflare rotate-access-token (needs the API token in the store)"
		if !needed {
			check.Status = checkWarn
		}
	case remaining <= serviceTokenExpiryWarning:
		check.Status = checkWarn
		check.Detail += ": run sm cloudflare rotate-access-token (needs the API token in the store)"
	}
	return check
}

// CloudflareOperationsCheck lists the tunnel operations that did not reach a
// terminal phase, by node: running, interrupted or halted, they hold their
// node. The offline doctor shares it.
func CloudflareOperationsCheck(ctx context.Context, q database.Querier) wire.DoctorCheck {
	ops, err := database.ListActiveTunnelOperations(ctx, q)
	if err != nil {
		return wire.DoctorCheck{Name: checkCFOperations, Status: checkFail, Detail: err.Error()}
	}
	if len(ops) == 0 {
		return wire.DoctorCheck{Name: checkCFOperations, Status: checkOK, Detail: "none in progress"}
	}
	nodes, err := database.ListNodes(ctx, q)
	if err != nil {
		return wire.DoctorCheck{Name: checkCFOperations, Status: checkFail, Detail: err.Error()}
	}
	names := make(map[domain.ID]string, len(nodes))
	for _, n := range nodes {
		names[n.ID] = n.Name
	}
	stuck := make([]string, 0, len(ops))
	for _, op := range ops {
		name := names[op.NodeID]
		if name == "" {
			name = op.NodeID.String()
		}
		phase := string(op.Phase)
		if op.Phase.Halted() {
			phase = fmt.Sprintf("%s at %s", op.Phase, op.HaltedPhase)
		}
		stuck = append(stuck, fmt.Sprintf("%s: %s %s", name, op.Kind, phase))
	}
	return wire.DoctorCheck{
		Name: checkCFOperations, Status: checkWarn,
		Detail: strings.Join(stuck, "; ") + ": run the setup or disable again to resume",
	}
}

// cloudflareChecks is the online report of a server with a cloudflare: block.
func (b *builder) cloudflareChecks(ctx context.Context) []wire.DoctorCheck {
	cf := b.cfg.Cloudflare
	if cf == nil {
		return nil
	}
	return CloudflareDoctor{
		Config: *cf, Now: b.o.Clock.Now(), DB: b.db.Reader(), Secrets: b.kit.store,
		NewProber: func(token audit.Secret) (CloudflareProber, error) {
			return cloudflare.New("", cf.AccountID, token)
		},
	}.Run(ctx)
}

// cloudflaredInstallHint names the usual install route on this operating system.
func cloudflaredInstallHint(goos string) string {
	if goos == "darwin" {
		return "install it with `brew install cloudflared`"
	}
	return "install it from Cloudflare's package repository (https://pkg.cloudflare.com)"
}

// cloudflaredFailure is the detail of a failed cloudflared check: the reason
// and the install route, which a missing binary's reason would only repeat.
func cloudflaredFailure(err error, goos string) string {
	if ssh.CloudflaredMissing(err) {
		return "cloudflared is not installed on the control plane; " + cloudflaredInstallHint(goos) + " to dial tunnelled nodes"
	}
	return reasonOf(err) + "; " + cloudflaredInstallHint(goos) + " to dial tunnelled nodes"
}

// reasonOf is the public message of err: not found, or refused as unsafe.
func reasonOf(err error) string {
	var e *smerr.Error
	if errors.As(err, &e) && e.Message != "" {
		return e.Message
	}
	return err.Error()
}
