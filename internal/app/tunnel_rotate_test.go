package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/transport/ssh"
)

func (ts *tunnelSetting) instanceRef() domain.ResourceRef {
	instance, err := database.GetInstance(context.Background(), ts.db.Reader())
	mustf(ts.t, err, "GetInstance")
	return domain.ResourceRef{Type: domain.ResourceInstance, ID: instance.ID}
}

// planRotation submits and approves the service-token rotation and makes
// attempt run it.
func (ts *tunnelSetting) planRotation() jobs.Job {
	ts.queued = ts.actionPlan(policy.ActionCloudflareRotate, ts.instanceRef())
	ts.current = ts.rotate
	return ts.queued
}

// admissionProbe models what a dial needs: the credential the dialler would
// read now is admitted by the owned Service Auth policy. It returns the
// reason it is not, empty when it is (or when nothing is set up yet).
func (ts *tunnelSetting) admissionProbe() string {
	stored, err := ts.secrets.Get(context.Background(), secrets.Ref{Name: "cloudflare/access-service-token"})
	if err != nil {
		return ""
	}
	held, err := ssh.ParseAccessToken(stored.Reveal())
	if err != nil {
		return "the stored credential is unreadable"
	}
	snap := ts.cf.Snapshot()
	for _, p := range snap.Policies {
		if p.Decision != "non_identity" {
			continue
		}
		if len(p.ServiceTokenIDs) == 0 {
			return "the Service Auth policy admits no token"
		}
		for _, id := range p.ServiceTokenIDs {
			if slices.ContainsFunc(snap.ServiceTokens, func(t cffake.ServiceToken) bool { return t.ID == id && t.ClientID == held.ClientID }) {
				return ""
			}
		}
		return "the dialler's credential " + held.ClientID + " is admitted by no token of the Service Auth policy"
	}
	return ""
}

// watchAdmission checks the probe after every Cloudflare mutation and every
// stored secret from now on; the returned function lists what it caught.
func (ts *tunnelSetting) watchAdmission() func() []string {
	var caught []string
	check := func() {
		if why := ts.admissionProbe(); why != "" {
			caught = append(caught, why)
		}
	}
	ts.chaos.afterMutation = check
	ts.secrets.afterPut = check
	return func() []string { return caught }
}

func (ts *tunnelSetting) state() database.CloudflareState {
	ts.t.Helper()
	state, err := database.GetCloudflareState(context.Background(), ts.db.Reader())
	mustf(ts.t, err, "GetCloudflareState")
	return state
}

// wantRotated fails unless exactly one service token remains, it is the one
// the instance state and the runtime secret name, and the policy admits only it.
func (ts *tunnelSetting) wantRotated(old cffake.ServiceToken) {
	ts.t.Helper()
	state, snap := ts.state(), ts.cf.Snapshot()
	if len(snap.ServiceTokens) != 1 || snap.ServiceTokens[0].ID != state.Token.ID || state.Token.ID == old.ID {
		ts.t.Fatalf("tokens %+v with the state on %s (old %s), want only the new one", snap.ServiceTokens, state.Token.ID, old.ID)
	}
	if state.Rotation != database.RotationIdle || state.Pending != nil {
		ts.t.Errorf("rotation state = %s pending %v, want idle", state.Rotation, state.Pending)
	}
	for _, p := range snap.Policies {
		if p.Decision == "non_identity" && !slices.Equal(p.ServiceTokenIDs, []string{state.Token.ID}) {
			ts.t.Errorf("the Service Auth policy admits %v, want only %s", p.ServiceTokenIDs, state.Token.ID)
		}
	}
	token, err := AccessTokens(ts.secrets, testAccessToken).AccessToken(context.Background())
	mustf(ts.t, err, "the dialler's token source")
	if token.ClientID != snap.ServiceTokens[0].ClientID || token.ClientID == old.ClientID {
		ts.t.Errorf("the dialler presents %s, want the new token %s", token.ClientID, snap.ServiceTokens[0].ClientID)
	}
	if routable := ts.cf.EverRoutableWithoutAccess(); len(routable) != 0 {
		ts.t.Errorf("routable without Access at some point: %v", routable)
	}
}

func TestRotationOverlapsTheTokensAndDeletesTheOldOneLast(t *testing.T) {
	ts := newEnabledTunnel(t)
	old, base, versions := ts.cf.ServiceTokens()[0], len(ts.cf.Mutations()), ts.secrets.versions("cloudflare/access-service-token")
	caught := ts.watchAdmission()
	ts.planRotation()

	mustf(t, ts.attempt(), "rotation")

	ts.wantRotated(old)
	want := []cffake.Op{cffake.OpServiceTokenNew, cffake.OpPolicyUpdate, cffake.OpPolicyUpdate, cffake.OpServiceTokenDel}
	if got := ts.committedOps(base); !slices.Equal(got, want) {
		t.Errorf("Cloudflare mutations = %v, want %v: create, admit both, keep only the new one, delete the old one last", got, want)
	}
	if got := ts.secrets.versions("cloudflare/access-service-token"); got != versions+1 {
		t.Errorf("runtime secret versions %d -> %d, want one new version", versions, got)
	}
	if got := ts.state().Token.Name; got != rotatedTokenName(ts.instanceRef().ID.String(), old.ID) {
		t.Errorf("rotated token name = %q", got)
	}
	if problems := caught(); len(problems) != 0 {
		t.Errorf("a dial would have failed: %v", problems)
	}
	for _, action := range []string{
		"cloudflare.access_token.rotation_started", "cloudflare.access_token.admitted", "cloudflare.access_token.switched",
		"cloudflare.access_token.retired", "cloudflare.access_token.rotated", "cloudflare.service_token.created",
	} {
		if len(ts.events(action)) == 0 && action != "cloudflare.service_token.created" {
			t.Errorf("no %s event", action)
		}
	}
	for _, event := range ts.events() {
		text := string(mustJSON(t, event.Data))
		for _, secret := range []string{old.ClientSecret, ts.cf.ServiceTokens()[0].ClientSecret} {
			if strings.Contains(text, secret) {
				t.Errorf("event %s carries a service token secret", event.Action)
			}
		}
	}
}

func TestRotationUnderEveryFaultNeverLeavesTheDialerWithoutAnAdmittedToken(t *testing.T) {
	clean := newEnabledTunnel(t)
	base := len(clean.cf.Mutations())
	clean.planRotation()
	mustf(t, clean.attempt(), "clean rotation")
	total := len(clean.cf.Mutations()) - base
	if total != 4 {
		t.Fatalf("a clean rotation made %d mutations, want 4", total)
	}

	for _, mode := range []string{"lost response", "refused before", "crash", "lease loss"} {
		for k := 1; k <= total; k++ {
			t.Run(fmt.Sprintf("%s at mutation %d", mode, k), func(t *testing.T) {
				ts := newEnabledTunnel(t)
				old := ts.cf.ServiceTokens()[0]
				caught := ts.watchAdmission()
				ts.planRotation()
				ts.arm(mode, k)

				failures := ts.converge(5)

				if len(failures) == 0 && (mode == "crash" || mode == "lease loss") {
					t.Fatal("the fault changed nothing")
				}
				ts.wantRotated(old)
				if problems := caught(); len(problems) != 0 {
					t.Errorf("a dial would have failed: %v", problems)
				}
				if mode == "lease loss" && !errors.Is(failures[0], jobs.ErrLeaseLost) {
					t.Errorf("first failure = %v, want the lease loss", failures[0])
				}
			})
		}
	}
	for k := 1; k <= 2; k++ {
		t.Run(fmt.Sprintf("crash right after secret %d", k), func(t *testing.T) {
			ts := newEnabledTunnel(t)
			old := ts.cf.ServiceTokens()[0]
			caught := ts.watchAdmission()
			ts.planRotation()
			ts.secrets.crashAfterPut = ts.secrets.puts + k

			failures := ts.converge(5)

			if len(failures) == 0 {
				t.Fatal("the crash changed nothing")
			}
			ts.wantRotated(old)
			if problems := caught(); len(problems) != 0 {
				t.Errorf("a dial would have failed: %v", problems)
			}
		})
	}
}

func TestASecondRotationUsesAnotherNameAndLeavesOneToken(t *testing.T) {
	ts := newEnabledTunnel(t)
	ts.planRotation()
	mustf(t, ts.attempt(), "first rotation")
	first := ts.cf.ServiceTokens()[0]
	caught := ts.watchAdmission()
	ts.planRotation()

	mustf(t, ts.attempt(), "second rotation")

	ts.wantRotated(first)
	if names := ts.cf.ServiceTokens(); names[0].Name == first.Name {
		t.Errorf("both rotations produced the name %q", first.Name)
	}
	if problems := caught(); len(problems) != 0 {
		t.Errorf("a dial would have failed: %v", problems)
	}
}

func TestAnEnableAfterARotationKeepsTheRotatedToken(t *testing.T) {
	ts := newEnabledTunnel(t)
	ts.planRotation()
	mustf(t, ts.attempt(), "rotation")
	token, base := ts.cf.ServiceTokens()[0], len(ts.cf.Mutations())
	ts.current = nil
	ts.plan()

	mustf(t, ts.attempt(), "rerun of the tunnel setup")

	if got := len(ts.cf.Mutations()) - base; got != 0 {
		t.Errorf("the rerun made %d Cloudflare mutations, want none: the rotated token is the instance's token", got)
	}
	if got := ts.cf.ServiceTokens(); len(got) != 1 || got[0].ID != token.ID {
		t.Errorf("tokens = %+v, want the rotated one kept", got)
	}
}

func TestRotationNeedsAnExistingServiceToken(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.planRotation()

	err := ts.attempt()

	wantError(t, err, smerr.CodeCapabilityUnavailable, "")
	if got := len(ts.cf.Mutations()); got != 0 {
		t.Errorf("%d Cloudflare mutations, want none", got)
	}
}

func TestARotationPlanNeedsAConnectionTakesTheInstanceLockAndIsHighRisk(t *testing.T) {
	plain := newSetting(t) // no cloudflare: block
	instance, err := database.GetInstance(context.Background(), plain.db.Reader())
	mustf(t, err, "GetInstance")
	_, err = plain.plans.Create(context.Background(), plain.caller(plain.admin), PlanRequest{
		Action: policy.ActionCloudflareRotate, Target: domain.ResourceRef{Type: domain.ResourceInstance, ID: instance.ID},
	})
	wantError(t, err, smerr.CodeInvalidArgument, "")

	ts := newEnabledTunnel(t)
	created, err := ts.plans.Create(context.Background(), ts.caller(ts.admin), PlanRequest{Action: policy.ActionCloudflareRotate, Target: ts.instanceRef()})
	mustf(t, err, "Create")
	if created.Plan.Risk != domain.RiskHigh || created.Policy.Decision != "allow" {
		t.Errorf("risk %s policy %+v, want a high-risk action an admin may plan", created.Plan.Risk, created.Policy)
	}
	ts.planRotation()
	if _, ok := ts.claim(); !ok {
		t.Fatal("no job to claim")
	}
	var instanceLock bool
	for key, mode := range ts.locks() {
		instanceLock = instanceLock || strings.Contains(key, "cloudflare") && mode == domain.LockExclusive
	}
	if !instanceLock {
		t.Errorf("locks = %v, want the exclusive cloudflare instance lock", ts.locks())
	}
}
