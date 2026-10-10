package domain_test

import (
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

type enum[T ~string] struct {
	name  string
	all   func() []T
	parse func(string) (T, error)
	valid func(T) bool
	wire  []string
}

func (e enum[T]) check(t *testing.T) {
	t.Helper()
	t.Run(e.name, func(t *testing.T) {
		got := make([]string, 0, len(e.all()))
		for _, v := range e.all() {
			got = append(got, string(v))
		}
		if !slices.Equal(got, e.wire) {
			t.Fatalf("All = %v, want %v", got, e.wire)
		}
		for _, w := range e.wire {
			v, err := e.parse(w)
			if err != nil || string(v) != w {
				t.Errorf("parse(%q) = %q, %v", w, v, err)
			}
			if !e.valid(v) {
				t.Errorf("%q should be valid", w)
			}
		}
		for _, bad := range []string{"", "bogus", " " + e.wire[0], e.wire[0] + " ", upper(e.wire[0])} {
			v, err := e.parse(bad)
			if err == nil {
				t.Errorf("parse(%q) accepted", bad)
			}
			if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Errorf("parse(%q) code = %s, want INVALID_ARGUMENT", bad, smerr.CodeOf(err))
			}
			if v != "" || e.valid(v) {
				t.Errorf("parse(%q) returned usable value %q", bad, v)
			}
		}
	})
}

func upper(s string) string {
	b := []byte(s)
	b[0] = b[0] - 'a' + 'A'
	return string(b)
}

func TestEnumsRoundTripAndRejectInvalid(t *testing.T) {
	enum[domain.ActorType]{"ActorType", domain.AllActorTypes, domain.ParseActorType,
		domain.ActorType.Valid, []string{"human", "automation", "mcp", "system"}}.check(t)
	enum[domain.CredentialKind]{"CredentialKind", domain.AllCredentialKinds, domain.ParseCredentialKind,
		domain.CredentialKind.Valid,
		[]string{"local_socket", "session", "api_token", "mcp_token", "oauth_access_token", "github_oidc"}}.check(t)
	enum[domain.RiskClass]{"RiskClass", domain.AllRiskClasses, domain.ParseRiskClass,
		domain.RiskClass.Valid, []string{"read", "operational", "high", "destructive", "governance"}}.check(t)
	enum[domain.ResourceType]{"ResourceType", domain.AllResourceTypes, domain.ParseResourceType,
		domain.ResourceType.Valid,
		[]string{"node", "service", "app", "app_target", "deployment", "environment", "provider",
			"job", "plan", "event", "instance", "identity", "secret"}}.check(t)
	enum[domain.ManagementState]{"ManagementState", domain.AllManagementStates, domain.ParseManagementState,
		domain.ManagementState.Valid, []string{"discovered", "managed", "retired"}}.check(t)
	enum[domain.Reachability]{"Reachability", domain.AllReachabilities, domain.ParseReachability,
		domain.Reachability.Valid, []string{"reachable", "unreachable", "unknown"}}.check(t)
	enum[domain.EnvironmentRiskLevel]{"EnvironmentRiskLevel", domain.AllEnvironmentRiskLevels,
		domain.ParseEnvironmentRiskLevel, domain.EnvironmentRiskLevel.Valid,
		[]string{"development", "staging", "production"}}.check(t)
	enum[domain.ProviderOrigin]{"ProviderOrigin", domain.AllProviderOrigins, domain.ParseProviderOrigin,
		domain.ProviderOrigin.Valid, []string{"static", "api"}}.check(t)
	enum[domain.JobState]{"JobState", domain.AllJobStates, domain.ParseJobState, domain.JobState.Valid,
		[]string{"awaiting_approval", "queued", "running", "interrupted", "succeeded", "failed", "cancelled"}}.check(t)
	enum[domain.RetryClass]{"RetryClass", domain.AllRetryClasses, domain.ParseRetryClass,
		domain.RetryClass.Valid, []string{"idempotent", "resumable", "non_retryable"}}.check(t)
	enum[domain.LockMode]{"LockMode", domain.AllLockModes, domain.ParseLockMode,
		domain.LockMode.Valid, []string{"exclusive", "shared"}}.check(t)
	enum[domain.IntentState]{"IntentState", domain.AllIntentStates, domain.ParseIntentState,
		domain.IntentState.Valid, []string{"recorded", "completed"}}.check(t)
	enum[domain.ApprovalDecision]{"ApprovalDecision", domain.AllApprovalDecisions, domain.ParseApprovalDecision,
		domain.ApprovalDecision.Valid, []string{"approve", "reject"}}.check(t)
	enum[domain.Severity]{"Severity", domain.AllSeverities, domain.ParseSeverity,
		domain.Severity.Valid, []string{"info", "warning", "error"}}.check(t)
	enum[domain.Result]{"Result", domain.AllResults, domain.ParseResult,
		domain.Result.Valid, []string{"succeeded", "failed", "denied", "pending"}}.check(t)
}

func TestRiskClassRank(t *testing.T) {
	ordered := []domain.RiskClass{domain.RiskRead, domain.RiskOperational, domain.RiskHigh, domain.RiskDestructive}
	for i, a := range ordered {
		if a.Rank() != i {
			t.Errorf("%s.Rank() = %d, want %d", a, a.Rank(), i)
		}
		for j, b := range ordered {
			if got, want := a.AtLeast(b), i >= j; got != want {
				t.Errorf("%s.AtLeast(%s) = %v, want %v", a, b, got, want)
			}
		}
	}
}

func TestRiskClassGovernanceIsOutsideTheScale(t *testing.T) {
	for _, other := range domain.AllRiskClasses() {
		if domain.RiskGovernance.AtLeast(other) {
			t.Errorf("governance.AtLeast(%s) = true", other)
		}
		if other.AtLeast(domain.RiskGovernance) {
			t.Errorf("%s.AtLeast(governance) = true", other)
		}
	}
	if domain.RiskClass("bogus").AtLeast(domain.RiskRead) {
		t.Error("an invalid class must not rank")
	}
}

func TestJobStateTerminal(t *testing.T) {
	terminal := map[domain.JobState]bool{
		domain.JobSucceeded: true, domain.JobFailed: true, domain.JobCancelled: true,
	}
	for _, s := range domain.AllJobStates() {
		if s.Terminal() != terminal[s] {
			t.Errorf("%s.Terminal() = %v, want %v", s, s.Terminal(), terminal[s])
		}
	}
}
