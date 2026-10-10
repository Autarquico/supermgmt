package errors_test

import (
	stderrors "errors"
	"fmt"
	"io"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// spec38 transcribes the table of spec §38 independently of the implementation.
var spec38 = map[smerr.Code][]smerr.Reason{
	"INVALID_ARGUMENT":       {"COMPOSE_REJECTED", "MANIFEST_INVALID", "UNKNOWN_ACTION", "AMBIGUOUS_TARGET"},
	"NOT_FOUND":              nil,
	"CONFLICT":               {"PLAN_STALE", "PLAN_EXPIRED", "ALREADY_SUBMITTED", "ALREADY_DECIDED", "RESOURCE_LOCKED", "RESTORE_HOLD", "IDEMPOTENCY_MISMATCH", "INVALID_TRANSITION", "PROJECT_NOT_OWNED"},
	"UNAUTHENTICATED":        {"CREDENTIAL_EXPIRED", "CREDENTIAL_REVOKED", "OIDC_REPLAY", "OIDC_INVALID"},
	"POLICY_DENIED":          {"DENY_RULE", "DEFAULT_DENY", "DESTRUCTIVE_GATE", "SCOPE_DENIED", "APPROVAL_NOT_SUPPORTED", "NOT_PLAN_ACTOR", "SELF_APPROVAL"},
	"APPROVAL_REQUIRED":      nil,
	"CAPABILITY_UNAVAILABLE": {"UNIT_NOT_ELIGIBLE", "HEALTH_CAPABILITY_MISSING"},
	"NODE_UNREACHABLE":       nil,
	"SSH_HOST_KEY_MISMATCH":  nil,
	"PROVIDER_ERROR":         nil,
	"CI_NOT_PASSED":          {"CHECK_FAILED", "CHECK_MISSING", "CI_TIMEOUT"},
	"ARTIFACT_NOT_IMMUTABLE": {"DIGEST_UNBOUND", "TAG_REFERENCE"},
	"DEPLOYMENT_FAILED":      {"PREFLIGHT_FAILED", "STAGING_FAILED", "HEALTH_FAILED", "ROLLBACK_UNAVAILABLE", "INTERRUPTED_BEFORE_DEPLOY", "REJECTED", "RESTORED_UNDISPATCHED"},
	"ROLLBACK_FAILED":        nil,
	"TIMEOUT":                nil,
	"INTERNAL":               nil,
}

func TestCodeForMatchesSpecTable(t *testing.T) {
	want := map[smerr.Reason]smerr.Code{}
	for code, reasons := range spec38 {
		for _, r := range reasons {
			want[r] = code
			if got := smerr.CodeFor(r); got != code {
				t.Errorf("CodeFor(%s) = %s, want %s", r, got, code)
			}
		}
	}
	declared := smerr.Reasons()
	if len(declared) != len(want) {
		t.Errorf("declared %d reasons, spec table has %d", len(declared), len(want))
	}
	for _, r := range declared {
		if _, ok := want[r]; !ok {
			t.Errorf("reason %s is declared but absent from the spec table", r)
		}
	}
}

func TestCodeForUnknownReasonIsInternal(t *testing.T) {
	if got := smerr.CodeFor("NOT_A_REASON"); got != smerr.CodeInternal {
		t.Errorf("CodeFor(unknown) = %s, want INTERNAL", got)
	}
}

func TestConstructors(t *testing.T) {
	cause := io.ErrUnexpectedEOF

	e := smerr.New(smerr.CodeNotFound, "", "no such node")
	if e.Code != smerr.CodeNotFound || e.Reason != "" || e.Err != nil {
		t.Errorf("New = %+v", e)
	}

	w := smerr.Wrap(cause, smerr.CodeTimeout, "", "probe")
	if !stderrors.Is(w, cause) {
		t.Error("Wrap must expose the cause through Unwrap")
	}

	f := smerr.FromReason(smerr.ReasonPlanStale, "plan changed")
	if f.Code != smerr.CodeConflict || f.Reason != smerr.ReasonPlanStale {
		t.Errorf("FromReason = %+v", f)
	}
}

func TestErrorString(t *testing.T) {
	tests := []struct {
		err  *smerr.Error
		want string
	}{
		{smerr.New(smerr.CodeNotFound, "", "no node"), "NOT_FOUND: no node"},
		{smerr.FromReason(smerr.ReasonPlanStale, "changed"), "CONFLICT/PLAN_STALE: changed"},
		{smerr.Wrap(io.EOF, smerr.CodeInternal, "", "read"), "INTERNAL: read: EOF"},
		{smerr.Wrap(io.EOF, smerr.CodeInternal, "", ""), "INTERNAL: EOF"},
		{smerr.New(smerr.CodeTimeout, "", ""), "TIMEOUT"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
}

func TestIsMatchesCodeAndOptionalReason(t *testing.T) {
	err := fmt.Errorf("claim: %w", smerr.FromReason(smerr.ReasonResourceLocked, "port busy"))

	tests := []struct {
		name   string
		target error
		want   bool
	}{
		{"same code, no reason", smerr.New(smerr.CodeConflict, "", ""), true},
		{"same code and reason", smerr.New(smerr.CodeConflict, smerr.ReasonResourceLocked, ""), true},
		{"same code, other reason", smerr.New(smerr.CodeConflict, smerr.ReasonPlanStale, ""), false},
		{"other code", smerr.New(smerr.CodeTimeout, "", ""), false},
		{"non-smerr target", io.EOF, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stderrors.Is(err, tt.target); got != tt.want {
				t.Errorf("errors.Is = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsReasonOnTargetNeverMatchesReasonlessError(t *testing.T) {
	err := smerr.New(smerr.CodeConflict, "", "x")
	if stderrors.Is(err, smerr.New(smerr.CodeConflict, smerr.ReasonPlanStale, "")) {
		t.Error("an error without reason must not match a reason-specific target")
	}
}

func TestAsFindsErrorThroughWrapping(t *testing.T) {
	inner := smerr.FromReason(smerr.ReasonSelfApproval, "no")
	err := fmt.Errorf("a: %w", fmt.Errorf("b: %w", inner))
	var got *smerr.Error
	if !stderrors.As(err, &got) || got != inner {
		t.Fatalf("errors.As = %v, want the inner error", got)
	}
}

func TestIsSeesThroughSmerrWrapOfForeignError(t *testing.T) {
	err := smerr.Wrap(io.EOF, smerr.CodeProviderError, "", "api")
	if !stderrors.Is(err, io.EOF) || !stderrors.Is(err, smerr.New(smerr.CodeProviderError, "", "")) {
		t.Error("both the cause and the smerr code must match")
	}
}

func TestCodeOf(t *testing.T) {
	if got := smerr.CodeOf(fmt.Errorf("x: %w", smerr.New(smerr.CodeTimeout, "", ""))); got != smerr.CodeTimeout {
		t.Errorf("CodeOf(wrapped) = %s", got)
	}
	if got := smerr.CodeOf(io.EOF); got != smerr.CodeInternal {
		t.Errorf("CodeOf(foreign) = %s, want INTERNAL", got)
	}
	if got := smerr.CodeOf(nil); got != smerr.CodeInternal {
		t.Errorf("CodeOf(nil) = %s, want INTERNAL", got)
	}
}

func TestErrorMessageDoesNotLeakDetails(t *testing.T) {
	e := smerr.New(smerr.CodeInternal, "", "boom")
	e.Details = map[string]any{"secret": "hunter2"}
	if strings.Contains(e.Error(), "hunter2") {
		t.Error("Error() must not render Details")
	}
}
