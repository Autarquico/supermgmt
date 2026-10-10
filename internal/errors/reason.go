package errors

import (
	"slices"
	"strings"
)

// Reason is the informative, closed-enum detail attached to a Code.
type Reason string

const (
	ReasonComposeRejected         Reason = "COMPOSE_REJECTED"
	ReasonManifestInvalid         Reason = "MANIFEST_INVALID"
	ReasonUnknownAction           Reason = "UNKNOWN_ACTION"
	ReasonAmbiguousTarget         Reason = "AMBIGUOUS_TARGET"
	ReasonPlanStale               Reason = "PLAN_STALE"
	ReasonPlanExpired             Reason = "PLAN_EXPIRED"
	ReasonAlreadySubmitted        Reason = "ALREADY_SUBMITTED"
	ReasonAlreadyDecided          Reason = "ALREADY_DECIDED"
	ReasonResourceLocked          Reason = "RESOURCE_LOCKED"
	ReasonRestoreHold             Reason = "RESTORE_HOLD"
	ReasonIdempotencyMismatch     Reason = "IDEMPOTENCY_MISMATCH"
	ReasonInvalidTransition       Reason = "INVALID_TRANSITION"
	ReasonProjectNotOwned         Reason = "PROJECT_NOT_OWNED"
	ReasonCredentialExpired       Reason = "CREDENTIAL_EXPIRED"
	ReasonCredentialRevoked       Reason = "CREDENTIAL_REVOKED"
	ReasonOIDCReplay              Reason = "OIDC_REPLAY"
	ReasonOIDCInvalid             Reason = "OIDC_INVALID"
	ReasonDenyRule                Reason = "DENY_RULE"
	ReasonDefaultDeny             Reason = "DEFAULT_DENY"
	ReasonDestructiveGate         Reason = "DESTRUCTIVE_GATE"
	ReasonScopeDenied             Reason = "SCOPE_DENIED"
	ReasonApprovalNotSupported    Reason = "APPROVAL_NOT_SUPPORTED"
	ReasonNotPlanActor            Reason = "NOT_PLAN_ACTOR"
	ReasonSelfApproval            Reason = "SELF_APPROVAL"
	ReasonUnitNotEligible         Reason = "UNIT_NOT_ELIGIBLE"
	ReasonHealthCapabilityMissing Reason = "HEALTH_CAPABILITY_MISSING"
	ReasonCheckFailed             Reason = "CHECK_FAILED"
	ReasonCheckMissing            Reason = "CHECK_MISSING"
	ReasonCITimeout               Reason = "CI_TIMEOUT"
	ReasonDigestUnbound           Reason = "DIGEST_UNBOUND"
	ReasonTagReference            Reason = "TAG_REFERENCE"
	ReasonPreflightFailed         Reason = "PREFLIGHT_FAILED"
	ReasonStagingFailed           Reason = "STAGING_FAILED"
	ReasonHealthFailed            Reason = "HEALTH_FAILED"
	ReasonRollbackUnavailable     Reason = "ROLLBACK_UNAVAILABLE"
	ReasonInterruptedBeforeDeploy Reason = "INTERRUPTED_BEFORE_DEPLOY"
	ReasonRejected                Reason = "REJECTED"
	ReasonRestoredUndispatched    Reason = "RESTORED_UNDISPATCHED"
)

var codeByReason = map[Reason]Code{
	ReasonComposeRejected:         CodeInvalidArgument,
	ReasonManifestInvalid:         CodeInvalidArgument,
	ReasonUnknownAction:           CodeInvalidArgument,
	ReasonAmbiguousTarget:         CodeInvalidArgument,
	ReasonPlanStale:               CodeConflict,
	ReasonPlanExpired:             CodeConflict,
	ReasonAlreadySubmitted:        CodeConflict,
	ReasonAlreadyDecided:          CodeConflict,
	ReasonResourceLocked:          CodeConflict,
	ReasonRestoreHold:             CodeConflict,
	ReasonIdempotencyMismatch:     CodeConflict,
	ReasonInvalidTransition:       CodeConflict,
	ReasonProjectNotOwned:         CodeConflict,
	ReasonCredentialExpired:       CodeUnauthenticated,
	ReasonCredentialRevoked:       CodeUnauthenticated,
	ReasonOIDCReplay:              CodeUnauthenticated,
	ReasonOIDCInvalid:             CodeUnauthenticated,
	ReasonDenyRule:                CodePolicyDenied,
	ReasonDefaultDeny:             CodePolicyDenied,
	ReasonDestructiveGate:         CodePolicyDenied,
	ReasonScopeDenied:             CodePolicyDenied,
	ReasonApprovalNotSupported:    CodePolicyDenied,
	ReasonNotPlanActor:            CodePolicyDenied,
	ReasonSelfApproval:            CodePolicyDenied,
	ReasonUnitNotEligible:         CodeCapabilityUnavailable,
	ReasonHealthCapabilityMissing: CodeCapabilityUnavailable,
	ReasonCheckFailed:             CodeCINotPassed,
	ReasonCheckMissing:            CodeCINotPassed,
	ReasonCITimeout:               CodeCINotPassed,
	ReasonDigestUnbound:           CodeArtifactNotImmutable,
	ReasonTagReference:            CodeArtifactNotImmutable,
	ReasonPreflightFailed:         CodeDeploymentFailed,
	ReasonStagingFailed:           CodeDeploymentFailed,
	ReasonHealthFailed:            CodeDeploymentFailed,
	ReasonRollbackUnavailable:     CodeDeploymentFailed,
	ReasonInterruptedBeforeDeploy: CodeDeploymentFailed,
	ReasonRejected:                CodeDeploymentFailed,
	ReasonRestoredUndispatched:    CodeDeploymentFailed,
}

// CodeFor returns the top-level code a reason belongs to (spec §38). A reason
// missing from the table maps to CodeInternal; the exhaustive test makes that
// unreachable for declared reasons.
func CodeFor(r Reason) Code {
	if c, ok := codeByReason[r]; ok {
		return c
	}
	return CodeInternal
}

// Reasons lists every declared reason in alphabetical order.
func Reasons() []Reason {
	all := make([]Reason, 0, len(codeByReason))
	for r := range codeByReason {
		all = append(all, r)
	}
	slices.SortFunc(all, func(a, b Reason) int { return strings.Compare(string(a), string(b)) })
	return all
}
