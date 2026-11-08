package errors

import (
	"slices"
	"strings"
)

// Reason is the informative, closed-enum detail attached to a Code.
type Reason string

const (
	ReasonUnknownAction          Reason = "UNKNOWN_ACTION"
	ReasonAmbiguousTarget        Reason = "AMBIGUOUS_TARGET"
	ReasonPlanStale              Reason = "PLAN_STALE"
	ReasonPlanExpired            Reason = "PLAN_EXPIRED"
	ReasonAlreadySubmitted       Reason = "ALREADY_SUBMITTED"
	ReasonAlreadyDecided         Reason = "ALREADY_DECIDED"
	ReasonResourceLocked         Reason = "RESOURCE_LOCKED"
	ReasonRestoreHold            Reason = "RESTORE_HOLD"
	ReasonIdempotencyMismatch    Reason = "IDEMPOTENCY_MISMATCH"
	ReasonInvalidTransition      Reason = "INVALID_TRANSITION"
	ReasonCredentialExpired      Reason = "CREDENTIAL_EXPIRED"
	ReasonCredentialRevoked      Reason = "CREDENTIAL_REVOKED"
	ReasonOIDCReplay             Reason = "OIDC_REPLAY"
	ReasonOIDCInvalid            Reason = "OIDC_INVALID"
	ReasonDenyRule               Reason = "DENY_RULE"
	ReasonDefaultDeny            Reason = "DEFAULT_DENY"
	ReasonDestructiveGate        Reason = "DESTRUCTIVE_GATE"
	ReasonScopeDenied            Reason = "SCOPE_DENIED"
	ReasonApprovalNotSupported   Reason = "APPROVAL_NOT_SUPPORTED"
	ReasonNotPlanActor           Reason = "NOT_PLAN_ACTOR"
	ReasonSelfApproval           Reason = "SELF_APPROVAL"
	ReasonUnitNotEligible        Reason = "UNIT_NOT_ELIGIBLE"
	ReasonRejected               Reason = "REJECTED"
	ReasonRestoredUndispatched   Reason = "RESTORED_UNDISPATCHED"
	ReasonMCPWritesDisabled      Reason = "MCP_WRITES_DISABLED"
	ReasonMCPActionForbidden     Reason = "MCP_ACTION_FORBIDDEN"
	ReasonMCPClientUnregistered  Reason = "MCP_CLIENT_UNREGISTERED"
	ReasonIssuanceWindowExpired  Reason = "ISSUANCE_WINDOW_EXPIRED"
	ReasonOAuthTokenInvalid      Reason = "OAUTH_TOKEN_INVALID"
	ReasonMCPDisabled            Reason = "MCP_DISABLED"
	ReasonTunnelDNSNegativeCache Reason = "TUNNEL_DNS_NEGATIVE_CACHE"
)

var codeByReason = map[Reason]Code{
	ReasonUnknownAction:          CodeInvalidArgument,
	ReasonAmbiguousTarget:        CodeInvalidArgument,
	ReasonPlanStale:              CodeConflict,
	ReasonPlanExpired:            CodeConflict,
	ReasonAlreadySubmitted:       CodeConflict,
	ReasonAlreadyDecided:         CodeConflict,
	ReasonResourceLocked:         CodeConflict,
	ReasonRestoreHold:            CodeConflict,
	ReasonIdempotencyMismatch:    CodeConflict,
	ReasonInvalidTransition:      CodeConflict,
	ReasonCredentialExpired:      CodeUnauthenticated,
	ReasonCredentialRevoked:      CodeUnauthenticated,
	ReasonOIDCReplay:             CodeUnauthenticated,
	ReasonOIDCInvalid:            CodeUnauthenticated,
	ReasonDenyRule:               CodePolicyDenied,
	ReasonDefaultDeny:            CodePolicyDenied,
	ReasonDestructiveGate:        CodePolicyDenied,
	ReasonScopeDenied:            CodePolicyDenied,
	ReasonApprovalNotSupported:   CodePolicyDenied,
	ReasonNotPlanActor:           CodePolicyDenied,
	ReasonSelfApproval:           CodePolicyDenied,
	ReasonUnitNotEligible:        CodeCapabilityUnavailable,
	ReasonRejected:               CodeDeploymentFailed,
	ReasonRestoredUndispatched:   CodeDeploymentFailed,
	ReasonMCPWritesDisabled:      CodePolicyDenied,
	ReasonMCPActionForbidden:     CodePolicyDenied,
	ReasonMCPClientUnregistered:  CodePolicyDenied,
	ReasonIssuanceWindowExpired:  CodeConflict,
	ReasonOAuthTokenInvalid:      CodeUnauthenticated,
	ReasonMCPDisabled:            CodeUnauthenticated,
	ReasonTunnelDNSNegativeCache: CodeNodeUnreachable,
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
