// Package errors defines the SuperMgmt error model (spec §38): a small set of
// stable top-level codes plus a closed set of reasons. Other packages import
// it as smerr.
package errors

// Code is the stable top-level error code clients branch on.
type Code string

const (
	CodeInvalidArgument       Code = "INVALID_ARGUMENT"
	CodeNotFound              Code = "NOT_FOUND"
	CodeConflict              Code = "CONFLICT"
	CodeUnauthenticated       Code = "UNAUTHENTICATED"
	CodePolicyDenied          Code = "POLICY_DENIED"
	CodeApprovalRequired      Code = "APPROVAL_REQUIRED"
	CodeCapabilityUnavailable Code = "CAPABILITY_UNAVAILABLE"
	CodeNodeUnreachable       Code = "NODE_UNREACHABLE"
	CodeSSHHostKeyMismatch    Code = "SSH_HOST_KEY_MISMATCH"
	CodeProviderError         Code = "PROVIDER_ERROR"
	CodeCINotPassed           Code = "CI_NOT_PASSED"
	CodeArtifactNotImmutable  Code = "ARTIFACT_NOT_IMMUTABLE"
	CodeDeploymentFailed      Code = "DEPLOYMENT_FAILED"
	CodeRollbackFailed        Code = "ROLLBACK_FAILED"
	CodeTimeout               Code = "TIMEOUT"
	CodeInternal              Code = "INTERNAL"
)
