// Package deployments holds the deployment state machine of spec §20.1, the
// steps a deployment runs in each recovery mode and the rule that decides
// whether a rollback is available (ADR-0029). It is pure: no storage, no
// transport, no clock.
//
// Frozen in M4 W0. T7a implements, in this package:
//
//	func Transition(from, to State) error              // INVALID_TRANSITION outside the §20.1 table
//	func (s State) Terminal() bool
//	func (s State) Provisional() bool                  // created, waiting_ci
//	func (s State) MutationStarted() bool              // deploying and later
//	func CoarseJobState(s State) domain.JobState
//	func RollbackAvailable(in RollbackInputs) (ok bool, cause string)
//	func Steps(p plan.Plan, m RecoveryMode) []Step
package deployments

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// State is a deployment's fine state (spec §20.1, deployments.state). The job
// that executes a deployment carries the coarse domain.JobState; the two are
// mirrored in the same transaction (ADR-0029).
type State string

const (
	StateCreated          State = "created"
	StateWaitingCI        State = "waiting_ci"
	StateAwaitingApproval State = "awaiting_approval"
	StateQueued           State = "queued"
	StatePreparing        State = "preparing"
	StateStaging          State = "staging"
	StateDeploying        State = "deploying"
	StateVerifying        State = "verifying"
	StateRollingBack      State = "rolling_back"
	StateInterrupted      State = "interrupted"
	StateSucceeded        State = "succeeded"
	StateFailed           State = "failed"
	StateRolledBack       State = "rolled_back"
	StateRollbackFailed   State = "rollback_failed"
	StateCancelled        State = "cancelled"
)

// AllStates lists the fifteen states in §20.1 order.
func AllStates() []State {
	return []State{
		StateCreated, StateWaitingCI, StateAwaitingApproval, StateQueued,
		StatePreparing, StateStaging, StateDeploying, StateVerifying, StateRollingBack, StateInterrupted,
		StateSucceeded, StateFailed, StateRolledBack, StateRollbackFailed, StateCancelled,
	}
}

// Kinds of deployment (spec §20.0, deployments.kind).
const (
	KindDeploy   = "deploy"
	KindRollback = "rollback"
)

// Rollback modes (spec §19, §19.1).
const (
	RollbackAutomatic = "automatic"
	RollbackManual    = "manual"
)

// Causes recorded in details.cause next to ROLLBACK_UNAVAILABLE, STAGING_FAILED
// or PREFLIGHT_FAILED (ADR-0007, ADR-0008, ADR-0029).
const (
	CauseManualMode         = "MANUAL_MODE"         // effective rollback mode is manual
	CauseStateful           = "STATEFUL"            // the target is stateful
	CauseEnvironmentForbids = "ENVIRONMENT_FORBIDS" // allow_automatic_rollback is false
	CauseNoKnownGood        = "NO_KNOWN_GOOD"       // first deployment of the target
	CauseRollbackKind       = "ROLLBACK_KIND"       // a kind: rollback never auto-rolls back
	CauseSecretVersionGone  = "SECRET_VERSION_GONE" // a bound secret version no longer exists
	CauseSnapshotGone       = "SNAPSHOT_GONE"       // an execution snapshot row is missing
	CauseSnapshotMismatch   = "SNAPSHOT_MISMATCH"   // a snapshot's content does not hash to its key
	CauseImageSizeUnknown   = "IMAGE_SIZE_UNKNOWN"  // preflight cannot size an image (Q14)
	CauseComposeUnsupported = "COMPOSE_UNSUPPORTED" // node Compose CLI outside the matrix
	CauseEnvHashMismatch    = "ENV_HASH_MISMATCH"   // resolved environment differs on the node
	CauseModelMismatch      = "MODEL_MISMATCH"      // CLI effective model differs from the frozen one
	CauseBackupFailed       = "BACKUP_FAILED"       // pre-deploy backup did not prove an artifact
)

// RollbackInputs are the facts §20.1 "Rollback available" decides on. Mode is
// the control-plane rollback mode, ManifestMode the manifest's ("" when the
// manifest sets none); the effective mode follows §19 precedence.
type RollbackInputs struct {
	Mode         string
	ManifestMode string
	Stateful     bool
	EnvAllows    bool
	HasKnownGood bool
	Kind         string
}

// Step names in App. C order. Forward steps execute a deploy plan; restore
// steps redeploy the plan's frozen rollback target (automatic rollback, a
// kind: rollback deployment, or safety recovery).
const (
	StepPreflight       = "preflight"
	StepSnapshot        = "snapshot"
	StepPreDeployBackup = "pre-deploy-backup"
	StepPull            = "pull"
	StepMaterialize     = "materialize"
	StepVerifyOnNode    = "verify-on-node"
	StepDeploy          = "deploy"
	StepHealthCheck     = "health-check"

	StepRestorePull        = "restore-pull"
	StepRestoreMaterialize = "restore-materialize"
	StepRestoreVerify      = "restore-verify-on-node"
	StepRestoreDeploy      = "restore-deploy"
	StepRestoreHealthCheck = "restore-health-check"
)

// Step is one checkpointed unit of a deployment job. Deadline is the remote
// command's deadline (spec §20.4); zero means the plan supplies it (backup
// timeout, health attempts × interval + timeout).
type Step struct {
	Name     string
	Deadline time.Duration
	Mutating bool
	Forward  bool // false: a restore step
}

// RecoveryMode is the durable recovery record's mode (deployments.recovery_mode).
type RecoveryMode string

const (
	RecoveryForward        RecoveryMode = "forward"
	RecoverySafetyRecovery RecoveryMode = "safety_recovery"
)

// Recovery is the durable record a requeueing reconcile verdict writes
// (ADR-0029). Target is the plan's frozen rollback_target.deployment_id; it is
// set only in safety recovery.
type Recovery struct {
	Mode       RecoveryMode
	ResumeStep string
	Reason     string
	Target     *domain.ID
}
