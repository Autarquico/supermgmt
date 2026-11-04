package app

import (
	"slices"

	"github.com/autarquico/supermgmt/internal/database"
)

// The phase contract of a move (ADR-0041, ADR-0042). movePhases is the one place that says what each phase of the
// app_moves row means: whether the commit has happened (so the move can only go forward), whether it belongs to the
// forward path or to compensation, and, on the forward path, which phases only a routed or only a stateful move
// walks. pastCommit, the claim rebuild, resume validation, the entry of compensation and the plan's step list all
// read it.

// phaseClass says what the phase allows.
type phaseClass int

const (
	// classPreCommit phases leave the target on A: a failure compensates.
	classPreCommit phaseClass = iota + 1
	// classPostCommit phases follow the commit: the target runs on B, nothing is undone and the only way is forward.
	classPostCommit
	// classCompensation phases undo a pre-commit move; rolled_back is the end of them.
	classCompensation
	// classHalted is failed or conflict: the class of the phase the move held (halted_phase) applies.
	classHalted
)

type movePhase struct {
	phase    database.AppMovePhase
	class    phaseClass
	routed   bool // only a routed move walks it
	stateful bool // only a stateful move walks it
}

// movePhases lists every phase. The forward path comes first in the order a move walks it, then compensation in the
// order it undoes, then the halted phases.
var movePhases = []movePhase{
	{phase: database.AppMovePreflight, class: classPreCommit},
	{phase: database.AppMoveStaged, class: classPreCommit},
	{phase: database.AppMoveSourceStop, class: classPreCommit, stateful: true},
	{phase: database.AppMoveDataCopied, class: classPreCommit, stateful: true},
	{phase: database.AppMoveStarted, class: classPreCommit},
	{phase: database.AppMoveVerified, class: classPreCommit},
	{phase: database.AppMoveRoutesDestIncluded, class: classPreCommit, routed: true},
	{phase: database.AppMoveRoutesSwitched, class: classPreCommit, routed: true},
	{phase: database.AppMoveCommitted, class: classPostCommit},
	{phase: database.AppMoveRoutesSourceCleaned, class: classPostCommit, routed: true},
	{phase: database.AppMoveSourceParked, class: classPostCommit},
	{phase: database.AppMoveDone, class: classPostCommit},

	{phase: database.AppMoveCompensatingRoutesRestored, class: classCompensation, routed: true},
	{phase: database.AppMoveCompensatingRoutesWithdrawn, class: classCompensation, routed: true},
	{phase: database.AppMoveCompensatingBStopped, class: classCompensation},
	{phase: database.AppMoveCompensatingSourceStarted, class: classCompensation},
	{phase: database.AppMoveCompensatingSourceVerified, class: classCompensation},
	{phase: database.AppMoveCompensatingBRemoved, class: classCompensation},
	{phase: database.AppMoveRolledBack, class: classCompensation},

	{phase: database.AppMoveFailed, class: classHalted},
	{phase: database.AppMoveConflict, class: classHalted},
}

func ruleOf(phase database.AppMovePhase) (movePhase, bool) {
	i := slices.IndexFunc(movePhases, func(p movePhase) bool { return p.phase == phase })
	if i < 0 {
		return movePhase{}, false
	}
	return movePhases[i], true
}

// heldPhase is the phase the move is in, or the one it held when it halted.
func heldPhase(m database.AppMove) database.AppMovePhase {
	if m.Phase.Halted() {
		return m.HaltedPhase
	}
	return m.Phase
}

func classOf(m database.AppMove) phaseClass {
	rule, _ := ruleOf(heldPhase(m))
	return rule.class
}

// pastCommit reports whether the move's target node already is the destination: the move is committed, cleaning
// or parking the source, or done. A halted move counts by the phase it held. Such a move never compensates.
func pastCommit(m database.AppMove) bool { return classOf(m) == classPostCommit }

// compensating reports whether the move is undoing itself, halted in the middle of it included.
func compensating(m database.AppMove) bool { return classOf(m) == classCompensation }

// forwardPhases are the phases a move of this shape walks, in order, from preflight to done.
func forwardPhases(routed, stateful bool) []database.AppMovePhase {
	var out []database.AppMovePhase
	for _, p := range movePhases {
		if p.class == classCompensation || p.class == classHalted || p.routed && !routed || p.stateful && !stateful {
			continue
		}
		out = append(out, p.phase)
	}
	return out
}

// successorOf is the phase after phase on the forward path of a move of this shape, and false at its end or for a
// phase that is not on the path.
func successorOf(phase database.AppMovePhase, routed, stateful bool) (database.AppMovePhase, bool) {
	path := forwardPhases(routed, stateful)
	i := slices.Index(path, phase)
	if i < 0 || i == len(path)-1 {
		return "", false
	}
	return path[i+1], true
}
