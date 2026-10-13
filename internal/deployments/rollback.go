package deployments

// RollbackAvailable applies the §20.1 "Rollback available" rule. When it is
// not available, cause names the first failing condition. The effective mode
// follows §19: a manifest "manual" downgrades automatic, "automatic" never
// upgrades manual.
func RollbackAvailable(in RollbackInputs) (ok bool, cause string) {
	switch {
	case in.Kind != KindDeploy:
		return false, CauseRollbackKind
	case effectiveMode(in) != RollbackAutomatic:
		return false, CauseManualMode
	case in.Stateful:
		return false, CauseStateful
	case !in.EnvAllows:
		return false, CauseEnvironmentForbids
	case !in.HasKnownGood:
		return false, CauseNoKnownGood
	}
	return true, ""
}

func effectiveMode(in RollbackInputs) string {
	if in.Mode == RollbackAutomatic && in.ManifestMode != RollbackManual {
		return RollbackAutomatic
	}
	return RollbackManual
}
