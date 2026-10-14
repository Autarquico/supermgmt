#!/bin/sh
# Release gate (ADR-0034, Q17): every check-run named in REQUIRED must have finished with conclusion
# success on the commit CHECKS describes. Pending, missing, skipped, neutral, cancelled, failed or
# any other outcome fails the gate; so does a check-run that GitHub Actions did not create.
# Usage: require-checks.sh REQUIRED CHECKS
#   REQUIRED  required-checks.txt: one check-run name per line, blank lines and # comments ignored
#   CHECKS    JSON of `gh api --paginate repos/OWNER/REPO/commits/SHA/check-runs` (pages may be concatenated)
# Needs jq. Exit 1: gate not satisfied (one line per offending check). Exit 2: unusable input.
set -eu

[ $# -eq 2 ] || { echo "usage: require-checks.sh REQUIRED CHECKS" >&2; exit 2; }
required=$1
checks=$2
[ -f "$required" ] || { echo "require-checks: $required does not exist" >&2; exit 2; }
[ -f "$checks" ] || { echo "require-checks: $checks does not exist" >&2; exit 2; }

names=$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$required" | jq -Rn '[inputs | select(length > 0 and (startswith("#") | not))]')
[ "$(printf '%s' "$names" | jq 'length')" -gt 0 ] || { echo "require-checks: $required lists no checks" >&2; exit 2; }

verdicts=$(jq -sr --argjson names "$names" '
	[ .[] | if type == "array" then .[] else . end | .check_runs[]? ] as $runs
	| $names[] as $name
	| [ $runs[] | select(.name == $name and .app.slug == "github-actions") ] as $found
	| if ($found | length) == 0 then "\($name): missing"
	  elif any($found[]; .status != "completed") then "\($name): not finished (\([ $found[] | select(.status != "completed") | .status ] | first))"
	  elif any($found[]; .conclusion != "success") then "\($name): \([ $found[] | select(.conclusion != "success") | .conclusion // "no conclusion" ] | first)"
	  else empty end
' "$checks") || { echo "require-checks: $checks is not check-run JSON" >&2; exit 2; }

if [ -n "$verdicts" ]; then
	printf '%s\n' "$verdicts" | sed 's/^/require-checks: /' >&2
	exit 1
fi
echo "require-checks: all $(printf '%s' "$names" | jq 'length') required checks succeeded"
