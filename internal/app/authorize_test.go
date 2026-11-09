package app

import (
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
)

func TestDenialsNameTheRuleOrGateThatRefused(t *testing.T) {
	cases := map[smerr.Reason]string{
		smerr.ReasonDestructiveGate: "allow_destructive",
		smerr.ReasonSelfApproval:    "allow_self_approval",
		smerr.ReasonDefaultDeny:     "no allowing rule",
		smerr.ReasonDenyRule:        "deny rule",
		smerr.ReasonScopeDenied:     "scopes",
	}
	for reason, want := range cases {
		err := decisionError(policy.Result{Decision: policy.DecisionDeny, Reason: reason})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want mention of %q", reason, err, want)
		}
	}
}
