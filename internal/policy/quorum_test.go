package policy

import (
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

var quorumNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func approve(who string, expiresIn time.Duration) ApprovalRecord {
	return ApprovalRecord{Approver: domain.ID(who), Decision: domain.DecisionApprove, ExpiresAt: quorumNow.Add(expiresIn)}
}

func reject(who string, expiresIn time.Duration) ApprovalRecord {
	return ApprovalRecord{Approver: domain.ID(who), Decision: domain.DecisionReject, ExpiresAt: quorumNow.Add(expiresIn)}
}

func everyoneAuthorized(domain.ID) bool { return true }

func TestEvaluateQuorum(t *testing.T) {
	requester := domain.Actor{ID: "requester", Type: domain.ActorHuman}
	cases := []struct {
		name string
		in   QuorumInput
		want QuorumResult
	}{
		{
			"one_of_one",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("a", time.Hour)}},
			QuorumResult{Satisfied: true, Count: 1, Required: 1},
		},
		{
			"no_records",
			QuorumInput{Required: 1},
			QuorumResult{Required: 1},
		},
		{
			"two_of_two_distinct",
			QuorumInput{Required: 2, Records: []ApprovalRecord{approve("a", time.Hour), approve("b", time.Hour)}},
			QuorumResult{Satisfied: true, Count: 2, Required: 2},
		},
		{
			"one_of_two",
			QuorumInput{Required: 2, Records: []ApprovalRecord{approve("a", time.Hour)}},
			QuorumResult{Count: 1, Required: 2},
		},
		{
			"duplicate_approver_counts_once",
			QuorumInput{Required: 2, Records: []ApprovalRecord{approve("a", time.Hour), approve("a", 2*time.Hour)}},
			QuorumResult{Count: 1, Required: 2},
		},
		{
			"expired_approval_does_not_count",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("a", -time.Second)}},
			QuorumResult{Required: 1},
		},
		{
			"approval_expiring_exactly_now_does_not_count",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("a", 0)}},
			QuorumResult{Required: 1},
		},
		{
			"expired_and_fresh_mix",
			QuorumInput{Required: 2, Records: []ApprovalRecord{approve("a", -time.Hour), approve("b", time.Hour)}},
			QuorumResult{Count: 1, Required: 2},
		},
		{
			"rejection_is_final_even_with_quorum",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("a", time.Hour), reject("b", time.Hour)}},
			QuorumResult{Count: 1, Required: 1, Rejected: true},
		},
		{
			"expired_rejection_is_still_final",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("a", time.Hour), reject("b", -time.Hour)}},
			QuorumResult{Count: 1, Required: 1, Rejected: true},
		},
		{
			"rejection_from_deauthorized_approver_still_blocks",
			QuorumInput{
				Required: 1, Records: []ApprovalRecord{approve("a", time.Hour), reject("gone", time.Hour)},
				StillAuthorized: func(id domain.ID) bool { return id != "gone" },
			},
			QuorumResult{Count: 1, Required: 1, Rejected: true},
		},
		{
			"approver_who_lost_authorization_is_not_counted",
			QuorumInput{
				Required: 2, Records: []ApprovalRecord{approve("a", time.Hour), approve("b", time.Hour)},
				StillAuthorized: func(id domain.ID) bool { return id == "a" },
			},
			QuorumResult{Count: 1, Required: 2},
		},
		{
			"nil_authorization_callback_authorizes_nobody",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("a", time.Hour)}, StillAuthorized: nil},
			QuorumResult{Required: 1},
		},
		{
			"self_approval_off",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("requester", time.Hour)}, Requester: requester, AllowSelfApproval: false},
			QuorumResult{Required: 1},
		},
		{
			"self_approval_on_for_human",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("requester", time.Hour)}, Requester: requester, AllowSelfApproval: true},
			QuorumResult{Satisfied: true, Count: 1, Required: 1},
		},
		{
			"self_approval_counts_once",
			QuorumInput{Required: 2, Records: []ApprovalRecord{approve("requester", time.Hour), approve("requester", 2*time.Hour)}, Requester: requester, AllowSelfApproval: true},
			QuorumResult{Count: 1, Required: 2},
		},
		{
			"self_approval_plus_another",
			QuorumInput{Required: 2, Records: []ApprovalRecord{approve("requester", time.Hour), approve("b", time.Hour)}, Requester: requester, AllowSelfApproval: true},
			QuorumResult{Satisfied: true, Count: 2, Required: 2},
		},
		{
			"self_approval_on_but_requester_is_automation",
			QuorumInput{
				Required: 1, Records: []ApprovalRecord{approve("requester", time.Hour)},
				Requester: domain.Actor{ID: "requester", Type: domain.ActorAutomation}, AllowSelfApproval: true,
			},
			QuorumResult{Required: 1},
		},
		{
			"self_approval_on_but_requester_is_mcp",
			QuorumInput{
				Required: 1, Records: []ApprovalRecord{approve("requester", time.Hour)},
				Requester: domain.Actor{ID: "requester", Type: domain.ActorMCP}, AllowSelfApproval: true,
			},
			QuorumResult{Required: 1},
		},
		{
			"other_approvers_unaffected_by_self_approval_off",
			QuorumInput{Required: 1, Records: []ApprovalRecord{approve("b", time.Hour)}, Requester: requester},
			QuorumResult{Satisfied: true, Count: 1, Required: 1},
		},
		{
			"required_below_one_is_treated_as_one",
			QuorumInput{Required: 0},
			QuorumResult{Required: 1},
		},
		{
			"required_below_one_with_one_approval",
			QuorumInput{Required: -2, Records: []ApprovalRecord{approve("a", time.Hour)}},
			QuorumResult{Satisfied: true, Count: 1, Required: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			in.Now = quorumNow
			if in.StillAuthorized == nil && tc.name != "nil_authorization_callback_authorizes_nobody" {
				in.StillAuthorized = everyoneAuthorized
			}
			if got := EvaluateQuorum(in); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
