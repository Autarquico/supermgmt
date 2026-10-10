package policy

import (
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
)

// ApprovalRecord is the stored decision of one approver for one plan hash.
// Renewing an approval updates ExpiresAt, so only ExpiresAt matters here.
type ApprovalRecord struct {
	Approver  domain.ID
	Decision  domain.ApprovalDecision
	ExpiresAt time.Time
}

// QuorumInput is everything EvaluateQuorum needs (spec §11.4).
type QuorumInput struct {
	Now      time.Time
	Required int
	Records  []ApprovalRecord

	Requester         domain.Actor
	AllowSelfApproval bool

	// StillAuthorized reports whether an approver still holds the permission
	// to approve. A nil function authorizes nobody, so forgetting it can only
	// stall an approval, never grant one.
	StillAuthorized func(approver domain.ID) bool
}

// QuorumResult is the verdict on a set of approvals.
type QuorumResult struct {
	Satisfied bool
	Count     int
	Required  int
	Rejected  bool
}

// EvaluateQuorum counts distinct, unexpired approvals from still-authorized
// approvers. Any rejection is final and blocks the quorum.
func EvaluateQuorum(in QuorumInput) QuorumResult {
	required := max(in.Required, minApprovals)
	out := QuorumResult{Required: required}
	counted := make(map[domain.ID]struct{})
	for _, rec := range in.Records {
		switch rec.Decision {
		case domain.DecisionReject:
			out.Rejected = true
		case domain.DecisionApprove:
			if in.counts(rec) {
				counted[rec.Approver] = struct{}{}
			}
		}
	}
	out.Count = len(counted)
	out.Satisfied = !out.Rejected && out.Count >= required
	return out
}

func (in QuorumInput) counts(rec ApprovalRecord) bool {
	switch {
	case !in.Now.Before(rec.ExpiresAt):
		return false
	case in.StillAuthorized == nil || !in.StillAuthorized(rec.Approver):
		return false
	case rec.Approver == in.Requester.ID:
		return in.AllowSelfApproval && in.Requester.Type == domain.ActorHuman
	}
	return true
}
