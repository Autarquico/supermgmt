package mcp

import (
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
)

// ---- approvals ----------------------------------------------------------------

// ApprovalView is a job awaiting approval with the plan it binds to. The plan
// goes through the same document view as a created plan.
type ApprovalView struct {
	Job          JobView      `json:"job"`
	Plan         PlanDocument `json:"plan"`
	Environments []string     `json:"environments"`
	Quorum       int          `json:"quorum"`
	Approvals    int          `json:"approvals"`
	ExpiresAt    time.Time    `json:"expires_at"`
}

func ViewApproval(a wire.Approval) (ApprovalView, error) {
	plan, err := viewPlanDocument(a.Plan)
	if err != nil {
		return ApprovalView{}, err
	}
	return ApprovalView{
		Job:          viewJob(a.Job),
		Plan:         plan,
		Environments: operatorLines(orEmpty(a.Environments)),
		Quorum:       a.Quorum,
		Approvals:    a.Approvals,
		ExpiresAt:    a.ExpiresAt,
	}, nil
}

// ---- providers ----------------------------------------------------------------

type ProviderView struct {
	ID           domain.ID             `json:"id"`
	Type         string                `json:"type"`
	Name         string                `json:"name"`
	Origin       domain.ProviderOrigin `json:"origin"`
	Status       string                `json:"status"`
	SpecRevision int64                 `json:"spec_revision"`
	LastSyncAt   *time.Time            `json:"last_sync_at"`
	Remote       ProviderRemote        `json:"remote"`
}

// ProviderRemote is why the latest sync failed, which the provider's API words.
type ProviderRemote struct {
	remoteMark
	LastError string `json:"last_error"`
}

func ViewProvider(p wire.Provider) ProviderView {
	var b remoteBuilder
	remote := ProviderRemote{LastError: b.scalar(p.LastError)}
	remote.remoteMark = b.mark()
	return ProviderView{
		ID:           p.ID,
		Type:         operatorLine(p.Type),
		Name:         operatorLine(p.Name),
		Origin:       p.Origin,
		Status:       operatorLine(p.Status),
		SpecRevision: p.SpecRevision,
		LastSyncAt:   p.LastSyncAt,
		Remote:       remote,
	}
}

// ---- backups ------------------------------------------------------------------

// BackupView leaves out the key ids a backup is wrapped under.
type BackupView struct {
	Name          string    `json:"name"`
	SizeBytes     int64     `json:"size_bytes"`
	CreatedAt     time.Time `json:"created_at"`
	SchemaVersion int       `json:"schema_version"`
	SMVersion     string    `json:"sm_version"`
}

func ViewBackup(b wire.Backup) BackupView {
	return BackupView{
		Name:          operatorLine(b.Name),
		SizeBytes:     b.SizeBytes,
		CreatedAt:     b.CreatedAt,
		SchemaVersion: b.SchemaVersion,
		SMVersion:     operatorLine(b.SMVersion),
	}
}

// ---- tunnel enrollments -------------------------------------------------------

// TunnelEnrollmentView leaves out the join line (a command to run on the
// host, not for a model to relay) and the scanned host public key.
type TunnelEnrollmentView struct {
	ID          domain.ID        `json:"id"`
	NodeID      domain.ID        `json:"node_id"`
	Name        string           `json:"name"`
	Environment string           `json:"environment"`
	Tags        []string         `json:"tags"`
	Hostname    string           `json:"hostname"`
	Phase       string           `json:"phase"`
	ExpiresAt   time.Time        `json:"expires_at"`
	Remote      EnrollmentRemote `json:"remote"`
}

// EnrollmentRemote is what the host key scan over the tunnel produced.
type EnrollmentRemote struct {
	remoteMark
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	Error              string `json:"error"`
}

func ViewTunnelEnrollment(e wire.TunnelEnrollment) TunnelEnrollmentView {
	var b remoteBuilder
	remote := EnrollmentRemote{HostKeyFingerprint: b.scalar(e.HostKeyFingerprint), Error: b.scalar(e.Error)}
	remote.remoteMark = b.mark()
	return TunnelEnrollmentView{
		ID:          e.ID,
		NodeID:      e.NodeID,
		Name:        operatorLine(e.Name),
		Environment: operatorLine(e.Environment),
		Tags:        operatorLines(orEmpty(e.Tags)),
		Hostname:    operatorLine(e.Hostname),
		Phase:       operatorLine(e.Phase),
		ExpiresAt:   e.ExpiresAt,
		Remote:      remote,
	}
}

// ---- instance SSH key ---------------------------------------------------------

// SSHKeyView is the public half of the instance identity; the DTO carries
// nothing else.
type SSHKeyView struct {
	Ref               string `json:"ref"`
	Version           int    `json:"version"`
	AuthorizedKey     string `json:"authorized_key"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

func ViewSSHKey(k wire.SSHKey) SSHKeyView {
	return SSHKeyView{
		Ref:               operatorLine(k.Ref),
		Version:           k.Version,
		AuthorizedKey:     operatorLine(k.AuthorizedKey),
		FingerprintSHA256: operatorLine(k.FingerprintSHA256),
	}
}

// ---- plannable actions --------------------------------------------------------

type ActionView struct {
	Name            string                `json:"name"`
	TargetType      domain.ResourceType   `json:"target_type"`
	Risk            domain.RiskClass      `json:"risk"`
	Parameters      []ActionParameterView `json:"parameters"`
	NeedsWriteTools bool                  `json:"needs_write_tools"`
}

type ActionParameterView struct {
	Name        string                      `json:"name"`
	Type        string                      `json:"type"`
	Required    bool                        `json:"required"`
	Values      []string                    `json:"values"`
	RiskByValue map[string]domain.RiskClass `json:"risk_by_value"`
}

func ViewAction(a wire.PlannableAction) ActionView {
	params := make([]ActionParameterView, len(a.Parameters))
	for i, p := range a.Parameters {
		params[i] = ActionParameterView{
			Name: p.Name, Type: p.Type, Required: p.Required,
			Values: orEmpty(p.Values), RiskByValue: orEmptyMap(p.RiskByValue),
		}
	}
	return ActionView{Name: a.Name, TargetType: a.Target, Risk: a.Risk, Parameters: params, NeedsWriteTools: a.NeedsWriteTools}
}

func orEmptyMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return map[K]V{}
	}
	return m
}

// ---- status -------------------------------------------------------------------

// StatusView is the composite of me, nodes and jobs. Counts are taken over
// whole listings; Truncated says the listing outgrew maxResolvePages.
type StatusView struct {
	Identity IdentityView `json:"identity"`
	Nodes    NodeCounts   `json:"nodes"`
	Jobs     JobCounts    `json:"jobs"`
}

type IdentityView struct {
	IdentityID   domain.ID             `json:"identity_id"`
	ActorType    domain.ActorType      `json:"actor_type"`
	DisplayName  string                `json:"display_name"`
	Credential   domain.CredentialKind `json:"credential"`
	Roles        []string              `json:"roles"`
	InstanceMode string                `json:"instance_mode"`
}

type NodeCounts struct {
	Total          int            `json:"total"`
	ByReachability map[string]int `json:"by_reachability"`
	Truncated      bool           `json:"truncated"`
}

// JobCounts counts the jobs that are not finished, by state.
type JobCounts struct {
	Unfinished int            `json:"unfinished"`
	ByState    map[string]int `json:"by_state"`
	Truncated  bool           `json:"truncated"`
}

func ViewIdentity(m wire.Me) IdentityView {
	return IdentityView{
		IdentityID:   m.IdentityID,
		ActorType:    m.ActorType,
		DisplayName:  operatorLine(m.DisplayName),
		Credential:   m.Credential,
		Roles:        operatorLines(orEmpty(m.Roles)),
		InstanceMode: operatorLine(m.InstanceMode),
	}
}
