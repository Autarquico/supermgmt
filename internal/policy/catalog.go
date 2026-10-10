// Package policy holds the action catalog, the policy document and the
// authorization engine (spec §11). It is pure: no storage, no I/O, no clock.
package policy

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Mode says how an action is carried out (spec §11.2).
type Mode string

const (
	ModeQuery      Mode = "query"
	ModeJob        Mode = "job"
	ModeDirect     Mode = "direct"
	ModeGovernance Mode = "governance"
	ModeSubAction  Mode = "sub-action"
)

// ParamType is the type of an action parameter.
type ParamType string

const (
	ParamString     ParamType = "string"
	ParamStringList ParamType = "string_list"
)

// ParamSpec is one entry of an action's closed parameter schema.
type ParamSpec struct {
	Name     string
	Type     ParamType
	Required bool
	// Values closes the set of accepted string values; empty means any string.
	Values []string
	// RiskByValue raises the action's risk for specific values.
	RiskByValue map[string]domain.RiskClass
}

// ActionSpec is one row of the action catalog.
type ActionSpec struct {
	Name string
	// Resource is the type the action targets; empty for plan.create, whose
	// targets are whatever the plan names.
	Resource          domain.ResourceType
	Risk              domain.RiskClass
	Mode              Mode
	Retry             domain.RetryClass // empty when the catalog says "—"
	Capability        string            // empty when no capability is required
	MaxAttempts       int               // 0 when the catalog says "—"
	CredentialIssuing bool
	Params            []ParamSpec
}

// Action names the engine itself must recognise.
const (
	ActionProxmoxVMPower        = "proxmox.vm.power"
	ActionSnapshotCreate        = "proxmox.snapshot.create"
	ActionNodeBackupTemplateRun = "node.backup_template.run"
	ActionApprovalGrant         = "approval.grant"
	ActionApprovalReject        = "approval.reject"
	ActionJobCancel             = "job.cancel"
	ActionJobResolve            = "job.resolve"
	ActionNodeSetup             = "node.setup"
	ActionSudoersWrite          = "sudoers.write"
	ActionLogBrokerInstall      = "log_broker.install"
)

// node.setup parameters (ADR-0009). docker_access has no default: the caller
// must ask, because docker group membership is root-equivalent (spec §17).
// Each grants entry is "<verb> <unit>", the tail of its sudoers line.
const (
	ParamDockerAccess = "docker_access"
	ParamLogsMode     = "logs_mode"
	ParamGrants       = "grants"
)

var catalogIndex = sync.OnceValue(func() map[string]ActionSpec {
	index := make(map[string]ActionSpec)
	for _, spec := range buildCatalog() {
		index[spec.Name] = spec
	}
	return index
})

// Lookup returns the catalog entry for action.
func Lookup(action string) (ActionSpec, bool) {
	spec, ok := catalogIndex()[action]
	return spec, ok
}

// Catalog lists every action, sorted by name.
func Catalog() []ActionSpec {
	index := catalogIndex()
	all := make([]ActionSpec, 0, len(index))
	for _, spec := range index {
		all = append(all, spec)
	}
	slices.SortFunc(all, func(a, b ActionSpec) int { return strings.Compare(a.Name, b.Name) })
	return all
}

// RiskFor computes the risk of action for params. Callers never supply risk.
// It rejects unknown actions and parameters outside the action's closed schema.
func RiskFor(action string, params map[string]any) (domain.RiskClass, error) {
	spec, ok := Lookup(action)
	if !ok {
		return "", unknownAction(action)
	}
	return spec.riskFor(params)
}

func unknownAction(action string) error {
	return smerr.New(smerr.CodeInvalidArgument, smerr.ReasonUnknownAction, "unknown action: "+action)
}

func (s ActionSpec) riskFor(params map[string]any) (domain.RiskClass, error) {
	if err := s.validateParams(params); err != nil {
		return "", err
	}
	risk := s.Risk
	for _, p := range s.Params {
		value, _ := params[p.Name].(string)
		if raised, ok := p.RiskByValue[value]; ok && raised.Rank() > risk.Rank() {
			risk = raised
		}
	}
	return risk, nil
}

func (s ActionSpec) validateParams(params map[string]any) error {
	for name := range params {
		if !slices.ContainsFunc(s.Params, func(p ParamSpec) bool { return p.Name == name }) {
			return s.paramError(name, "unknown parameter")
		}
	}
	for _, p := range s.Params {
		raw, present := params[p.Name]
		if !present {
			if p.Required {
				return s.paramError(p.Name, "missing required parameter")
			}
			continue
		}
		if problem := p.check(raw); problem != "" {
			return s.paramError(p.Name, problem)
		}
	}
	return nil
}

// check returns what is wrong with raw as a value of p, or "".
func (p ParamSpec) check(raw any) string {
	if p.Type == ParamStringList {
		if !isStringList(raw) {
			return "parameter must be a list of strings"
		}
		return ""
	}
	value, isString := raw.(string)
	switch {
	case !isString:
		return "parameter must be a string"
	case len(p.Values) > 0 && !slices.Contains(p.Values, value):
		return "invalid parameter value"
	}
	return ""
}

// isStringList accepts []string and the []any a JSON decoder produces.
func isStringList(raw any) bool {
	switch list := raw.(type) {
	case []string:
		return true
	case []any:
		return !slices.ContainsFunc(list, func(item any) bool { _, ok := item.(string); return !ok })
	}
	return false
}

func (s ActionSpec) paramError(param, problem string) error {
	return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("%s: %s %q", s.Name, problem, param))
}

func buildCatalog() []ActionSpec {
	const (
		read   = domain.RiskRead
		op     = domain.RiskOperational
		high   = domain.RiskHigh
		destr  = domain.RiskDestructive
		noRun  = domain.RetryNonRetryable
		resume = domain.RetryResumable
		idem   = domain.RetryIdempotent
	)
	query := func(name string, res domain.ResourceType, capability string) ActionSpec {
		return ActionSpec{Name: name, Resource: res, Risk: read, Mode: ModeQuery, Capability: capability}
	}
	job := func(name string, res domain.ResourceType, risk domain.RiskClass, retry domain.RetryClass, capability string, attempts int) ActionSpec {
		return ActionSpec{Name: name, Resource: res, Risk: risk, Mode: ModeJob, Retry: retry, Capability: capability, MaxAttempts: attempts}
	}
	direct := func(name string, res domain.ResourceType, risk domain.RiskClass) ActionSpec {
		return ActionSpec{Name: name, Resource: res, Risk: risk, Mode: ModeDirect}
	}
	credential := func(name string, res domain.ResourceType) ActionSpec {
		spec := direct(name, res, op)
		spec.CredentialIssuing = true
		return spec
	}
	governance := func(name string, res domain.ResourceType) ActionSpec {
		return ActionSpec{Name: name, Resource: res, Risk: domain.RiskGovernance, Mode: ModeGovernance}
	}

	vmPower := job(ActionProxmoxVMPower, domain.ResourceNode, op, noRun, "proxmox.vm.power", 1)
	vmPower.Params = []ParamSpec{{
		Name:        "verb",
		Type:        ParamString,
		Required:    true,
		Values:      []string{"start", "shutdown", "reboot", "stop"},
		RiskByValue: map[string]domain.RiskClass{"stop": high},
	}}

	setup := job(ActionNodeSetup, domain.ResourceNode, high, idem, "node.ssh", 3)
	setup.Params = []ParamSpec{
		{Name: ParamDockerAccess, Type: ParamString, Required: true, Values: []string{"true", "false"}},
		{Name: ParamLogsMode, Type: ParamString, Required: true, Values: []string{"journal-group", "broker"}},
		{Name: ParamGrants, Type: ParamStringList},
	}

	return []ActionSpec{
		query("node.read", domain.ResourceNode, ""),
		query("service.read", domain.ResourceService, "service.read"),
		query("service.logs", domain.ResourceService, "service.logs"),
		query("app.read", domain.ResourceApp, ""),
		query("app_target.read", domain.ResourceAppTarget, ""),
		query("deployment.read", domain.ResourceDeployment, ""),
		query("environment.read", domain.ResourceEnvironment, ""),
		query("provider.read", domain.ResourceProvider, ""),
		query("job.read", domain.ResourceJob, ""),
		query("plan.read", domain.ResourcePlan, ""),
		query("event.read", domain.ResourceEvent, ""),
		query("config.read", domain.ResourceInstance, ""),
		query("identity.read", domain.ResourceIdentity, ""),
		query("backup.read", domain.ResourceInstance, ""),
		query("node.connect", domain.ResourceNode, "node.ssh"),
		query("plan.create", "", ""),

		job("node.probe", domain.ResourceNode, read, idem, "node.read", 3),
		job("service.start", domain.ResourceService, op, noRun, "service.start", 1),
		job("service.stop", domain.ResourceService, op, noRun, "service.stop", 1),
		job("service.restart", domain.ResourceService, op, noRun, "service.restart", 1),
		job("node.reboot", domain.ResourceNode, high, noRun, "node.reboot", 1),
		job("node.shutdown", domain.ResourceNode, high, noRun, "node.shutdown", 1),
		vmPower,
		job(ActionSnapshotCreate, domain.ResourceNode, op, noRun, "proxmox.snapshot.create", 1),
		job("proxmox.snapshot.rollback", domain.ResourceNode, high, noRun, "proxmox.snapshot.create", 1),
		job("proxmox.snapshot.delete", domain.ResourceNode, destr, noRun, "proxmox.snapshot.create", 1),
		job("proxmox.backup.create", domain.ResourceNode, op, noRun, "proxmox.backup.create", 1),
		{Name: ActionNodeBackupTemplateRun, Resource: domain.ResourceNode, Risk: op, Mode: ModeSubAction, Capability: "node.exec.template"},
		job("deployment.create", domain.ResourceAppTarget, op, resume, "docker.compose.deploy", 3),
		job("deployment.rollback", domain.ResourceAppTarget, op, resume, "docker.compose.deploy", 3),
		setup,
		job(ActionSudoersWrite, domain.ResourceNode, high, noRun, "node.ssh", 1),
		job(ActionLogBrokerInstall, domain.ResourceNode, high, noRun, "node.ssh", 1),
		job("backup.create", domain.ResourceInstance, op, idem, "", 3),

		direct("node.add", domain.ResourceNode, op),
		direct("node.update", domain.ResourceNode, op),
		direct("node.remove", domain.ResourceNode, destr),
		direct("provider.write", domain.ResourceProvider, high),
		direct("provider.delete", domain.ResourceProvider, destr),
		direct("environment.write", domain.ResourceEnvironment, high),
		direct("app.write", domain.ResourceApp, op),
		direct("app_target.write", domain.ResourceAppTarget, op),
		direct("config.write", domain.ResourceInstance, high),
		direct("secret.write", domain.ResourceSecret, high),
		direct("identity.write", domain.ResourceIdentity, high),
		direct("role_binding.write", domain.ResourceIdentity, high),
		direct("mcp_client.register", domain.ResourceIdentity, high),
		credential("mcp_client.issue_token", domain.ResourceIdentity),
		direct("mcp_client.delete", domain.ResourceIdentity, op),
		credential("token.create", domain.ResourceIdentity),
		direct("token.revoke", domain.ResourceIdentity, op),
		credential("enrollment.create", domain.ResourceInstance),

		governance(ActionApprovalGrant, domain.ResourcePlan),
		governance(ActionApprovalReject, domain.ResourcePlan),
		governance(ActionJobCancel, domain.ResourceJob),
		governance(ActionJobResolve, domain.ResourceJob),
	}
}
