package policy

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// specCatalog transcribes the spec §11.2 table: action, resource, risk, mode,
// retry, capability, max attempts. "-" means the table shows "—".
const specCatalog = `
node.read                  node        read         query       -              -                        -
service.read               service     read         query       -              service.read             -
service.logs               service     read         query       -              service.logs             -
app.read                   app         read         query       -              -                        -
app_target.read            app_target  read         query       -              -                        -
deployment.read            deployment  read         query       -              -                        -
environment.read           environment read         query       -              -                        -
provider.read              provider    read         query       -              -                        -
job.read                   job         read         query       -              -                        -
plan.read                  plan        read         query       -              -                        -
event.read                 event       read         query       -              -                        -
config.read                instance    read         query       -              -                        -
identity.read              identity    read         query       -              -                        -
backup.read                instance    read         query       -              -                        -
node.connect               node        read         query       -              node.ssh                 -
plan.create                -           read         query       -              -                        -
node.probe                 node        read         job         idempotent     node.read                3
service.start              service     operational  job         non_retryable  service.start            1
service.stop               service     operational  job         non_retryable  service.stop             1
service.restart            service     operational  job         non_retryable  service.restart          1
node.reboot                node        high         job         non_retryable  node.reboot              1
node.shutdown              node        high         job         non_retryable  node.shutdown            1
proxmox.vm.power           node        operational  job         non_retryable  proxmox.vm.power         1
proxmox.snapshot.create    node        operational  job         non_retryable  proxmox.snapshot.create  1
proxmox.snapshot.rollback  node        high         job         non_retryable  proxmox.snapshot.create  1
proxmox.snapshot.delete    node        destructive  job         non_retryable  proxmox.snapshot.create  1
proxmox.backup.create      node        operational  job         non_retryable  proxmox.backup.create    1
node.backup_template.run   node        operational  sub-action  -              node.exec.template       -
deployment.create          app_target  operational  job         resumable      docker.compose.deploy    3
deployment.rollback        app_target  operational  job         resumable      docker.compose.deploy    3
node.setup                 node        high         job         idempotent     node.ssh                 3
node.tunnel.disable        node        high         job         idempotent     node.ssh                 3
cloudflare.access_token.rotate instance high        job         idempotent     -                        3
sudoers.write              node        high         job         non_retryable  node.ssh                 1
log_broker.install         node        high         job         non_retryable  node.ssh                 1
backup.create              instance    operational  job         idempotent     -                        3
node.add                   node        operational  direct      -              -                        -
node.update                node        operational  direct      -              -                        -
node.remove                node        destructive  direct      -              -                        -
provider.write             provider    high         direct      -              -                        -
provider.delete            provider    destructive  direct      -              -                        -
environment.write          environment high         direct      -              -                        -
app.write                  app         operational  direct      -              -                        -
app_target.write           app_target  operational  direct      -              -                        -
app_route.expose           app_target  operational  direct      -              -                        -
app_route.unexpose         app_target  operational  direct      -              -                        -
config.write               instance    high         direct      -              -                        -
secret.write               secret      high         direct      -              -                        -
identity.write             identity    high         direct      -              -                        -
role_binding.write         identity    high         direct      -              -                        -
mcp_client.register        identity    high         direct      -              -                        -
mcp_client.issue_token     identity    operational  direct      -              -                        -
mcp_client.delete          identity    operational  direct      -              -                        -
token.create               identity    operational  direct      -              -                        -
token.revoke               identity    operational  direct      -              -                        -
enrollment.create          instance    operational  direct      -              -                        -
approval.grant             plan        governance   governance  -              -                        -
approval.reject            plan        governance   governance  -              -                        -
job.cancel                 job         governance   governance  -              -                        -
job.resolve                job         governance   governance  -              -                        -
`

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func TestCatalog_MatchesSpecTable(t *testing.T) {
	rows := strings.Split(strings.TrimSpace(specCatalog), "\n")
	if got := len(Catalog()); got != len(rows) {
		t.Fatalf("catalog has %d actions, spec table has %d", got, len(rows))
	}
	for _, row := range rows {
		f := strings.Fields(row)
		name := f[0]
		t.Run(name, func(t *testing.T) {
			spec, ok := Lookup(name)
			if !ok {
				t.Fatal("missing from catalog")
			}
			attempts := 0
			if dash(f[6]) != "" {
				attempts, _ = strconv.Atoi(f[6])
			}
			want := ActionSpec{
				Name: name, Resource: domain.ResourceType(dash(f[1])), Risk: domain.RiskClass(f[2]),
				Mode: Mode(f[3]), Retry: domain.RetryClass(dash(f[4])), Capability: dash(f[5]), MaxAttempts: attempts,
			}
			spec.Params, spec.CredentialIssuing = nil, false
			if spec.Name != want.Name || spec.Resource != want.Resource || spec.Risk != want.Risk ||
				spec.Mode != want.Mode || spec.Retry != want.Retry || spec.Capability != want.Capability ||
				spec.MaxAttempts != want.MaxAttempts {
				t.Fatalf("got %+v, want %+v", spec, want)
			}
		})
	}
}

func TestCatalog_CredentialIssuingActions(t *testing.T) {
	var got []string
	for _, spec := range Catalog() {
		if spec.CredentialIssuing {
			got = append(got, spec.Name)
		}
	}
	want := "enrollment.create mcp_client.issue_token token.create"
	if strings.Join(got, " ") != want {
		t.Fatalf("credential-issuing = %v, want %s", got, want)
	}
}

func TestCatalog_EveryTypeAndEnumIsValid(t *testing.T) {
	for _, spec := range Catalog() {
		if spec.Resource != "" && !spec.Resource.Valid() {
			t.Errorf("%s: invalid resource %q", spec.Name, spec.Resource)
		}
		if !spec.Risk.Valid() {
			t.Errorf("%s: invalid risk %q", spec.Name, spec.Risk)
		}
		if spec.Retry != "" && !spec.Retry.Valid() {
			t.Errorf("%s: invalid retry %q", spec.Name, spec.Retry)
		}
	}
}

func TestRiskFor(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		params  map[string]any
		want    domain.RiskClass
		wantErr bool
	}{
		{"power_start", ActionProxmoxVMPower, map[string]any{"verb": "start"}, domain.RiskOperational, false},
		{"power_shutdown", ActionProxmoxVMPower, map[string]any{"verb": "shutdown"}, domain.RiskOperational, false},
		{"power_reboot", ActionProxmoxVMPower, map[string]any{"verb": "reboot"}, domain.RiskOperational, false},
		{"power_stop_is_high", ActionProxmoxVMPower, map[string]any{"verb": "stop"}, domain.RiskHigh, false},
		{"power_missing_verb", ActionProxmoxVMPower, nil, "", true},
		{"power_unknown_verb", ActionProxmoxVMPower, map[string]any{"verb": "poweroff"}, "", true},
		{"power_verb_not_string", ActionProxmoxVMPower, map[string]any{"verb": 1}, "", true},
		{"power_extra_param", ActionProxmoxVMPower, map[string]any{"verb": "start", "force": "yes"}, "", true},
		{"no_params_action", "node.reboot", nil, domain.RiskHigh, false},
		{"no_params_action_rejects_params", "node.reboot", map[string]any{"x": "y"}, "", true},
		{"destructive", "node.remove", nil, domain.RiskDestructive, false},
		{"setup", ActionNodeSetup, setupParams("false", "journal-group", []any{"restart nginx.service"}), domain.RiskHigh, false},
		{"setup_without_grants", ActionNodeSetup, setupParams("true", "broker", nil), domain.RiskHigh, false},
		{"setup_grants_as_strings", ActionNodeSetup, setupParams("true", "broker", []string{"start a.service"}), domain.RiskHigh, false},
		{"setup_docker_access_has_no_default", ActionNodeSetup, map[string]any{ParamLogsMode: "broker"}, "", true},
		{"setup_docker_access_not_boolean_text", ActionNodeSetup, setupParams("yes", "broker", nil), "", true},
		{"setup_unknown_logs_mode", ActionNodeSetup, setupParams("true", "syslog", nil), "", true},
		{"setup_grants_not_a_list", ActionNodeSetup, setupParams("true", "broker", "restart a.service"), "", true},
		{"setup_grants_with_a_number", ActionNodeSetup, setupParams("true", "broker", []any{"restart a.service", 1}), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RiskFor(tc.action, tc.params)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("risk = %q, want %q", got, tc.want)
			}
			if err != nil && smerr.CodeOf(err) != smerr.CodeInvalidArgument {
				t.Fatalf("code = %s, want INVALID_ARGUMENT", smerr.CodeOf(err))
			}
		})
	}
}

// setupParams builds node.setup parameters; a nil grants is left out.
func setupParams(dockerAccess, logsMode string, grants any) map[string]any {
	params := map[string]any{ParamDockerAccess: dockerAccess, ParamLogsMode: logsMode}
	if grants != nil {
		params[ParamGrants] = grants
	}
	return params
}

func TestCatalog_EveryServiceVerbIsAnAction(t *testing.T) {
	for _, verb := range domain.AllServiceVerbs() {
		if _, ok := Lookup(verb.Action()); !ok {
			t.Errorf("%s: no catalog action %q", verb, verb.Action())
		}
	}
}

func TestRiskFor_UnknownActionIsTyped(t *testing.T) {
	_, err := RiskFor("node.explode", nil)
	if !errors.Is(err, smerr.New(smerr.CodeInvalidArgument, smerr.ReasonUnknownAction, "")) {
		t.Fatalf("err = %v, want INVALID_ARGUMENT/UNKNOWN_ACTION", err)
	}
}
