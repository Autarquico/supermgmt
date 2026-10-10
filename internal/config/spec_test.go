package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// asProviderList indents a provider mapping into a one-item `providers:` list.
func asProviderList(block string) string {
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	for i, l := range lines {
		prefix := "    "
		if i == 0 {
			prefix = "  - "
		}
		lines[i] = prefix + l
	}
	return "providers:\n" + strings.Join(lines, "\n") + "\n"
}

func TestSpecMasterExampleLoads(t *testing.T) {
	res, err := Load(filepath.Join("testdata", "spec-8.2.yaml"), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := res.Config
	if c.Instance.Mode != ModeServer || c.Server.Listen != "127.0.0.1:8787" || c.Jobs.ReconcileGrace.String() != "45s" {
		t.Errorf("spec example decoded wrongly: %+v", c.Instance)
	}
	if got := c.Security.AllowSelfApproval; got == nil || *got {
		t.Errorf("allow_self_approval = %v, the example sets false", got)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestExampleConfigIsTheSpecExample(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "examples", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(example) != readTestdata(t, "spec-8.2.yaml") {
		t.Error("examples/config.yaml differs from the spec §8.2 example in testdata")
	}
	if _, err := Load(filepath.Join("..", "..", "examples", "config.yaml"), nil); err != nil {
		t.Errorf("examples/config.yaml does not load: %v", err)
	}
}

func TestSpecEnvironmentsExampleLoads(t *testing.T) {
	res := mustLoad(t, localDoc+readTestdata(t, "spec-8.2.1.yaml"))
	envs := res.Config.Environments
	if len(envs) != 1 || envs[0].Name != "production" || !envs[0].RequireProvenance || envs[0].ApprovalsRequired != 1 {
		t.Errorf("environments = %+v", envs)
	}
}

func TestEnvironmentApprovalsRequiredDefaultsToOne(t *testing.T) {
	res := mustLoad(t, localDoc+"environments:\n  - {name: dev, risk_level: development}\n")
	if got := res.Config.Environments[0].ApprovalsRequired; got != 1 {
		t.Errorf("approvals_required = %d, want 1 when absent", got)
	}
	if _, err := load(t, localDoc+"environments:\n  - {name: dev, risk_level: development, approvals_required: 0}\n"); err == nil {
		t.Error("an explicit approvals_required: 0 must be rejected")
	}
}

func TestSpecProviderExamples(t *testing.T) {
	tests := []struct {
		file    string
		mode    string
		wantErr string // "" means valid
	}{
		{"spec-8.3-proxmox.yaml", serverDoc, ""},
		{"spec-8.3-ssh-local.yaml", localDoc, ""},
		{"spec-8.3-ssh-server.yaml", serverDoc, ""},
		{"spec-8.3-ssh-local.yaml", serverDoc, "ssh-agent:// is not allowed in server mode"},
	}
	for _, tt := range tests {
		t.Run(tt.file+" in "+strings.Fields(tt.mode)[len(strings.Fields(tt.mode))-1], func(t *testing.T) {
			_, err := load(t, tt.mode+asProviderList(readTestdata(t, tt.file)))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("want valid, got %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSSHNodeDefaults(t *testing.T) {
	minimal := "providers:\n  - type: ssh\n    name: n\n    endpoint: {host: h, admin_user: alex}\n"
	tests := []struct {
		mode      string
		wantAdmin string
	}{
		{localDoc, DefaultAdminCredentialRef},
		{serverDoc, ""},
	}
	for _, tt := range tests {
		ssh := mustLoad(t, tt.mode+minimal).Config.Providers[0].SSH
		if ssh.Endpoint.User != "supermgmt" || ssh.Endpoint.Port != 22 || ssh.CredentialRef != "secret://ssh/default" {
			t.Errorf("defaults = %+v, want user supermgmt, port 22, credential secret://ssh/default", ssh)
		}
		if ssh.AdminCredentialRef != tt.wantAdmin {
			t.Errorf("admin_credential_ref = %q, want %q", ssh.AdminCredentialRef, tt.wantAdmin)
		}
	}
	if _, err := load(t, localDoc+"providers:\n  - type: ssh\n    name: n\n    endpoint: {host: h}\n"); err == nil ||
		!strings.Contains(err.Error(), "providers[0].endpoint.admin_user") {
		t.Errorf("an SSH node without admin_user must be rejected, got %v", err)
	}
}
