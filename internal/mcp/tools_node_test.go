package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const scannedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIScanned"

func (f *serverFakeAPI) ScanHostKey(_ context.Context, r wire.ScanHostKeyRequest) (wire.HostKey, error) {
	f.scans = append(f.scans, r)
	return f.scanned, f.scanErr
}

func (f *serverFakeAPI) AddSSHNode(_ context.Context, r wire.AddSSHNodeRequest) (wire.Direct[wire.Node], error) {
	f.addNodes = append(f.addNodes, r)
	return f.added, f.submitErr
}

func nodeFake() *serverFakeAPI {
	api := newServerFakeAPI()
	api.scanned = wire.HostKey{AuthorizedKey: scannedKey, Type: "ssh-ed25519", FingerprintSHA256: "SHA256:abc"}
	api.added = wire.Direct[wire.Node]{Pending: &api.routeSubmission.Submission}
	return api
}

func TestAddNode_PinsTheKeyTheDaemonScannedAndWaitsForApproval(t *testing.T) {
	api := nodeFake()
	out := writeSession(t, api)("infra_add_node", map[string]any{
		"name": "edge-1", "host": "10.0.0.5", "port": 2222, "admin_user": "root", "admin_credential_ref": "secret://ssh/admin",
	})

	if len(api.scans) != 1 || api.scans[0] != (wire.ScanHostKeyRequest{Host: "10.0.0.5", Port: 2222}) {
		t.Fatalf("scans = %+v", api.scans)
	}
	want := wire.AddSSHNodeRequest{
		Name: "edge-1", Host: "10.0.0.5", Port: 2222, AdminUser: "root",
		HostPublicKey: scannedKey, AdminCredentialRef: "secret://ssh/admin",
	}
	if len(api.addNodes) != 1 || api.addNodes[0].HostPublicKey != want.HostPublicKey || api.addNodes[0].Name != want.Name ||
		api.addNodes[0].AdminCredentialRef != want.AdminCredentialRef || api.addNodes[0].CredentialRef != "" {
		t.Fatalf("add = %+v, want %+v", api.addNodes, want)
	}
	if out["status"] != "approval_required" || out["job_id"] != string(serverJobID) {
		t.Errorf("result = %v", out)
	}
}

func TestAddNode_HasNoKeyFingerprintOrCredentialFileArgument(t *testing.T) {
	for _, tool := range listedTools(t, serverSession(t, nodeFake(), true)) {
		if tool.Name != "infra_add_node" {
			continue
		}
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"host_public_key", "host_key", "fingerprint", "credential_ref", "tunnel"} {
			if _, found := schema.Properties[banned]; found {
				t.Errorf("infra_add_node offers %s", banned)
			}
		}
		return
	}
	t.Fatal("infra_add_node is not registered")
}

func TestAddNode_AScanFailureSurfacesAndNothingIsAdded(t *testing.T) {
	api := nodeFake()
	api.scanErr = smerr.New(smerr.CodeNodeUnreachable, "", "connection refused")
	result := callReadTool(t, serverSession(t, api, true), "infra_add_node", map[string]any{"name": "n", "host": "h.example.com", "admin_user": "root"})
	if !result.IsError || len(api.addNodes) != 0 {
		t.Errorf("error=%v adds=%v", result.IsError, api.addNodes)
	}
}

func TestAddNode_APolicyDeniedScanIsADeniedResultNamingTheReason(t *testing.T) {
	api := nodeFake()
	api.scanErr = smerr.New(smerr.CodePolicyDenied, smerr.ReasonMCPWritesDisabled, "denied")
	out := writeSession(t, api)("infra_add_node", map[string]any{"name": "n", "host": "h.example.com", "admin_user": "root"})
	if out["status"] != "denied" || len(api.addNodes) != 0 {
		t.Fatalf("result = %v adds=%v", out, api.addNodes)
	}
	if summary, _ := out["summary"].(string); summary != "policy denied node.add: MCP_WRITES_DISABLED" {
		t.Errorf("summary = %q", summary)
	}
}

func TestAddNode_ARefusedAddSurfacesAsAToolError(t *testing.T) {
	api := nodeFake()
	api.submitErr = smerr.New(smerr.CodeInvalidArgument, "", "admin_credential_ref must be a secret:// reference")
	result := callReadTool(t, serverSession(t, api, true), "infra_add_node", map[string]any{
		"name": "n", "host": "h.example.com", "admin_user": "root", "admin_credential_ref": "file:///etc/key",
	})
	if !result.IsError {
		t.Error("a refused add was reported as success")
	}
}

func TestSetupNode_SendsOnlySafeParametersAndWaitsForApproval(t *testing.T) {
	api := nodeFake()
	api.plan.Plan = json.RawMessage(`{"action":"node.setup","risk":"high"}`)
	out := writeSession(t, api)("infra_setup_node", map[string]any{"node": "web-1", "tunnel": true})

	if len(api.planRequests) != 1 {
		t.Fatalf("plans = %+v", api.planRequests)
	}
	req := api.planRequests[0]
	wantParams := map[string]any{"docker_access": "false", "logs_mode": "journal-group", "tunnel": "true"}
	if req.Action != "node.setup" || len(req.Parameters) != len(wantParams) || req.Targets[0].ID != readNodeID {
		t.Fatalf("request = %+v", req)
	}
	for k, v := range wantParams {
		if req.Parameters[k] != v {
			t.Errorf("parameter %s = %v, want %v", k, req.Parameters[k], v)
		}
	}
	if len(api.submits) != 1 || out["status"] != "approval_required" {
		t.Errorf("submits=%v result=%v", api.submits, out)
	}
}

func TestSetupNode_WithoutTunnelSendsNoTunnelParameter(t *testing.T) {
	api := nodeFake()
	writeSession(t, api)("infra_setup_node", map[string]any{"node": string(readNodeID)})
	if _, has := api.planRequests[0].Parameters["tunnel"]; has {
		t.Errorf("parameters = %v", api.planRequests[0].Parameters)
	}
}

func TestSetupNode_ARefusedPlanSurfacesAndIsNotSubmitted(t *testing.T) {
	api := nodeFake()
	api.planErr = smerr.New(smerr.CodeInvalidArgument, "", "refused")
	result := callReadTool(t, serverSession(t, api, true), "infra_setup_node", map[string]any{"node": "web-1"})
	if !result.IsError || len(api.submits) != 0 {
		t.Errorf("error=%v submits=%v", result.IsError, api.submits)
	}
}

func TestSetupNode_DescriptionNamesBothActionsTheRuleMustGrant(t *testing.T) {
	for _, tool := range listedTools(t, serverSession(t, nodeFake(), true)) {
		if tool.Name != "infra_setup_node" {
			continue
		}
		for _, want := range []string{"node.setup", "sudoers.write"} {
			if !strings.Contains(tool.Description, want) {
				t.Errorf("description does not name %s: %q", want, tool.Description)
			}
		}
		return
	}
	t.Fatal("infra_setup_node is not registered")
}
