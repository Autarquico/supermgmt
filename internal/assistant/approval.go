package assistant

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/autarquico/supermgmt/internal/domain"
)

// writeTools are the MCP tools whose result is a WriteResult (internal/mcp
// tools_write.go and its siblings). Read tools embed remote text in their
// output and so can never open an approval.
var writeTools = map[string]bool{
	"infra_add_node": true, "infra_setup_node": true, "infra_submit_plan": true,
	"infra_start_service": true, "infra_stop_service": true, "infra_restart_service": true,
	"infra_shutdown_node": true, "infra_reboot_node": true, "infra_probe_node": true,
	"infra_power_guest": true, "infra_snapshot_guest": true, "infra_create_backup": true,
	"infra_refresh_provider": true, "infra_cancel_job": true, "infra_disable_tunnel": true,
	"infra_rotate_cloudflare_access_token": true, "infra_expose_port": true, "infra_unexpose_port": true,
}

const statusApprovalRequired = "approval_required"

func isWriteTool(name string) bool {
	tool, ok := strings.CutPrefix(name, mcpToolPrefix)
	return ok && writeTools[tool]
}

// approvalSignal reads the text of one tool result of toolName. It returns a
// signal only for a known write tool whose whole text is one JSON object with
// status approval_required and a valid job id. No substring search.
func approvalSignal(toolName, text string) (Signal, bool) {
	if !isWriteTool(toolName) {
		return Signal{}, false
	}
	var result struct {
		Status string `json:"status"`
		JobID  string `json:"job_id"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	if err := dec.Decode(&result); err != nil {
		return Signal{}, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Signal{}, false
	}
	if result.Status != statusApprovalRequired {
		return Signal{}, false
	}
	id, err := domain.ParseID(result.JobID)
	if err != nil {
		return Signal{}, false
	}
	return Signal{JobID: id, Tool: strings.TrimPrefix(toolName, mcpToolPrefix)}, true
}
