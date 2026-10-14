package mcp_test

import (
	"slices"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestSDK_ProtocolVersionsAreTheOnesADR0031Records pins the protocol versions
// of the pinned SDK (v1.8.0). An SDK upgrade that changes them is an ADR-0031
// and ADR-0033 amendment, not a silent change.
func TestSDK_ProtocolVersionsAreTheOnesADR0031Records(t *testing.T) {
	want := []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	if got := sdk.SupportedProtocolVersions(); !slices.Equal(got, want) {
		t.Errorf("SDK protocol versions = %v, ADR-0031 records %v", got, want)
	}
}
