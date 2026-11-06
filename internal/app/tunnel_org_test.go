package app

import (
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// A new fake organisation has the Cloudflare login and no One-time PIN, as an account created after June 2026.
func TestATunnelSetupOnANewOrganisationWithoutIdentityProvidersFailsBeforeCreatingTheAccessApplication(t *testing.T) {
	ts := newTunnelSetting(t)
	ts.handler.tunnel.opts.Config.AccessIdentityProviders = nil
	ts.plan()

	err := ts.attempt()

	if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable || err == nil ||
		!strings.Contains(err.Error(), "One-time PIN in Zero Trust") || !strings.Contains(err.Error(), "access_identity_providers") {
		t.Fatalf("setup = %v, want the actionable One-time PIN error", err)
	}
	if apps := ts.cf.Snapshot().Apps; len(apps) != 0 {
		t.Errorf("%d Access applications created, want none", len(apps))
	}
}
