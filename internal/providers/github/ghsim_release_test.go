//go:build !ghsim

package github

import (
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
)

// A build without the ghsim tag is what ships: whatever the environment says,
// the OIDC issuer stays GitHub's.
func TestReleaseBuildHasNoGhsim(t *testing.T) {
	if ghsimCompiled {
		t.Fatal("ghsim is compiled into a build without the ghsim tag")
	}
	t.Setenv("SM_GHSIM_OIDC_ISSUER", "https://evil.example")
	t.Setenv("SM_GHSIM_OIDC_CA_FILE", "/nonexistent")

	v, err := NewOIDCVerifier(OIDCConfig{
		Audience: "https://sm.example", Clock: domaintest.NewFakeClock(oidcNow), Replay: &oidcMemoryReplay{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(*oidcVerifier).issuer; got != ActionsIssuer {
		t.Errorf("issuer = %q, want %q", got, ActionsIssuer)
	}
}
