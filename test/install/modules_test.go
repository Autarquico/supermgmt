package install_test

import (
	"os"
	"strings"
	"testing"
)

// Spec retire-deployments, scenario "the build is smaller": after go mod tidy
// the deployment and GitHub-attestation stacks are not required, and go-oidc
// stays for MCP OAuth.
func TestTheModuleGraphNoLongerRequiresTheDeploymentStack(t *testing.T) {
	for _, file := range []string{"go.mod", "go.sum"} {
		raw, err := os.ReadFile("../../" + file)
		if err != nil {
			t.Fatal(err)
		}
		for _, retired := range []string{
			"github.com/compose-spec/compose-go",
			"github.com/sigstore/sigstore-go",
			"github.com/theupdateframework/go-tuf",
			"github.com/google/go-containerregistry",
			"github.com/sigstore/protobuf-specs",
			"github.com/secure-systems-lab/go-securesystemslib",
			"github.com/opencontainers/go-digest",
		} {
			if strings.Contains(string(raw), retired) {
				t.Errorf("%s still mentions %s", file, retired)
			}
		}
	}
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mod), "github.com/coreos/go-oidc/v3") {
		t.Error("go.mod lost go-oidc, which MCP OAuth needs")
	}
}
