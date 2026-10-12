//go:build ghsim

package github

import (
	"fmt"
	"os"
)

// ghsimCompiled is true only under the ghsim build tag, used by the e2e
// binary. Release binaries never carry it.
const ghsimCompiled = true

const (
	ghsimIssuerEnv = "SM_GHSIM_OIDC_ISSUER"
	ghsimCAFileEnv = "SM_GHSIM_OIDC_CA_FILE"
)

// ghsimOIDC reads the simulated issuer and its CA from the environment. An
// unset issuer means the real Actions issuer.
func ghsimOIDC() (ghsimOverride, error) {
	issuer := os.Getenv(ghsimIssuerEnv)
	if issuer == "" {
		return ghsimOverride{}, nil
	}
	override := ghsimOverride{issuer: issuer}
	if path := os.Getenv(ghsimCAFileEnv); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return ghsimOverride{}, fmt.Errorf("github: read %s: %w", ghsimCAFileEnv, err)
		}
		override.caPEM = pem
	}
	return override, nil
}
