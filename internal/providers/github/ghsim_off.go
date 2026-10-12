//go:build !ghsim

package github

// ghsimCompiled is false in every release build: the OIDC issuer and trusted
// root cannot be overridden.
const ghsimCompiled = false

func ghsimOIDC() (ghsimOverride, error) { return ghsimOverride{}, nil }
