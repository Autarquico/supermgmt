//go:build e2e

package e2e_test

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// Tests in this file are written against the specified behavior and fail on the current product
// code. They are skipped (SM_E2E_RUN_KNOWN_BUGS=1 runs them) and reported to the architect; the
// owner of the product code removes the knownBug line when the defect is fixed.

// TestM2_LoginBootstrapWithoutOIDC
//
// Criterion S1 / spec §11.5 (PLAN §9 "Fresh server bootstrap"): on a server without OIDC,
// `sm admin bootstrap-code` followed by `sm login --bootstrap` creates the first administrator and
// stores a working session.
func TestM2_LoginBootstrapWithoutOIDC(t *testing.T) {
	knownBug(t, "BUG-2", "`sm login --bootstrap` never sends display_name (internal/cli/login.go bootstrapLogin builds "+
		"wire.BootstrapRequest{Code: code}), and without OIDC the server requires it (internal/app/auth.go:400): "+
		"the exchange fails with \"display_name is required\". Repro: install a server without OIDC, `sm admin bootstrap-code`, `sm login --bootstrap`.")
	ctx := context.Background()
	srv := harness.StartServer(t, harness.NewNetwork(t), harness.NewCA(t), harness.ServerOptions{Mode: harness.Direct})
	laptop := harness.NewClient(t)
	laptop.AddProfile(ctx, "fresh", srv.URL, srv.CAFile)
	laptop.Must(ctx, srv.IssueBootstrapCode(ctx)+"\n", "login", "--bootstrap")
	laptop.Must(ctx, "", "nodes", "list")
}

// TestM2_BootstrapBindsOIDCIdentity
//
// Criterion S1 / spec §11.5: on a fresh server with OIDC, the person who signs in with the IdP and
// presents the bootstrap code becomes the administrator. The client secret has to exist before any
// administrator does, and the only way to store it is `sm secrets import`, an authenticated
// high-risk job; the offline form the spec lists (§2.1.1, §3.5 step 5) is not implemented.
func TestM2_BootstrapBindsOIDCIdentity(t *testing.T) {
	knownBug(t, "BUG-3", "`sm secrets import --offline` (spec §2.1.1) does not exist, so a fresh server cannot be given its OIDC "+
		"client secret before the first administrator; the OIDC-bound bootstrap of spec §11.5 is unreachable from the CLI. "+
		"Repro: install a server, stop it, run `sm secrets import --offline --name auth/oidc-client --from-file F` as the service user.")
	ctx := context.Background()
	srv := harness.StartServer(t, harness.NewNetwork(t), harness.NewCA(t), harness.ServerOptions{Mode: harness.Direct})
	srv.C.MustExec(ctx, "systemctl", "stop", "supermgmt")
	srv.C.WriteFile(ctx, "/var/lib/supermgmt/client-secret", []byte("client secret\n"), "0600")
	srv.C.MustExec(ctx, "chown", "supermgmt:supermgmt", "/var/lib/supermgmt/client-secret")
	res := srv.C.Exec(ctx, "", "runuser", "-u", "supermgmt", "--", harness.ServerBinary, "secrets", "import", "--offline",
		"--name", harness.OIDCSecretName, "--from-file", "/var/lib/supermgmt/client-secret", "--config", harness.ServerConfig)
	if res.Code != 0 {
		t.Fatalf("sm secrets import --offline exited %d\n%s", res.Code, res.Output())
	}
}
