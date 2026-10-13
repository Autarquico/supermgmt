package github

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
)

// The webhook endpoint is public: an unsigned body is never interpreted and a
// signed one reduces to a well-formed event or an error.
func FuzzVerifyWebhook(f *testing.F) {
	for _, body := range []string{
		`{"check_run":{"head_sha":"` + commitA + `"},"repository":{"id":42}}`,
		`{"zen":"hi","repository":{"id":42}}`,
		`{"check_suite":{"head_sha":"zz"},"repository":{"id":-1}}`,
		`[`, ``, `null`,
	} {
		f.Add([]byte(body), true)
		f.Add([]byte(body), false)
	}
	f.Fuzz(func(t *testing.T, body []byte, signed bool) {
		signature := "sha256=" + strings.Repeat("0", 64)
		if signed {
			signature = webhookSign(webhookSecret, body)
		}
		event, err := VerifyWebhook(webhookSecret, signature, body)
		switch {
		case err != nil && event != (WebhookEvent{}):
			t.Fatalf("event %+v returned with error %v", event, err)
		case err != nil:
		case !signed:
			t.Fatalf("an unsigned body produced %+v", event)
		case event.Type != "" && (event.RepositoryID <= 0 || !commitPattern.MatchString(event.HeadSHA)):
			t.Fatalf("malformed event accepted: %+v", event)
		}
	})
}

// MatchClaims never panics, and a pull_request* token never matches.
func FuzzMatchClaims(f *testing.F) {
	f.Add("push", "refs/heads/main", "acme/shop/.github/workflows/ci.yml@refs/heads/main", "", "production", oidcCommit, int64(123), int64(555))
	f.Add("pull_request_target", "refs/heads/main", "", "x", "", "", int64(0), int64(0))
	f.Fuzz(func(t *testing.T, event, ref, workflowRef, jobWorkflowRef, environment, sha string, repositoryID, runID int64) {
		claims := oidcMatchable()
		claims.EventName, claims.Ref, claims.WorkflowRef, claims.JobWorkflowRef = event, ref, workflowRef, jobWorkflowRef
		claims.Environment, claims.SHA, claims.RepositoryID, claims.RunID = environment, sha, repositoryID, runID
		policy := oidcPolicy()
		policy.AllowedEvents = []string{event, "push"}
		err := MatchClaims(claims, policy, sha, EnvRequirement{Required: environment != "", Name: environment})
		if err == nil && strings.HasPrefix(event, "pull_request") {
			t.Fatalf("a %s token matched the policy", event)
		}
	})
}

// A hostile Actions token is refused; an accepted one carries the registered
// claims the verifier promises. The issuer runs in process.
func FuzzActionsOIDCToken(f *testing.F) {
	issuer := ghfake.NewOIDCIssuer(oidcFuzzTB{f})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(issuer.CAPEM()) {
		f.Fatal("no certificate in CA PEM")
	}
	verifier, err := newOIDCVerifier(issuer.Issuer(),
		OIDCConfig{Audience: oidcAudience, Clock: domaintest.NewFakeClock(oidcNow), Replay: &oidcMemoryReplay{}, Timeout: testTimeout},
		netguard.WithTestDialer(issuer.Dial), netguard.WithRootCAs(pool))
	if err != nil {
		f.Fatal(err)
	}
	valid := map[string]any{
		"iss": issuer.Issuer(), "aud": oidcAudience, "sub": "repo:acme/shop:ref:refs/heads/main", "jti": "seed",
		"iat": oidcNow.Unix(), "exp": oidcNow.Unix() + 300,
		"repository_id": "123", "repository_owner_id": "987", "repository": "acme/shop",
		"ref": "refs/heads/main", "sha": oidcCommit, "event_name": "push",
		"workflow_ref": "acme/shop/.github/workflows/ci.yml@refs/heads/main", "run_id": "555", "run_attempt": "2",
	}
	validJSON, err := json.Marshal(valid)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("", string(validJSON))
	f.Add("", "{}")
	f.Add("eyJhbGciOiJSUzI1NiJ9.e30.c2ln", "")
	f.Add("a.b.c", "")
	f.Add(ghfake.UnsignedToken(valid), "")
	f.Fuzz(func(t *testing.T, raw, claimsJSON string) {
		if raw == "" {
			var claims map[string]any
			if json.Unmarshal([]byte(claimsJSON), &claims) != nil {
				return
			}
			raw = issuer.Sign(claims)
		}
		got, err := verifier.Verify(context.Background(), raw)
		if err != nil {
			return
		}
		if got.Issuer != issuer.Issuer() || got.RepositoryID <= 0 || got.RunID <= 0 || got.JTI == "" || !got.ExpiresAt.After(oidcNow) {
			t.Fatalf("accepted claims violate the registered rules: %+v", got)
		}
	})
}

// oidcFuzzTB lets the issuer sign inside a fuzz callback, where *testing.F
// refuses Helper.
type oidcFuzzTB struct{ testing.TB }

func (oidcFuzzTB) Helper() {}
