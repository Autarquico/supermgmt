package app

import (
	"context"
	"errors"
	"testing"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
)

func TestLocalSocketCredentialsAreAlwaysActive(t *testing.T) {
	state, err := LocalSocketCredentials{}.Status(context.Background(), domain.CredentialContext{Kind: domain.CredentialLocalSocket})

	if err != nil || state != CredentialActive {
		t.Fatalf("Status = %q, %v; want active", state, err)
	}
}

func TestLocalSocketCredentialsRefuseKindsWithoutAStore(t *testing.T) {
	for _, kind := range []domain.CredentialKind{
		domain.CredentialSession, domain.CredentialAPIToken, domain.CredentialMCPToken,
		domain.CredentialOAuthAccessToken, domain.CredentialGitHubOIDC,
	} {
		_, err := LocalSocketCredentials{}.Status(context.Background(), domain.CredentialContext{Kind: kind})

		wantError(t, err, smerr.CodeUnauthenticated, "")
	}
}

func TestStateErrorMapsEveryStateAndFailsClosedOnUnknownOnes(t *testing.T) {
	tests := []struct {
		state  CredentialState
		code   smerr.Code
		reason smerr.Reason
	}{
		{CredentialRevoked, smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked},
		{CredentialExpired, smerr.CodeUnauthenticated, smerr.ReasonCredentialExpired},
		{"suspended", smerr.CodeUnauthenticated, ""},
	}
	if err := stateError(CredentialActive); err != nil {
		t.Errorf("active credential: %v", err)
	}
	for _, tt := range tests {
		wantError(t, stateError(tt.state), tt.code, tt.reason)
	}
}

func TestACredentialLookupFailureIsNotMistakenForARevocation(t *testing.T) {
	broken := errors.New("disk on fire")
	f := newFixture(t, func(c *Config) { c.Credentials = failingCredentials{broken} })

	err := f.plans.requireStillValid(context.Background(), domain.CredentialContext{Kind: domain.CredentialAPIToken})

	if !errors.Is(err, broken) || !errors.Is(err, jobs.ErrInfrastructure) || isTyped(err) {
		t.Fatalf("err = %v, want the lookup failure marked as infrastructure", err)
	}
}

type failingCredentials struct{ err error }

func (f failingCredentials) Status(context.Context, domain.CredentialContext) (CredentialState, error) {
	return "", f.err
}

func TestNewServicesRejectIncompleteConfig(t *testing.T) {
	f := newFixture(t)
	incomplete := []func(*Config){
		func(c *Config) { c.DB = nil },
		func(c *Config) { c.Clock = nil },
		func(c *Config) { c.IDs = nil },
		func(c *Config) { c.Policy = nil },
		func(c *Config) { c.Credentials = nil },
	}
	for i, breakIt := range incomplete {
		cfg := f.cfg
		breakIt(&cfg)
		if _, err := NewRevalidator(cfg); err == nil {
			t.Errorf("case %d: NewRevalidator accepted an incomplete config", i)
		}
		if _, err := NewPlans(cfg, f.store); err == nil {
			t.Errorf("case %d: NewPlans accepted an incomplete config", i)
		}
		if _, err := NewApprovals(cfg, f.store); err == nil {
			t.Errorf("case %d: NewApprovals accepted an incomplete config", i)
		}
	}
	if _, err := NewPlans(f.cfg, nil); err == nil {
		t.Error("NewPlans accepted a nil store")
	}
	if _, err := NewApprovals(f.cfg, nil); err == nil {
		t.Error("NewApprovals accepted a nil store")
	}
}
