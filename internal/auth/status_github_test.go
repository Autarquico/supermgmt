package auth

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/domain"
)

func TestGitHubOIDCCredentialsReadAsRevoked(t *testing.T) {
	got, err := CredentialStatus{}.Status(context.Background(), domain.CredentialContext{Kind: domain.CredentialGitHubOIDC, ID: "cred-1"})
	if err != nil || got != app.CredentialRevoked {
		t.Fatalf("Status = %q, %v; want revoked", got, err)
	}
}
