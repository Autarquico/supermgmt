package app

import (
	"context"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

func TestTheDialerReadsTheRuntimeServiceTokenFromTheStoreAtDialTime(t *testing.T) {
	store := newMemSecrets()
	source := AccessTokens(store, testAccessToken)

	_, err := source.AccessToken(context.Background())
	if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Fatalf("missing token: %v, want CAPABILITY_UNAVAILABLE", err)
	}

	_, _ = store.Put(context.Background(), "cloudflare/access-service-token", audit.Secret("id-1:secret-1"), nil)
	token, err := source.AccessToken(context.Background())
	if err != nil || token.ClientID != "id-1" || token.ClientSecret.Reveal() != "secret-1" {
		t.Fatalf("token = %+v, %v", token, err)
	}

	_, _ = store.Put(context.Background(), "cloudflare/access-service-token", audit.Secret("id-2:secret-2"), nil)
	if token, _ = source.AccessToken(context.Background()); token.ClientID != "id-2" {
		t.Errorf("client id = %q: a rotated token must be used by the next dial", token.ClientID)
	}
}

func TestACredentialReferenceThatIsNotASecretIsRefused(t *testing.T) {
	if _, err := AccessTokens(newMemSecrets(), "env://X").AccessToken(context.Background()); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("err = %v, want INVALID_ARGUMENT", err)
	}
}
