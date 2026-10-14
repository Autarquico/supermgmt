package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/database"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// restoreRevokesAllCredentials does what a restore's neutralization does.
func (r *oauthJWTRig) restoreRevokesAllCredentials() {
	r.t.Helper()
	must(r.t, r.db.WithWriteTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		_, err := database.RevokeAllCredentials(ctx, tx, r.clock.Now())
		return err
	}), "revoke all credentials")
}

func TestOAuthRestore_RefusesTokensIssuedBeforeItEvenIfTheDatabaseNeverRecordedThem(t *testing.T) {
	r := newOAuthJWTRig(t)
	seen := r.token(nil)
	must(t, r.resolve(seen), "token presented before the backup")
	unseen := r.token(nil) // issued before the restore, never presented

	r.clock.Advance(time.Minute)
	r.restoreRevokesAllCredentials()

	r.wantRefused(r.resolve(seen), smerr.CodeUnauthenticated, smerr.ReasonCredentialRevoked)
	r.wantRefused(r.resolve(unseen), smerr.CodeUnauthenticated, smerr.ReasonOAuthTokenInvalid)
	must(t, r.resolve(r.token(nil)), "token issued at the restore")
}
