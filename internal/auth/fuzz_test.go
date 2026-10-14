package auth_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
)

// fuzzMigratedDB is an empty migrated database whose clock is fixed at epoch.
// It takes a testing.TB because fuzz targets build their fixtures once, before
// f.Fuzz, where only *testing.F is at hand.
func fuzzMigratedDB(tb testing.TB) (*database.DB, *domaintest.FakeClock) {
	tb.Helper()
	ctx := context.Background()
	clock := domaintest.NewFakeClock(epoch)
	db, err := database.Open(ctx, filepath.Join(tb.TempDir(), "sm.db"), database.Options{Clock: clock})
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		tb.Fatalf("Migrate: %v", err)
	}
	return db, clock
}

// fuzzRefusingVerifier is the Actions verifier of a deployment whose every
// token is bad: the resolver chain, not the verifier, is under test here.
type fuzzRefusingVerifier struct{}

func (fuzzRefusingVerifier) Verify(context.Context, string) (github.Claims, error) {
	return github.Claims{}, smerr.New(smerr.CodeUnauthenticated, "", "invalid token")
}

// fuzzWantRefusal fails unless err is a typed refusal that carries no caller.
func fuzzWantRefusal(t *testing.T, caller app.Caller, err error) {
	t.Helper()
	var typed *smerr.Error
	if !errors.As(err, &typed) {
		t.Fatalf("error %v is not a typed smerr error", err)
	}
	if caller.ID != "" {
		t.Fatalf("a refused bearer produced caller %+v", caller)
	}
}

// Any bearer of an HTTPS request or of the MCP socket is refused with a typed
// error, since nothing is registered; Hash agrees on what is well formed.
func FuzzBearer(f *testing.F) {
	db, clock := fuzzMigratedDB(f)
	bearers := auth.BearerResolver{
		Tokens: auth.DBResolver{DB: db, Clock: clock},
		GitHub: auth.GitHubResolver{DB: db, Verifier: fuzzRefusingVerifier{}, Clock: clock},
	}
	socket := auth.MCPResolver{DB: db, Clock: clock, Enabled: true}
	minted, _, err := auth.Mint(auth.KindMCP)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"", "sm", "sms_", "smm_", minted.Reveal(), "smt_" + strings.Repeat("A", 60), "smb_" + strings.Repeat("-", 60),
		"smj_" + strings.Repeat("0", 60), "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln", "eyJ..", "eyJ.a.b.c", "Bearer x", "\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, bearer string) {
		kind, hash, hashErr := auth.Hash(bearer)
		if hashErr == nil && (len(hash) != 64 || !strings.HasPrefix(bearer, "sm"+string(rune(kind))+"_")) {
			t.Fatalf("Hash accepted %q as kind %q with hash %q", bearer, string(rune(kind)), hash)
		}
		ctx := context.Background()
		caller, err := bearers.Resolve(ctx, bearer)
		if err == nil {
			t.Fatalf("an unregistered bearer %q was admitted as %+v", bearer, caller)
		}
		fuzzWantRefusal(t, caller, err)
		caller, err = socket.Resolve(ctx, bearer)
		if err == nil {
			t.Fatalf("an unregistered mcp bearer %q was admitted as %+v", bearer, caller)
		}
		fuzzWantRefusal(t, caller, err)
	})
}
