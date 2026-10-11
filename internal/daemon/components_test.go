package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/app"
	"github.com/autarquico/supermgmt/internal/auth"
	"github.com/autarquico/supermgmt/internal/auth/oidc"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

func TestTheBackupScheduleFiresOnlyWhileNoHoldIsInForce(t *testing.T) {
	var fired, reported atomic.Int64
	var held atomic.Bool
	var holdErr atomic.Pointer[error]
	s := &backupSchedule{
		fire: func(context.Context) error { fired.Add(1); return nil },
		held: func(context.Context) (bool, error) {
			if err := holdErr.Load(); err != nil {
				return false, *err
			}
			return held.Load(), nil
		},
		report: func(error) { reported.Add(1) },
	}
	ctx := context.Background()

	s.tick(ctx)
	held.Store(true)
	s.tick(ctx)
	s.tick(ctx)
	held.Store(false)
	s.tick(ctx)
	unreadable := errors.New("unreadable")
	holdErr.Store(&unreadable)
	s.tick(ctx)

	if fired.Load() != 2 {
		t.Errorf("fired %d times, want 2: once before the hold, once after it, none while held or unreadable", fired.Load())
	}
	if reported.Load() != 1 {
		t.Errorf("reported %d failures, want the unreadable hold once", reported.Load())
	}
}

func TestExpiredCredentialsAreSweptAfterTheGraceAndNotBefore(t *testing.T) {
	ctx := context.Background()
	clock := domaintest.NewFakeClock(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "db"), database.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSystemIdentity(ctx, db, clock); err != nil {
		t.Fatal(err)
	}
	session := func(hash string, expires time.Time) {
		t.Helper()
		err := db.WithWriteTx(ctx, func(ctx context.Context, tx *database.Tx) error {
			return database.CreateAuthSession(ctx, tx, database.AuthSession{
				ID: domain.UUIDv7Generator{}.NewID(), IdentityID: SystemIdentityID, TokenHash: hash, Origin: database.OriginOIDC,
				CreatedAt: clock.Now().Add(-72 * time.Hour), ExpiresAt: expires,
			})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	session("long-gone", clock.Now().Add(-2*authGrace))
	session("just-expired", clock.Now().Add(-time.Hour))
	session("live", clock.Now().Add(time.Hour))
	sweep := &authSweep{db: db, now: clock.Now, report: func(err error) { t.Error(err) }}

	sweep.once(ctx)

	var left int
	if err := db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&left); err != nil || left != 2 {
		t.Errorf("sessions left = %d, %v; want the expired-within-grace and the live one", left, err)
	}
}

func TestTheSystemIdentityIsCreatedOnceAndIsAnActiveCredentialHolder(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "db"), database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	clock := domain.SystemClock{}

	for range 2 {
		if err := EnsureSystemIdentity(ctx, db, clock); err != nil {
			t.Fatal(err)
		}
	}

	identity, err := database.GetIdentity(ctx, db.Reader(), SystemIdentityID)
	if err != nil || identity.ActorType != domain.ActorSystem {
		t.Fatalf("identity = %+v, %v", identity, err)
	}
	status := auth.CredentialStatus{DB: db, Clock: clock}
	for _, cred := range []domain.CredentialContext{
		{Kind: domain.CredentialLocalSocket}, {Kind: domain.CredentialLocalSocket, ID: "system"},
	} {
		if state, err := status.Status(ctx, cred); err != nil || state != app.CredentialActive {
			t.Errorf("%+v: %s, %v; scheduled jobs would fail at claim", cred, state, err)
		}
	}
}

type fakeLogin struct{ oidc.Login }

func TestTheLazyLoginKeepsTryingUntilTheIdentityProviderAnswers(t *testing.T) {
	var attempts atomic.Int64
	l := &lazyLogin{build: func(context.Context) (oidc.Login, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("connection refused")
		}
		return fakeLogin{}, nil
	}}
	ctx := context.Background()

	_, _, err := l.Start(ctx, "http://127.0.0.1:1/callback", "challenge")

	if smerr.CodeOf(err) != smerr.CodeProviderError {
		t.Fatalf("first use: %v, want PROVIDER_ERROR", err)
	}
	first, err := l.get(ctx)
	second, _ := l.get(ctx)
	if err != nil || first != second || attempts.Load() != 2 {
		t.Errorf("get = %v, %v after %d attempts; the adapter must be built once it works", first, err, attempts.Load())
	}
}

func TestSecretReferencesParse(t *testing.T) {
	for raw, want := range map[string]secrets.Ref{
		"secret://auth/oidc":   {Name: "auth/oidc"},
		"secret://auth/oidc@3": {Name: "auth/oidc", Version: 3},
	} {
		if got, err := parseSecretRef(raw); err != nil || got != want {
			t.Errorf("%s = %+v, %v; want %+v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "auth/oidc", "file:///x", "secret://", "secret://x@0", "secret://a@b"} {
		if _, err := parseSecretRef(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}
