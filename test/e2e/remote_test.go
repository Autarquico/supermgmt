//go:build e2e

package e2e_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// TestM2_RemoteControlOverHTTPS
//
// Criterion S1 (docs/specs/m2-server-auth-release.md, "control remoto autenticado"; PLAN §9 row 1):
// Given a server in server mode with OIDC, when the laptop's sm logs in and operates, then it works
// over authenticated HTTPS. The IdP is Dex on a private docker network address, the server runs
// under systemd in a clean Debian container, once with TLS terminated by `sm server` (direct) and
// once behind a TLS-terminating proxy container (proxy). The first administrator is the Dex user
// who signs in and presents the bootstrap code (spec 11.5).
func TestM2_RemoteControlOverHTTPS(t *testing.T) {
	w := newIdP(t)
	for _, mode := range []harness.TLSMode{harness.Direct, harness.Proxy} {
		t.Run(string(mode), func(t *testing.T) { remoteControl(t, w, mode) })
	}
}

func remoteControl(t *testing.T, w *idp, mode harness.TLSMode) {
	ctx := context.Background()
	op := w.startOperated(t, mode)
	srv := op.srv

	t.Run("the person who signed in and presented the bootstrap code is the administrator and operates", func(t *testing.T) {
		me := whoami(t, srv, op.admin)
		if me.ActorType != domain.ActorHuman || !strings.Contains(strings.Join(me.Roles, ","), "admin") {
			t.Fatalf("who am I = %+v, want a human with the admin role", me)
		}
		operate(t, srv, op.admin)
		if again := srv.Sm(ctx, "", "admin", "bootstrap-code", "--config", harness.ServerConfig); again.Code == 0 {
			t.Fatal("a second bootstrap code was issued although an administrator exists")
		}
	})

	t.Run("another person signed in through the browser has no more than their role allows", func(t *testing.T) {
		laptop := op.person(t)
		me := w.loginWithBrowser(t, srv, laptop, harness.DexOtherUser)
		if res := laptop.Run(ctx, "", "backup", "create"); res.Code == 0 {
			t.Fatalf("a person without a role created a backup: %s", res.Output())
		}
		srv.Sm(ctx, "", "admin", "grant", string(me.IdentityID), "admin", "--config", harness.ServerConfig)
		operate(t, srv, laptop)
	})

	t.Run("the device flow signs in the same person on another machine", func(t *testing.T) {
		other := op.person(t)
		me := w.loginWithDeviceCode(t, srv, other)
		if want := whoami(t, srv, op.admin).IdentityID; me.IdentityID != want {
			t.Fatalf("device login identity %s differs from browser login identity %s", me.IdentityID, want)
		}
		other.Must(ctx, "", "nodes", "list")
	})

	t.Run("logging out revokes the session on the server", func(t *testing.T) {
		laptop := op.person(t)
		w.loginWithBrowser(t, srv, laptop, harness.DexUser)
		session := laptop.StoredToken("ops")
		laptop.Must(ctx, "", "logout")
		if _, err := srv.Typed(session).Me(ctx); err == nil {
			t.Fatal("the session still works after logout")
		}
	})

	t.Run("a revoked token ends the event stream", func(t *testing.T) {
		laptop := op.admin
		created := laptop.Must(ctx, "", "tokens", "create", "--name", "stream", "--expires-in", "1d")
		token := strings.TrimSpace(strings.SplitN(created.Stdout, "\n", 2)[0])
		var listed wire.Page[wire.Token]
		laptop.JSON(ctx, "", &listed, "tokens", "list")
		var tokenID domain.ID
		for _, item := range listed.Items {
			if item.Name == "stream" {
				tokenID = item.ID
			}
		}
		if tokenID == "" {
			t.Fatalf("token stream not listed: %+v", listed)
		}

		watcher := op.person(t)
		watcher.Must(ctx, token+"\n", "login", "--token-stdin")
		follow := watcher.Start(ctx, "", "events", "--follow", "--json")
		// The stream starts "from now": keep causing events until one arrives, so the test does
		// not depend on how fast the follower connects.
		streaming := false
		for i := 0; i < 10 && !streaming; i++ {
			laptop.Must(ctx, "", "tokens", "create", "--name", fmt.Sprintf("marker-%d", i), "--expires-in", "1d")
			streaming = follow.TryLine(regexp.MustCompile(`token`), 3*time.Second)
		}
		if !streaming {
			t.Fatalf("events --follow printed nothing although tokens were created:\n%s", follow.Stderr())
		}

		laptop.Must(ctx, "", "tokens", "revoke", string(tokenID))
		res, err := follow.Wait(90 * time.Second)
		if err != nil {
			t.Fatalf("the stream outlived the revoked token: %v", err)
		}
		if res.Code == 0 {
			t.Fatalf("events --follow exited cleanly after its token was revoked:\n%s", res.Output())
		}
	})

	t.Run("no credential is stored or logged in plaintext", func(t *testing.T) {
		harness.AssertNoPlaintext(t, srv.Evidence(ctx), map[string]string{
			"the IdP client secret": w.dex.ClientSecret, "the administrator's session": op.admin.StoredToken("ops"),
		})
	})
}

// operate does what an administrator does from a laptop: list nodes, create a token, back up.
func operate(t *testing.T, srv *harness.Server, laptop *harness.Client) {
	t.Helper()
	ctx := context.Background()
	laptop.Must(ctx, "", "nodes", "list")

	created := laptop.Must(ctx, "", "tokens", "create", "--name", "ci", "--expires-in", "30d")
	if token := strings.TrimSpace(strings.SplitN(created.Stdout, "\n", 2)[0]); !strings.HasPrefix(token, "smt_") {
		t.Fatalf("tokens create printed %q, want an smt_ token", token)
	}

	var submitted wire.Submission
	laptop.JSON(ctx, "", &submitted, "backup", "create")
	harness.WaitJob(ctx, t, srv.Typed(laptop.StoredToken("ops")), jobOf(t, submitted), domain.JobSucceeded)
	var backups wire.Page[wire.Backup]
	laptop.JSON(ctx, "", &backups, "backup", "list")
	if len(backups.Items) == 0 {
		t.Fatal("backup list is empty after a successful backup")
	}
}
