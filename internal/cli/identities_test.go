package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const identityID = "0198a3b4-0000-7000-8000-000000000001"

var identityEpoch = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

func fakeIdentities() wire.Page[wire.Identity] {
	disabled := identityEpoch.Add(time.Hour)
	return wire.Page[wire.Identity]{NextCursor: "next-1", Items: []wire.Identity{
		{ID: identityID, ActorType: "human", DisplayName: "Ada", Roles: []string{"admin"}, CreatedAt: identityEpoch},
		{ID: "0198a3b4-0000-7000-8000-000000000002", ActorType: "human", DisplayName: "Bob", Roles: []string{}, CreatedAt: identityEpoch, DisabledAt: &disabled},
	}}
}

func TestIdentitiesListShowsStateRolesAndHintsAtTheNextPage(t *testing.T) {
	api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, fakeIdentities()) })

	r := api.run("identities", "list", "--limit", "2", "--cursor", "c0")

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"Ada", "enabled", "admin", "Bob", "disabled", "more results: --cursor next-1"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
	got := api.Requests()
	if len(got) != 1 || got[0].Path != wire.PathIdentities || got[0].Query != "cursor=c0&limit=2" {
		t.Errorf("requests = %+v, want one GET of the identities with the page flags", got)
	}
}

func TestIdentitiesDisablePostsToTheIdentityAndSaysCredentialsAreGone(t *testing.T) {
	api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		disabled := identityEpoch
		reply(w, http.StatusOK, wire.Identity{ID: identityID, DisabledAt: &disabled, Roles: []string{}})
	})

	r := api.run("identities", "disable", identityID)

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "disabled identity "+identityID) || !strings.Contains(r.stdout, "revoked") {
		t.Errorf("output = %q, want the identity and that its credentials were revoked", r.stdout)
	}
	got := api.Mutations()
	if len(got) != 1 || got[0].Method != http.MethodPost || got[0].Path != wire.Path(wire.PathIdentityDisable, identityID) {
		t.Errorf("mutations = %+v, want one POST to disable", got)
	}
}

func TestIdentitiesEnableTellsYouToGrantTheRolesAgain(t *testing.T) {
	api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, wire.Identity{ID: identityID, Roles: []string{}})
	})

	r := api.run("identities", "enable", identityID)

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "sm admin grant") {
		t.Errorf("output = %q, want the hint to grant the roles again", r.stdout)
	}
	got := api.Mutations()
	if len(got) != 1 || got[0].Path != wire.Path(wire.PathIdentityEnable, identityID) {
		t.Errorf("mutations = %+v, want one POST to enable", got)
	}
}

func TestIdentitiesDisableRefusesWhatIsNotAnIDWithoutCallingTheDaemon(t *testing.T) {
	api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, wire.Identity{}) })

	r := api.run("identities", "disable", "not-an-id")

	if r.code != exitUsage {
		t.Errorf("exit %d, want the usage exit", r.code)
	}
	if got := api.Requests(); len(got) != 0 {
		t.Errorf("requests = %+v, want none", got)
	}
}

func TestIdentitiesDisableReportsTheLastAdminRefusal(t *testing.T) {
	api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		replyError(w, http.StatusConflict, smerr.CodeConflict, "", "this is the last enabled admin")
	})

	r := api.run("identities", "disable", identityID)

	if r.code == 0 || !strings.Contains(r.stderr, "last enabled admin") {
		t.Errorf("exit %d, stderr %q, want the refusal reported", r.code, r.stderr)
	}
}

func TestTokensListWithIdentityAsksForThatIdentitysTokens(t *testing.T) {
	expires := identityEpoch.Add(24 * time.Hour)
	api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, wire.Page[wire.Token]{Items: []wire.Token{
			{ID: "tok-1", IdentityID: identityID, Name: "bootstrap", Scopes: []string{}, CreatedAt: identityEpoch, ExpiresAt: expires},
		}})
	})

	r := api.run("tokens", "list", "--identity", identityID)

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "bootstrap") {
		t.Errorf("output = %q, want the token listed", r.stdout)
	}
	got := api.Requests()
	if len(got) != 1 || got[0].Path != wire.Path(wire.PathIdentityTokens, identityID) {
		t.Errorf("requests = %+v, want the identity's token list", got)
	}
}

func TestTokensListWithoutIdentityStillListsYourOwn(t *testing.T) {
	api := newFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, wire.Page[wire.Token]{}) })

	r := api.run("tokens", "list", "--json")

	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var page wire.Page[wire.Token]
	if err := json.Unmarshal([]byte(r.stdout), &page); err != nil {
		t.Fatalf("output is not JSON: %v: %q", err, r.stdout)
	}
	got := api.Requests()
	if len(got) != 1 || got[0].Path != wire.PathTokens {
		t.Errorf("requests = %+v, want the caller's own token list", got)
	}
}
