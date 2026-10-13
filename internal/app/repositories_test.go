package app

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/providers/github"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// Repositories answers the listing from the fixture's table, a page at a time
// in ascending id order.
func (c appsGitHubClient) Repositories(_ context.Context, page github.Page) ([]github.Repo, github.Page, error) {
	c.g.mu.Lock()
	defer c.g.mu.Unlock()
	c.g.pages = append(c.g.pages, page)
	if c.g.listFail != nil {
		return nil, github.Page{}, c.g.listFail
	}
	ids := make([]int64, 0, len(c.g.repos))
	for id := range c.g.repos {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	lo := min((page.Number-1)*page.PerPage, len(ids))
	hi := min(lo+page.PerPage, len(ids))
	out := make([]github.Repo, 0, hi-lo)
	for _, id := range ids[lo:hi] {
		out = append(out, c.g.repos[id])
	}
	next := github.Page{}
	if hi < len(ids) {
		next = github.Page{Number: page.Number + 1, PerPage: page.PerPage}
	}
	return out, next, nil
}

func newRepositoriesFixture(t *testing.T) (*appsFixture, *Repositories) {
	t.Helper()
	f := newAppsFixture(t)
	for id := int64(1); id <= 3; id++ {
		f.gh.repos[id] = github.Repo{ID: id, OwnerID: 10, Owner: "acme", Name: "r" + strconv.FormatInt(id, 10), URL: "https://github.com/acme/r", Private: id == 2}
	}
	repos, err := NewRepositories(f.cfg, f.gh)
	mustf(t, err, "NewRepositories")
	return f, repos
}

func TestRepositoriesList_PagesThroughTheProvidersRepositories(t *testing.T) {
	f, repos := newRepositoriesFixture(t)
	ctx := context.Background()

	first, err := repos.List(ctx, f.caller(f.alice), f.ghHost.ID, wire.PageQuery{Limit: 3})
	mustf(t, err, "List")
	second, err := repos.List(ctx, f.caller(f.alice), f.ghHost.ID, wire.PageQuery{Limit: 3, Cursor: first.NextCursor})
	mustf(t, err, "List page 2")

	if len(first.Items) != 3 || first.NextCursor != "2" {
		t.Fatalf("page 1 = %d items, cursor %q; want 3 and cursor 2", len(first.Items), first.NextCursor)
	}
	if len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].GitHubRepositoryID != 4242 {
		t.Errorf("page 2 = %+v, want the last repository and no cursor", second)
	}
	if got := f.gh.pages; len(got) != 2 || got[0] != (github.Page{Number: 1, PerPage: 3}) || got[1] != (github.Page{Number: 2, PerPage: 3}) {
		t.Errorf("pages requested = %+v", got)
	}
	if !first.Items[1].Private {
		t.Errorf("the private flag is lost: %+v", first.Items[1])
	}
}

func TestRepositoriesList_EntriesGetAnIDOnceAnAppReferencesThem(t *testing.T) {
	f, repos := newRepositoriesFixture(t)
	app := f.createApp(appsRepositoryRequest(f))

	page, err := repos.List(context.Background(), f.caller(f.alice), f.ghHost.ID, wire.PageQuery{Limit: 100})

	mustf(t, err, "List")
	for _, item := range page.Items {
		linked := item.GitHubRepositoryID == f.repoMain.ID
		if linked != (item.ID != nil) {
			t.Errorf("repository %d: ID %v, linked %v", item.GitHubRepositoryID, item.ID, linked)
		}
		if linked && *item.ID != *app.Repository.ID {
			t.Errorf("ID = %s, want %s", *item.ID, *app.Repository.ID)
		}
	}
}

func TestRepositoriesList_Refusals(t *testing.T) {
	f, repos := newRepositoriesFixture(t)
	ctx := context.Background()

	_, denied := repos.List(ctx, f.caller(f.dave), f.ghHost.ID, wire.PageQuery{})
	_, notGitHub := repos.List(ctx, f.caller(f.alice), f.provider.ID, wire.PageQuery{})
	_, unknown := repos.List(ctx, f.caller(f.alice), f.ids.NewID(), wire.PageQuery{})
	_, badCursor := repos.List(ctx, f.caller(f.alice), f.ghHost.ID, wire.PageQuery{Cursor: "abc"})
	_, zeroCursor := repos.List(ctx, f.caller(f.alice), f.ghHost.ID, wire.PageQuery{Cursor: "0"})

	wantAppsCode(t, denied, smerr.CodePolicyDenied)
	wantAppsCode(t, notGitHub, smerr.CodeInvalidArgument)
	wantAppsCode(t, unknown, smerr.CodeNotFound)
	wantAppsCode(t, badCursor, smerr.CodeInvalidArgument)
	wantAppsCode(t, zeroCursor, smerr.CodeInvalidArgument)
	if len(f.gh.pages) != 0 {
		t.Errorf("GitHub was asked for %d pages despite the refusals", len(f.gh.pages))
	}
}

func TestRepositoriesList_GitHubFailuresAreTypedAndDoNotLeakTheirText(t *testing.T) {
	f, repos := newRepositoriesFixture(t)
	f.gh.listFail = errors.New("Get https://api.github.com/user/repos: Authorization: Bearer ghp_secret")

	_, err := repos.List(context.Background(), f.caller(f.alice), f.ghHost.ID, wire.PageQuery{})

	wantAppsCode(t, err, smerr.CodeProviderError)
	var typed *smerr.Error
	if !errors.As(err, &typed) || strings.Contains(typed.Message, "ghp_secret") {
		t.Errorf("message %q leaks the upstream error", typed.Message)
	}
}

func TestRepositoriesList_AMissingRepositoryListIs404(t *testing.T) {
	f, repos := newRepositoriesFixture(t)
	f.gh.listFail = &github.APIError{Status: 404}

	_, err := repos.List(context.Background(), f.caller(f.alice), f.ghHost.ID, wire.PageQuery{})

	wantAppsCode(t, err, smerr.CodeNotFound)
}

func TestNewRepositories_RequiresItsCollaborators(t *testing.T) {
	f := newFixture(t)

	if _, err := NewRepositories(f.cfg, nil); err == nil {
		t.Error("NewRepositories without GitHub clients succeeded")
	}
	if _, err := NewRepositories(Config{}, &appsGitHub{}); err == nil {
		t.Error("NewRepositories without a database succeeded")
	}
}

// ---- the production client factory ---------------------------------------------------

type fixedSecrets struct {
	values map[string]string
	asked  []secrets.Ref
}

func (s *fixedSecrets) Get(_ context.Context, ref secrets.Ref) (audit.Secret, error) {
	s.asked = append(s.asked, ref)
	value, ok := s.values[ref.Name]
	if !ok {
		return "", smerr.New(smerr.CodeNotFound, "", "secret not found")
	}
	return audit.Secret(value), nil
}

func (f *appsFixture) addAppsProvider(p domain.Provider) domain.Provider {
	f.t.Helper()
	p.ID, p.Origin, p.CreatedAt, p.UpdatedAt = f.ids.NewID(), domain.ProviderAPI, f.clock.Now(), f.clock.Now()
	var stored domain.Provider
	f.inTx(func(ctx context.Context, tx *database.Tx) error {
		var err error
		stored, err = database.CreateProvider(ctx, tx, p)
		return err
	})
	return stored
}

func TestProviderGitHubClients_BuildsTheClientFromTheProviderRow(t *testing.T) {
	f := newAppsFixture(t)
	store := &fixedSecrets{values: map[string]string{"providers/github/token": "ghp_token"}}

	client, err := NewGitHubClients(f.db, store).For(context.Background(), f.ghHost.ID)

	mustf(t, err, "For")
	if client == nil {
		t.Fatal("no client")
	}
	if len(store.asked) != 1 || store.asked[0].Name != "providers/github/token" || store.asked[0].Version != 0 {
		t.Errorf("secrets read = %+v, want the latest version of the credential_ref", store.asked)
	}
}

func TestProviderGitHubClients_Refusals(t *testing.T) {
	f := newAppsFixture(t)
	noCredential := f.addAppsProvider(domain.Provider{Type: github.ProviderType, Name: "gh-nocred", Endpoint: "https://api.github.com", CredentialRef: "file:///etc/token"})
	badCA := f.addAppsProvider(domain.Provider{
		Type: github.ProviderType, Name: "gh-badca", Endpoint: "https://ghe.example.com/api/v3",
		CredentialRef: "secret://providers/github/token", Config: map[string]any{"ca_file": "/nonexistent/ca.pem"},
	})
	badEndpoint := f.addAppsProvider(domain.Provider{Type: github.ProviderType, Name: "gh-http", Endpoint: "http://api.github.com", CredentialRef: "secret://providers/github/token"})
	store := &fixedSecrets{values: map[string]string{"providers/github/token": "ghp_token"}}
	clients := NewGitHubClients(f.db, store)
	missingSecret := NewGitHubClients(f.db, &fixedSecrets{})

	tests := []struct {
		name     string
		clients  GitHubClients
		provider domain.ID
		want     smerr.Code
	}{
		{"unknown provider", clients, f.ids.NewID(), smerr.CodeNotFound},
		{"not a github provider", clients, f.provider.ID, smerr.CodeInvalidArgument},
		{"credential that is not a secret", clients, noCredential.ID, smerr.CodeInternal},
		{"unreadable ca_file", clients, badCA.ID, smerr.CodeInternal},
		{"endpoint that is not https", clients, badEndpoint.ID, smerr.CodeInternal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.clients.For(context.Background(), tc.provider)
			wantAppsCode(t, err, tc.want)
		})
	}
	if _, err := missingSecret.For(context.Background(), f.ghHost.ID); err == nil {
		t.Error("a missing token secret produced a client")
	}
}

// ---- CI policy completion -------------------------------------------------------------

func TestCompleteCIPolicy_FillsIDsFromTheRepositoryAndKeepsWhatWasGiven(t *testing.T) {
	repo := &repositoryFacts{GitHubID: 4242, OwnerID: 77}
	given := wire.CIPolicy{RepositoryID: 9, AllowedEvents: []string{"workflow_dispatch", "push", "push"}}
	empty := wire.CIPolicy{}

	completeCIPolicy(&given, repo)
	completeCIPolicy(&empty, repo)
	completeCIPolicy(nil, repo)
	completeCIPolicy(&wire.CIPolicy{}, nil)

	if given.RepositoryID != 9 || given.OwnerID != 77 {
		t.Errorf("given = %+v: a stated id is kept for validation to compare, a missing one is filled", given)
	}
	if got := given.AllowedEvents; len(got) != 2 || got[0] != "push" || got[1] != "workflow_dispatch" {
		t.Errorf("allowed_events = %v, want sorted and deduplicated", got)
	}
	if empty.RepositoryID != 4242 || empty.OwnerID != 77 || len(empty.AllowedEvents) != 1 || empty.AllowedEvents[0] != "push" || empty.RequiredChecks == nil {
		t.Errorf("empty = %+v, want ids from the repository and the push default", empty)
	}
}
