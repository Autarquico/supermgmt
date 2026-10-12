package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/providers/github"
	"github.com/autarquico/supermgmt/internal/secrets"
)

// A github provider keeps api_url in Provider.Endpoint, credential_ref in
// Provider.CredentialRef and ca_file in Config (providerConfigCAFile).
const (
	actionProviderRead = "provider.read"

	maxRepositoriesPage = 100
)

// GitHubClients yields the read-only client of a github provider. It is the
// seam between the services and the network: the production implementation
// builds the client from the provider row and its token secret.
type GitHubClients interface {
	For(ctx context.Context, providerID domain.ID) (github.Client, error)
}

// secretReader is what the client factory needs of the secret store.
type secretReader interface {
	Get(ctx context.Context, ref secrets.Ref) (audit.Secret, error)
}

// providerGitHubClients builds clients from provider rows (ADR-0028): api_url
// is the endpoint, credential_ref names the token secret, ca_file is optional.
type providerGitHubClients struct {
	db      *database.DB
	secrets secretReader
}

// NewGitHubClients returns the production GitHubClients.
func NewGitHubClients(db *database.DB, store secretReader) GitHubClients {
	return providerGitHubClients{db: db, secrets: store}
}

func (p providerGitHubClients) For(ctx context.Context, providerID domain.ID) (github.Client, error) {
	provider, err := database.GetProvider(ctx, p.db.Reader(), providerID)
	if err != nil {
		return nil, err
	}
	if provider.Type != github.ProviderType {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("provider %s is not a github provider", provider.Name))
	}
	name, ok := secretNameOf(provider.CredentialRef)
	if !ok {
		return nil, smerr.New(smerr.CodeInternal, "", fmt.Sprintf("provider %s has no secret:// credential_ref", provider.Name))
	}
	token, err := p.secrets.Get(ctx, secrets.Ref{Name: name})
	if err != nil {
		return nil, fmt.Errorf("read the token of provider %s: %w", provider.Name, err)
	}
	ca, err := caOf(provider)
	if err != nil {
		return nil, err
	}
	client, err := github.New(provider.Endpoint, ca, token)
	if err != nil {
		return nil, smerr.Wrap(err, smerr.CodeInternal, "", fmt.Sprintf("provider %s: cannot build the GitHub client", provider.Name))
	}
	return client, nil
}

func caOf(provider domain.Provider) ([]byte, error) {
	path, _ := provider.Config[providerConfigCAFile].(string)
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path) //nolint:gosec // an operator-configured CA bundle path, absolute by config validation
	if err != nil {
		return nil, smerr.Wrap(err, smerr.CodeInternal, "", fmt.Sprintf("provider %s: cannot read ca_file", provider.Name))
	}
	return pem, nil
}

// repositoryFacts is a GitHub repository as resolved from the provider, kept
// in plans so that applying an approved plan needs no network.
type repositoryFacts struct {
	ProviderID    domain.ID `json:"provider_id"`
	GitHubID      int64     `json:"github_id"`
	OwnerID       int64     `json:"owner_id"`
	Owner         string    `json:"owner"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	DefaultBranch string    `json:"default_branch"`
}

func factsOfRow(r database.Repository) repositoryFacts {
	return repositoryFacts{
		ProviderID: r.ProviderID, GitHubID: r.GithubRepositoryID, OwnerID: r.GithubOwnerID,
		Owner: r.Owner, Name: r.Name, URL: r.URL, DefaultBranch: r.DefaultBranch,
	}
}

func factsOfRepo(providerID domain.ID, r github.Repo) repositoryFacts {
	return repositoryFacts{
		ProviderID: providerID, GitHubID: r.ID, OwnerID: r.OwnerID,
		Owner: r.Owner, Name: r.Name, URL: r.URL, DefaultBranch: r.DefaultBranch,
	}
}

// resolveRepository asks the provider for the repository with the GitHub id.
func resolveRepository(ctx context.Context, clients GitHubClients, providerID domain.ID, githubID int64) (repositoryFacts, error) {
	client, err := clients.For(ctx, providerID)
	if err != nil {
		return repositoryFacts{}, err
	}
	repo, err := client.Repository(ctx, githubID)
	if err != nil {
		return repositoryFacts{}, githubFailure(err, "repository")
	}
	return factsOfRepo(providerID, repo), nil
}

// githubFailure types a GitHub error without leaking its text: a 404 means
// the provider's token cannot see the object, anything else is a provider fault.
func githubFailure(err error, what string) error {
	var api *github.APIError
	if errors.As(err, &api) && api.Status == http.StatusNotFound {
		return smerr.New(smerr.CodeNotFound, "", what+" not found or not visible to the provider's token")
	}
	return smerr.Wrap(err, smerr.CodeProviderError, "", "GitHub could not answer the "+what+" request")
}

// ensureRepository stores the repository the first time an app references it.
func ensureRepository(ctx context.Context, q database.Querier, clock domain.Clock, ids domain.IDGenerator, f repositoryFacts) (database.Repository, error) {
	existing, err := database.GetRepositoryByGithubID(ctx, q, f.ProviderID, f.GitHubID)
	if err == nil {
		return existing, nil
	}
	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Code != smerr.CodeNotFound {
		return database.Repository{}, err
	}
	at := clock.Now()
	return database.CreateRepository(ctx, q, database.Repository{
		ID: ids.NewID(), ProviderID: f.ProviderID, GithubRepositoryID: f.GitHubID, GithubOwnerID: f.OwnerID,
		Owner: f.Owner, Name: f.Name, URL: f.URL, DefaultBranch: f.DefaultBranch, CreatedAt: at, UpdatedAt: at,
	})
}

// Repositories lists the repositories a github provider can see (spec §23
// GET /providers/{id}/repositories).
type Repositories struct {
	core
	clients GitHubClients
}

// NewRepositories validates cfg and the collaborators.
func NewRepositories(cfg Config, clients GitHubClients) (*Repositories, error) {
	c, err := newCore(cfg)
	if err != nil {
		return nil, err
	}
	if clients == nil {
		return nil, errors.New("app: repositories need the GitHub clients")
	}
	return &Repositories{core: c, clients: clients}, nil
}

// List returns one page of the provider's repositories. The cursor is the
// GitHub page number. An entry has an ID once an app references the repository.
func (r *Repositories) List(ctx context.Context, by Caller, providerID domain.ID, page wire.PageQuery) (wire.Page[wire.Repository], error) {
	provider, err := r.readableProvider(ctx, by, providerID)
	if err != nil {
		return wire.Page[wire.Repository]{}, err
	}
	number, err := repositoriesPageNumber(page.Cursor)
	if err != nil {
		return wire.Page[wire.Repository]{}, err
	}
	client, err := r.clients.For(ctx, provider.ID)
	if err != nil {
		return wire.Page[wire.Repository]{}, err
	}
	repos, next, err := client.Repositories(ctx, github.Page{Number: number, PerPage: repositoriesPerPage(page.Limit)})
	if err != nil {
		return wire.Page[wire.Repository]{}, githubFailure(err, "repository list")
	}
	items, err := r.viewsOf(ctx, provider.ID, repos)
	if err != nil {
		return wire.Page[wire.Repository]{}, err
	}
	out := wire.Page[wire.Repository]{Items: items}
	if next.Number > 0 {
		out.NextCursor = strconv.Itoa(next.Number)
	}
	return out, nil
}

func (r *Repositories) readableProvider(ctx context.Context, by Caller, id domain.ID) (domain.Provider, error) {
	provider, err := database.GetProvider(ctx, r.cfg.DB.Reader(), id)
	if err != nil {
		return domain.Provider{}, err
	}
	target := policy.Target{
		Ref:   domain.ResourceRef{Type: domain.ResourceProvider, ID: id},
		Attrs: policy.Attributes{Provider: provider.Name},
	}
	if _, err := r.authorizeGivenTarget(ctx, by, actionProviderRead, target); err != nil {
		return domain.Provider{}, err
	}
	if provider.Type != github.ProviderType {
		return domain.Provider{}, smerr.New(smerr.CodeInvalidArgument, "", "only github providers list repositories")
	}
	return provider, nil
}

func (r *Repositories) viewsOf(ctx context.Context, providerID domain.ID, repos []github.Repo) ([]wire.Repository, error) {
	q := r.cfg.DB.Reader()
	items := make([]wire.Repository, len(repos))
	for i, repo := range repos {
		view := repositoryListing(providerID, repo)
		stored, err := database.GetRepositoryByGithubID(ctx, q, providerID, repo.ID)
		switch {
		case err == nil:
			view.ID = &stored.ID
		case !isNotFoundError(err):
			return nil, err
		}
		items[i] = view
	}
	return items, nil
}

func repositoryListing(providerID domain.ID, r github.Repo) wire.Repository {
	return wire.Repository{
		ProviderID: providerID, GitHubRepositoryID: r.ID, GitHubOwnerID: r.OwnerID,
		Owner: r.Owner, Name: r.Name, URL: r.URL, DefaultBranch: r.DefaultBranch, Private: r.Private,
	}
}

func repositoryView(r database.Repository) wire.Repository {
	id := r.ID
	return wire.Repository{
		ID: &id, ProviderID: r.ProviderID, GitHubRepositoryID: r.GithubRepositoryID, GitHubOwnerID: r.GithubOwnerID,
		Owner: r.Owner, Name: r.Name, URL: r.URL, DefaultBranch: r.DefaultBranch,
	}
}

func repositoriesPageNumber(cursor string) (int, error) {
	if cursor == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(cursor)
	if err != nil || n < 1 {
		return 0, smerr.New(smerr.CodeInvalidArgument, "", "invalid cursor")
	}
	return n, nil
}

func repositoriesPerPage(limit int) int {
	if limit <= 0 {
		return wire.DefaultLimit
	}
	return min(limit, maxRepositoriesPage)
}

func secretNameOf(ref string) (string, bool) {
	name, ok := strings.CutPrefix(ref, "secret://")
	return name, ok && name != ""
}

func isNotFoundError(err error) bool {
	var typed *smerr.Error
	return errors.As(err, &typed) && typed.Code == smerr.CodeNotFound
}

// authorizeGivenTarget evaluates a query or pre-check action on target for the
// caller and audits a refusal (spec §11.3). It does not resolve the target
// itself: the caller supplies the policy view.
func (c core) authorizeGivenTarget(ctx context.Context, by Caller, action string, target policy.Target) (domain.Actor, error) {
	q := c.cfg.DB.Reader()
	actor, err := c.beginRequest(ctx, q, by)
	if err != nil {
		return domain.Actor{}, err
	}
	res := c.authorize(policy.Request{Actor: actor, Action: action, Targets: []policy.Target{target}})
	if res.Decision == policy.DecisionAllow {
		return actor, nil
	}
	err = c.write(ctx, func(ctx context.Context, tx *database.Tx) error {
		if err := c.auditDecision(ctx, tx, actor, action, target.Ref, res); err != nil {
			return err
		}
		return reject(decisionError(res))
	})
	return domain.Actor{}, err
}

// ---- CI policy (spec §18) ----------------------------------------------------

// githubActionsAppID is the GitHub App behind GitHub Actions check runs; its
// checks must name the workflow that produced them.
const githubActionsAppID = 15368

const maxRequiredChecks = 32

var (
	ciBranchPattern   = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)
	ciEventPattern    = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)
	ciWorkflowPattern = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$`)
	ciReusablePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/\.github/workflows/[A-Za-z0-9._-]+\.ya?ml@[A-Za-z0-9._/-]+$`)
)

// completeCIPolicy fills what GitHub knows: the numeric repository and owner
// ids come from the repository the app is linked to, never from names.
func completeCIPolicy(ci *wire.CIPolicy, repo *repositoryFacts) {
	if ci == nil || repo == nil {
		return
	}
	if ci.RepositoryID == 0 {
		ci.RepositoryID = repo.GitHubID
	}
	if ci.OwnerID == 0 {
		ci.OwnerID = repo.OwnerID
	}
	if len(ci.AllowedEvents) == 0 {
		ci.AllowedEvents = []string{"push"}
	}
	ci.AllowedEvents = sortedUnique(ci.AllowedEvents)
	if ci.RequiredChecks == nil {
		ci.RequiredChecks = []wire.RequiredCheck{}
	}
}

func sortedUnique(items []string) []string {
	out := slices.Clone(items)
	slices.Sort(out)
	return slices.Compact(out)
}

func invalidArgument(format string, args ...any) error {
	return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf(format, args...))
}

// validateCIPolicy checks a completed CI policy against its repository.
func validateCIPolicy(ci wire.CIPolicy, repo *repositoryFacts) error {
	switch {
	case repo == nil:
		return invalidArgument("ci_policy needs a linked repository")
	case ci.RepositoryID != repo.GitHubID || ci.OwnerID != repo.OwnerID:
		return invalidArgument("ci_policy repository_id and owner_id must be those of the linked repository")
	case !ciBranchPattern.MatchString(ci.Branch) || strings.Contains(ci.Branch, ".."):
		return invalidArgument("ci_policy branch is not a valid branch name")
	}
	if err := validateCIEvents(ci.AllowedEvents); err != nil {
		return err
	}
	if err := validateRequiredChecks(ci.RequiredChecks); err != nil {
		return err
	}
	return validateDeployWorkflows(ci)
}

func validateCIEvents(events []string) error {
	if len(events) == 0 {
		return invalidArgument("ci_policy allowed_events is empty")
	}
	for _, event := range events {
		if !ciEventPattern.MatchString(event) || strings.HasPrefix(event, "pull_request") {
			return invalidArgument("ci_policy allowed_events cannot include %q: pull request events never deploy", event)
		}
	}
	return nil
}

func validateRequiredChecks(checks []wire.RequiredCheck) error {
	if len(checks) == 0 || len(checks) > maxRequiredChecks {
		return invalidArgument("ci_policy needs between 1 and %d required_checks", maxRequiredChecks)
	}
	for _, check := range checks {
		switch {
		case check.Name == "" || len(check.Name) > 200 || !utf8.ValidString(check.Name):
			return invalidArgument("a required check needs a name of at most 200 characters")
		case check.AppID <= 0:
			return invalidArgument("required check %q needs the numeric app_id of the GitHub App that produces it", check.Name)
		case check.AppID == githubActionsAppID && !ciWorkflowPattern.MatchString(check.WorkflowPath):
			return invalidArgument("required check %q is a GitHub Actions check and needs its workflow_path", check.Name)
		case check.AppID != githubActionsAppID && check.WorkflowPath != "":
			return invalidArgument("required check %q: workflow_path applies to GitHub Actions checks only", check.Name)
		}
	}
	return nil
}

func validateDeployWorkflows(ci wire.CIPolicy) error {
	if ci.DeployWorkflow != "" && !ciWorkflowPattern.MatchString(ci.DeployWorkflow) {
		return invalidArgument("ci_policy deploy_workflow must be a path under .github/workflows")
	}
	if ci.DeployReusableWorkflow != "" && !ciReusablePattern.MatchString(ci.DeployReusableWorkflow) {
		return invalidArgument("ci_policy deploy_reusable_workflow must be <owner>/<repo>/<path>@<ref>")
	}
	return nil
}
