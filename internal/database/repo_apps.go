package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ---- repositories ----------------------------------------------------------

// Repository is a GitHub repository known through a github provider (spec §9).
type Repository struct {
	ID                 domain.ID
	ProviderID         domain.ID
	GithubRepositoryID int64
	GithubOwnerID      int64
	Owner              string
	Name               string
	URL                string
	DefaultBranch      string
	MetadataJSON       []byte
	SpecRevision       int64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

const repositoryColumns = `id, provider_id, github_repository_id, github_owner_id, owner, name, url,
	default_branch, metadata_json, spec_revision, created_at, updated_at`

func scanRepository(row scanner) (Repository, error) {
	var (
		r                    Repository
		metadata             string
		createdAt, updatedAt int64
	)
	err := row.Scan(&r.ID, &r.ProviderID, &r.GithubRepositoryID, &r.GithubOwnerID, &r.Owner, &r.Name, &r.URL,
		&r.DefaultBranch, &metadata, &r.SpecRevision, &createdAt, &updatedAt)
	if err != nil {
		return Repository{}, err
	}
	r.MetadataJSON = []byte(metadata)
	r.CreatedAt, r.UpdatedAt = domain.FromUnixMillis(createdAt), domain.FromUnixMillis(updatedAt)
	return r, nil
}

// CreateRepository stores r at spec_revision 1. (provider, github repository id) is unique: CONFLICT.
func CreateRepository(ctx context.Context, q Querier, r Repository) (Repository, error) {
	_, err := q.ExecContext(ctx, `INSERT INTO repositories (`+repositoryColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.ProviderID, r.GithubRepositoryID, r.GithubOwnerID, r.Owner, r.Name, r.URL,
		r.DefaultBranch, appsJSONOrEmptyObject(r.MetadataJSON), initialRevision, millis(r.CreatedAt), millis(r.UpdatedAt))
	if err != nil {
		return Repository{}, conflictIfDuplicate(err, "repository")
	}
	r.SpecRevision = initialRevision
	return r, nil
}

// GetRepository returns the repository or NOT_FOUND.
func GetRepository(ctx context.Context, q Querier, id domain.ID) (Repository, error) {
	r, err := scanRepository(q.QueryRowContext(ctx, `SELECT `+repositoryColumns+` FROM repositories WHERE id = ?`, id))
	return appsFoundOrErr(r, err, "repository")
}

// GetRepositoryByGithubID returns the repository the provider knows under its GitHub id, or NOT_FOUND.
func GetRepositoryByGithubID(ctx context.Context, q Querier, providerID domain.ID, githubID int64) (Repository, error) {
	r, err := scanRepository(q.QueryRowContext(ctx, `SELECT `+repositoryColumns+`
		FROM repositories WHERE provider_id = ? AND github_repository_id = ?`, providerID, githubID))
	return appsFoundOrErr(r, err, "repository")
}

// ListRepositories returns every repository ordered by owner and name.
func ListRepositories(ctx context.Context, q Querier) ([]Repository, error) {
	return appsListRows(ctx, q, "repositories", scanRepository,
		`SELECT `+repositoryColumns+` FROM repositories ORDER BY owner, name, id`)
}

// UpdateRepository rewrites the mutable fields of r and bumps spec_revision, provided the stored
// revision still equals expectedRev; otherwise CONFLICT.
func UpdateRepository(ctx context.Context, q Querier, r Repository, expectedRev int64) (Repository, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE repositories SET owner = ?, name = ?, url = ?, default_branch = ?, metadata_json = ?,
		                        updated_at = ?, spec_revision = spec_revision + 1
		WHERE id = ? AND spec_revision = ?`,
		r.Owner, r.Name, r.URL, r.DefaultBranch, appsJSONOrEmptyObject(r.MetadataJSON), millis(r.UpdatedAt), r.ID, expectedRev)
	if err := appsRevisionOutcome(ctx, q, res, err, "repositories", r.ID, expectedRev); err != nil {
		return Repository{}, err
	}
	return GetRepository(ctx, q, r.ID)
}

// ---- apps ------------------------------------------------------------------

// App is a deployable application (spec §9). ComposeContent, ComposeSourceHash, CIPolicyJSON,
// RepositoryID and AutomationIdentityID are optional: empty/nil is stored as NULL.
type App struct {
	ID                   domain.ID
	Name                 string
	RepositoryID         *domain.ID
	ManifestPath         string
	DeployedService      string
	ImagePolicyJSON      []byte
	ComposeSource        string
	ComposeContent       string
	ComposeSourceHash    string
	ComposeExceptions    []byte
	VariablesJSON        []byte
	SecretRefsJSON       []byte
	CIPolicyJSON         []byte
	AutomationIdentityID *domain.ID
	SpecRevision         int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

const appColumns = `id, name, repository_id, manifest_path, deployed_service, image_policy_json, compose_source,
	compose_content, compose_source_hash, compose_exceptions_json, variables_json, secret_refs_json,
	ci_policy_json, automation_identity_id, spec_revision, created_at, updated_at`

func scanApp(row scanner) (App, error) {
	var (
		a                                           App
		repositoryID, automationID                  sql.NullString
		content, hash, ciPolicy                     sql.NullString
		imagePolicy, exceptions, variables, secrets string
		createdAt, updatedAt                        int64
	)
	err := row.Scan(&a.ID, &a.Name, &repositoryID, &a.ManifestPath, &a.DeployedService, &imagePolicy,
		&a.ComposeSource, &content, &hash, &exceptions, &variables, &secrets, &ciPolicy, &automationID,
		&a.SpecRevision, &createdAt, &updatedAt)
	if err != nil {
		return App{}, err
	}
	a.RepositoryID, a.AutomationIdentityID = idOf(repositoryID), idOf(automationID)
	a.ComposeContent, a.ComposeSourceHash = content.String, hash.String
	a.ImagePolicyJSON, a.ComposeExceptions = []byte(imagePolicy), []byte(exceptions)
	a.VariablesJSON, a.SecretRefsJSON = []byte(variables), []byte(secrets)
	if ciPolicy.Valid {
		a.CIPolicyJSON = []byte(ciPolicy.String)
	}
	a.CreatedAt, a.UpdatedAt = domain.FromUnixMillis(createdAt), domain.FromUnixMillis(updatedAt)
	return a, nil
}

// CreateApp stores a at spec_revision 1. A duplicate name is CONFLICT.
func CreateApp(ctx context.Context, q Querier, a App) (App, error) {
	_, err := q.ExecContext(ctx, `INSERT INTO apps (`+appColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, nullID(a.RepositoryID), a.ManifestPath, a.DeployedService, string(a.ImagePolicyJSON),
		a.ComposeSource, appsNullText(a.ComposeContent), appsNullText(a.ComposeSourceHash),
		appsJSONOrEmptyObject(a.ComposeExceptions), appsJSONOrEmptyObject(a.VariablesJSON), appsJSONOrEmptyObject(a.SecretRefsJSON),
		appsNullText(string(a.CIPolicyJSON)), nullID(a.AutomationIdentityID), initialRevision,
		millis(a.CreatedAt), millis(a.UpdatedAt))
	if err != nil {
		return App{}, conflictIfDuplicate(err, "app")
	}
	a.SpecRevision = initialRevision
	return a, nil
}

// GetApp returns the app or NOT_FOUND.
func GetApp(ctx context.Context, q Querier, id domain.ID) (App, error) {
	a, err := scanApp(q.QueryRowContext(ctx, `SELECT `+appColumns+` FROM apps WHERE id = ?`, id))
	return appsFoundOrErr(a, err, "app")
}

// GetAppByName returns the app or NOT_FOUND.
func GetAppByName(ctx context.Context, q Querier, name string) (App, error) {
	a, err := scanApp(q.QueryRowContext(ctx, `SELECT `+appColumns+` FROM apps WHERE name = ?`, name))
	return appsFoundOrErr(a, err, "app")
}

// ListApps returns every app ordered by name.
func ListApps(ctx context.Context, q Querier) ([]App, error) {
	return appsListRows(ctx, q, "apps", scanApp, `SELECT `+appColumns+` FROM apps ORDER BY name, id`)
}

// UpdateApp rewrites every configured field of a (the name included) and bumps spec_revision,
// provided the stored revision still equals expectedRev; otherwise CONFLICT.
func UpdateApp(ctx context.Context, q Querier, a App, expectedRev int64) (App, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE apps SET name = ?, repository_id = ?, manifest_path = ?, deployed_service = ?, image_policy_json = ?,
		                compose_source = ?, compose_content = ?, compose_source_hash = ?,
		                compose_exceptions_json = ?, variables_json = ?, secret_refs_json = ?, ci_policy_json = ?,
		                automation_identity_id = ?, updated_at = ?, spec_revision = spec_revision + 1
		WHERE id = ? AND spec_revision = ?`,
		a.Name, nullID(a.RepositoryID), a.ManifestPath, a.DeployedService, string(a.ImagePolicyJSON),
		a.ComposeSource, appsNullText(a.ComposeContent), appsNullText(a.ComposeSourceHash),
		appsJSONOrEmptyObject(a.ComposeExceptions), appsJSONOrEmptyObject(a.VariablesJSON), appsJSONOrEmptyObject(a.SecretRefsJSON),
		appsNullText(string(a.CIPolicyJSON)), nullID(a.AutomationIdentityID), millis(a.UpdatedAt), a.ID, expectedRev)
	if err := appsRevisionOutcome(ctx, q, res, err, "apps", a.ID, expectedRev); err != nil {
		return App{}, err
	}
	return GetApp(ctx, q, a.ID)
}

// ---- app targets -----------------------------------------------------------

// AppTarget places an app on one node of one environment (spec §9). The compose project
// is immutable once stored.
type AppTarget struct {
	ID                   domain.ID
	AppID                domain.ID
	EnvironmentID        domain.ID
	NodeID               domain.ID
	ComposeProject       string
	DeploymentPolicyJSON []byte
	SpecRevision         int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

const appTargetColumns = `id, app_id, environment_id, node_id, compose_project, deployment_policy_json,
	spec_revision, created_at, updated_at`

func scanAppTarget(row scanner) (AppTarget, error) {
	var (
		t                    AppTarget
		policy               string
		createdAt, updatedAt int64
	)
	err := row.Scan(&t.ID, &t.AppID, &t.EnvironmentID, &t.NodeID, &t.ComposeProject, &policy,
		&t.SpecRevision, &createdAt, &updatedAt)
	if err != nil {
		return AppTarget{}, err
	}
	t.DeploymentPolicyJSON = []byte(policy)
	t.CreatedAt, t.UpdatedAt = domain.FromUnixMillis(createdAt), domain.FromUnixMillis(updatedAt)
	return t, nil
}

// CreateAppTarget stores t at spec_revision 1. (node, project) and (app, environment) are
// unique: CONFLICT.
func CreateAppTarget(ctx context.Context, q Querier, t AppTarget) (AppTarget, error) {
	_, err := q.ExecContext(ctx, `INSERT INTO app_targets (`+appTargetColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.AppID, t.EnvironmentID, t.NodeID, t.ComposeProject, string(t.DeploymentPolicyJSON),
		initialRevision, millis(t.CreatedAt), millis(t.UpdatedAt))
	if err != nil {
		return AppTarget{}, conflictIfDuplicate(err, "app target")
	}
	t.SpecRevision = initialRevision
	return t, nil
}

// GetAppTarget returns the target or NOT_FOUND.
func GetAppTarget(ctx context.Context, q Querier, id domain.ID) (AppTarget, error) {
	t, err := scanAppTarget(q.QueryRowContext(ctx, `SELECT `+appTargetColumns+` FROM app_targets WHERE id = ?`, id))
	return appsFoundOrErr(t, err, "app target")
}

// ListAppTargets returns every target ordered by creation.
func ListAppTargets(ctx context.Context, q Querier) ([]AppTarget, error) {
	return appsListRows(ctx, q, "app targets", scanAppTarget,
		`SELECT `+appTargetColumns+` FROM app_targets ORDER BY created_at, id`)
}

// ListAppTargetsByApp returns the targets of one app ordered by creation.
func ListAppTargetsByApp(ctx context.Context, q Querier, appID domain.ID) ([]AppTarget, error) {
	return appsListRows(ctx, q, "app targets", scanAppTarget,
		`SELECT `+appTargetColumns+` FROM app_targets WHERE app_id = ? ORDER BY created_at, id`, appID)
}

// UpdateAppTarget rewrites the environment, node and deployment policy of t and bumps
// spec_revision, provided the stored revision still equals expectedRev; otherwise CONFLICT.
// The compose project is never written: it is immutable.
func UpdateAppTarget(ctx context.Context, q Querier, t AppTarget, expectedRev int64) (AppTarget, error) {
	res, err := q.ExecContext(ctx, `
		UPDATE app_targets SET environment_id = ?, node_id = ?, deployment_policy_json = ?, updated_at = ?,
		                       spec_revision = spec_revision + 1
		WHERE id = ? AND spec_revision = ?`,
		t.EnvironmentID, t.NodeID, string(t.DeploymentPolicyJSON), millis(t.UpdatedAt), t.ID, expectedRev)
	if err := appsRevisionOutcome(ctx, q, res, err, "app_targets", t.ID, expectedRev); err != nil {
		return AppTarget{}, err
	}
	return GetAppTarget(ctx, q, t.ID)
}

// ---- shared helpers --------------------------------------------------------

func appsJSONOrEmptyObject(b []byte) string {
	if len(b) == 0 {
		return "{}"
	}
	return string(b)
}

func appsNullText(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func appsFoundOrErr[T any](v T, err error, what string) (T, error) {
	var zero T
	if errors.Is(err, sql.ErrNoRows) {
		return zero, notFound(what)
	}
	if err != nil {
		return zero, fmt.Errorf("read %s: %w", what, err)
	}
	return v, nil
}

func appsListRows[T any](ctx context.Context, q Querier, what string, scan func(scanner) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", what, err)
	}
	defer func() { _ = rows.Close() }()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", what, err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list %s: %w", what, err)
	}
	return out, nil
}

// appsRevisionOutcome turns the result of an If-Match UPDATE into nil, CONFLICT for a uniqueness
// violation, or the NOT_FOUND/CONFLICT that staleOrMissing diagnoses when no row matched.
func appsRevisionOutcome(ctx context.Context, q Querier, res sql.Result, execErr error, table string, id domain.ID, expectedRev int64) error {
	if isUniqueViolation(execErr) {
		return smerr.Wrap(execErr, smerr.CodeConflict, "", table+" already exists")
	}
	if execErr != nil {
		return fmt.Errorf("update %s: %w", table, execErr)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update %s: %w", table, err)
	}
	if affected == 0 {
		return staleOrMissing(ctx, q, table, id, expectedRev)
	}
	return nil
}
