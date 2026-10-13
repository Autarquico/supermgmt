package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/deployments/manifest"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/policy"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The actions the Apps service decides (spec §11.2): writes are `direct`
// actions that policy may wrap in a control_plane.apply job awaiting approval.
const (
	appWriteAction       = "app.write"
	appTargetWriteAction = "app_target.write"
	appReadAction        = "app.read"
	appTargetReadAction  = "app_target.read"

	composeSourceControlPlane = "control-plane"
	composeSourceRepository   = "repository"

	rollbackAutomatic = "automatic"
	rollbackManual    = "manual"

	defaultBackupTimeout = 10 * time.Minute
	maxBackupTimeout     = time.Hour

	defaultHealthTimeout  = 3 * time.Second
	defaultHealthInterval = 5 * time.Second
	defaultHealthAttempts = 12
	maxHealthTimeout      = 30 * time.Second
	maxHealthInterval     = time.Minute
	maxHealthAttempts     = 60

	maxAppVariables    = 256
	maxVariableBytes   = 4 << 10
	maxAppSecretRefs   = 64
	maxManifestPathLen = 256
)

// unboundDigest stands for the artifact digest while a configuration is
// validated: the real digest only exists at deployment time.
const unboundDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

const (
	eventAppWritten       = appWriteAction
	eventAppTargetWritten = appTargetWriteAction
)

var (
	appNamePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	composeServiceName    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	composeProjectName    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	imageRepositoryName   = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	pinnedImagePattern    = regexp.MustCompile(`^[^@]+@sha256:[0-9a-f]{64}$`)
	variableNamePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	secretRefNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	appSecretPathPattern  = regexp.MustCompile(`^secret://apps/[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$`)
	healthPathPattern     = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	manifestPathCharacter = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// planBuilder builds the plan of a direct action; build in production.
type planBuilder func(ctx context.Context, q database.Querier, action string, actorID domain.ID, ref domain.ResourceRef, params map[string]any) (built, error)

// Apps is the catalog of applications and their targets (spec §9, §18-§20.5).
// Writes validate everything a deployment later relies on that does not depend
// on a commit: the image policy, the Compose source through the closed
// pipeline (once per target), secret references, the CI policy and the target's
// deployment policy. The same validation runs again when an approved change is
// applied, because the world may have moved while it waited.
type Apps struct {
	core
	plans   *Plans
	clients GitHubClients
	build   planBuilder
}

// NewApps validates cfg and the collaborators. The job store is the one built
// with this package's Revalidator and LockPlanner.
func NewApps(cfg Config, jobStore *jobs.Store, clients GitHubClients) (*Apps, error) {
	plans, err := NewPlans(cfg, jobStore)
	if err != nil {
		return nil, err
	}
	if clients == nil {
		return nil, errors.New("app: apps need the GitHub clients")
	}
	return &Apps{core: plans.core, plans: plans, clients: clients, build: build}, nil
}

// ---- the configuration of an app ----------------------------------------------------

// appSpec is the configured part of an app, as plans carry it. Compose content
// is control-plane text with `${secret:<ref>}` references, never a secret value.
type appSpec struct {
	Name            string                 `json:"name"`
	Repository      *repositoryFacts       `json:"repository"`
	ManifestPath    string                 `json:"manifest_path"`
	DeployedService string                 `json:"deployed_service"`
	ImagePolicy     wire.ImagePolicy       `json:"image_policy"`
	ComposeSource   string                 `json:"compose_source"`
	ComposeContent  string                 `json:"compose_content"`
	Exceptions      wire.ComposeExceptions `json:"compose_exceptions"`
	Variables       map[string]string      `json:"variables"`
	SecretRefs      map[string]string      `json:"secret_refs"`
	CI              *wire.CIPolicy         `json:"ci_policy"`
}

// complete applies the defaults and canonical forms, so that equal
// configurations are stored and planned identically.
func (s *appSpec) complete() {
	if s.ManifestPath == "" {
		s.ManifestPath = manifest.DefaultPath
	}
	if s.ComposeSource == "" {
		s.ComposeSource = composeSourceControlPlane
	}
	s.ImagePolicy.Sidecars = appsNonNilMap(s.ImagePolicy.Sidecars)
	s.ImagePolicy.Pinned = sortedUnique(appsNonNilSlice(s.ImagePolicy.Pinned))
	s.Exceptions.Services = appsNonNilMap(s.Exceptions.Services)
	s.Variables, s.SecretRefs = appsNonNilMap(s.Variables), appsNonNilMap(s.SecretRefs)
	completeCIPolicy(s.CI, s.Repository)
}

func appsNonNilMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return map[K]V{}
	}
	return m
}

func appsNonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// validate checks a completed configuration. It never reads storage.
func (s appSpec) validate(ctx context.Context) error {
	if !appNamePattern.MatchString(s.Name) {
		return invalidArgument("name must match %s", appNamePattern)
	}
	if !composeServiceName.MatchString(s.DeployedService) {
		return invalidArgument("deployed_service is not a valid Compose service name")
	}
	if err := validateManifestPath(s.ManifestPath); err != nil {
		return err
	}
	if err := validateImagePolicy(s.ImagePolicy, s.DeployedService); err != nil {
		return err
	}
	if err := validateVariables(s.Variables); err != nil {
		return err
	}
	if err := validateSecretRefs(s.SecretRefs); err != nil {
		return err
	}
	if s.CI != nil {
		if err := validateCIPolicy(*s.CI, s.Repository); err != nil {
			return err
		}
	}
	return s.validateCompose(ctx)
}

func (s appSpec) validateCompose(ctx context.Context) error {
	switch s.ComposeSource {
	case composeSourceControlPlane:
		if s.ComposeContent == "" {
			return invalidArgument("compose_content is required when compose_source is control-plane")
		}
		if len(s.ComposeContent) > compose.MaxRawBytes {
			return invalidArgument("compose_content exceeds %d bytes", compose.MaxRawBytes)
		}
		return validateComposeSource(ctx, s.composeSource(unboundDigest))
	case composeSourceRepository:
		if s.Repository == nil {
			return invalidArgument("compose_source repository needs a linked repository")
		}
		if s.ComposeContent != "" {
			return invalidArgument("compose_content must be empty when compose_source is repository")
		}
		return nil
	}
	return invalidArgument("compose_source must be %s or %s", composeSourceControlPlane, composeSourceRepository)
}

// composeSource is the pipeline input for this configuration. The digest binds
// the deployed service's image; deployments pass the real one.
func (s appSpec) composeSource(digest string) compose.Source {
	deployed := s.ImagePolicy.Deployed + "@" + digest
	return compose.Source{
		Raw: []byte(s.ComposeContent), Variables: s.Variables, SecretRefs: s.SecretRefs,
		Exceptions: composeExceptionsOf(s.Exceptions), Images: compose.ImagePolicy(s.ImagePolicy),
		DeployedService: s.DeployedService, ArtifactDigest: digest,
		BoundDigests: map[string]string{deployed: compose.BindingPinned},
	}
}

func composeExceptionsOf(e wire.ComposeExceptions) compose.Exceptions {
	services := make(map[string]compose.ServiceExceptions, len(e.Services))
	for name, x := range e.Services {
		services[name] = compose.ServiceExceptions(x)
	}
	return compose.Exceptions{Services: services}
}

// The Compose pipeline is CPU-bound and takes no context: cancellation is
// honored before it starts, and these two are the only places that call it.

func validateComposeSource(ctx context.Context, s compose.Source) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return compose.ValidateSource(s) //nolint:contextcheck // see above
}

func freezeComposeSource(ctx context.Context, s compose.Source, t compose.Target) (compose.Frozen, error) {
	if err := ctx.Err(); err != nil {
		return compose.Frozen{}, err
	}
	return compose.Freeze(s, t) //nolint:contextcheck // see above
}

// sourceHash is the SHA-256 of the control-plane source text (ADR-0007); a
// repository-sourced app has none.
func (s appSpec) sourceHash() string {
	if s.ComposeSource != composeSourceControlPlane {
		return ""
	}
	sum := sha256.Sum256([]byte(s.ComposeContent))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateManifestPath(p string) error {
	if p == "" || len(p) > maxManifestPathLen || !manifestPathCharacter.MatchString(p) ||
		strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || slices.Contains(strings.Split(p, "/"), "..") ||
		slices.Contains(strings.Split(p, "/"), ".") || strings.Contains(p, "//") {
		return invalidArgument("manifest_path must be a clean relative path inside the repository")
	}
	return nil
}

// validateImagePolicy checks spec §20.3 step 8's inputs: the deployed
// service's bare repository, the repository each sidecar may use, and the
// pinned digests an admin approved.
func validateImagePolicy(p wire.ImagePolicy, deployedService string) error {
	if err := validateImageRepository("image_policy.deployed", p.Deployed); err != nil {
		return err
	}
	for service, repository := range p.Sidecars {
		if !composeServiceName.MatchString(service) || service == deployedService {
			return invalidArgument("image_policy.sidecars: %q is not a sidecar service name", service)
		}
		if err := validateImageRepository("image_policy.sidecars."+service, repository); err != nil {
			return err
		}
	}
	for _, ref := range p.Pinned {
		if err := validatePinnedImage(ref); err != nil {
			return err
		}
	}
	return nil
}

func validateImageRepository(what, repository string) error {
	last := repository[strings.LastIndex(repository, "/")+1:]
	if !imageRepositoryName.MatchString(repository) || strings.Contains(last, ":") {
		return invalidArgument("%s must be a bare image repository without tag or digest", what)
	}
	return nil
}

func validatePinnedImage(ref string) error {
	repository, _, _ := strings.Cut(ref, "@")
	if !pinnedImagePattern.MatchString(ref) || validateImageRepository("image_policy.pinned", repository) != nil {
		return invalidArgument("image_policy.pinned entries must be <repository>@sha256:<64 hex>, got %q", ref)
	}
	return nil
}

func validateVariables(vars map[string]string) error {
	if len(vars) > maxAppVariables {
		return invalidArgument("at most %d variables", maxAppVariables)
	}
	for name, value := range vars {
		switch {
		case !variableNamePattern.MatchString(name):
			return invalidArgument("variable name %q is not valid", name)
		case len(value) > maxVariableBytes || !utf8.ValidString(value) || strings.ContainsRune(value, 0):
			return invalidArgument("variable %q has an invalid value", name)
		}
	}
	return nil
}

func validateSecretRefs(refs map[string]string) error {
	if len(refs) > maxAppSecretRefs {
		return invalidArgument("at most %d secret_refs", maxAppSecretRefs)
	}
	for name, path := range refs {
		if !secretRefNamePattern.MatchString(name) {
			return invalidArgument("secret ref name %q is not valid", name)
		}
		if !appSecretPathPattern.MatchString(path) {
			return invalidArgument("secret ref %q must point to secret://apps/<name>: app secrets live under apps/", name)
		}
	}
	return nil
}

// ---- stored form ---------------------------------------------------------------------

func decodeStored[T any](raw []byte, what string) (T, error) {
	var out T
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("stored %s is unreadable: %w", what, err)
	}
	return out, nil
}

func encodeStored(v any, what string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", what, err)
	}
	return raw, nil
}

// specOfRow reads the configuration back; repo is the app's repository row.
func specOfRow(row database.App, repo *database.Repository) (appSpec, error) {
	spec := appSpec{
		Name: row.Name, ManifestPath: row.ManifestPath, DeployedService: row.DeployedService,
		ComposeSource: row.ComposeSource, ComposeContent: row.ComposeContent,
	}
	if repo != nil {
		facts := factsOfRow(*repo)
		spec.Repository = &facts
	}
	var err error
	if spec.ImagePolicy, err = decodeStored[wire.ImagePolicy](row.ImagePolicyJSON, "image policy"); err != nil {
		return appSpec{}, err
	}
	if spec.Exceptions, err = decodeStored[wire.ComposeExceptions](row.ComposeExceptions, "compose exceptions"); err != nil {
		return appSpec{}, err
	}
	if spec.Variables, err = decodeStored[map[string]string](row.VariablesJSON, "variables"); err != nil {
		return appSpec{}, err
	}
	if spec.SecretRefs, err = decodeStored[map[string]string](row.SecretRefsJSON, "secret refs"); err != nil {
		return appSpec{}, err
	}
	if len(row.CIPolicyJSON) > 0 {
		ci, err := decodeStored[wire.CIPolicy](row.CIPolicyJSON, "ci policy")
		if err != nil {
			return appSpec{}, err
		}
		spec.CI = &ci
	}
	spec.complete()
	return spec, nil
}

// fill writes spec into row, leaving identity, repository link, automation link
// and timestamps to the caller.
func (s appSpec) fill(row *database.App) error {
	var err error
	row.Name, row.ManifestPath, row.DeployedService = s.Name, s.ManifestPath, s.DeployedService
	row.ComposeSource, row.ComposeContent, row.ComposeSourceHash = s.ComposeSource, s.ComposeContent, s.sourceHash()
	if row.ImagePolicyJSON, err = encodeStored(s.ImagePolicy, "image policy"); err != nil {
		return err
	}
	if row.ComposeExceptions, err = encodeStored(s.Exceptions, "compose exceptions"); err != nil {
		return err
	}
	if row.VariablesJSON, err = encodeStored(s.Variables, "variables"); err != nil {
		return err
	}
	if row.SecretRefsJSON, err = encodeStored(s.SecretRefs, "secret refs"); err != nil {
		return err
	}
	row.CIPolicyJSON = nil
	if s.CI != nil {
		row.CIPolicyJSON, err = encodeStored(s.CI, "ci policy")
	}
	return err
}

// patched applies an AppPatch; nil fields keep their value.
func (s appSpec) patched(p wire.AppPatch) appSpec {
	if p.ManifestPath != nil {
		s.ManifestPath = *p.ManifestPath
	}
	if p.ImagePolicy != nil {
		s.ImagePolicy = *p.ImagePolicy
	}
	if p.ComposeSource != nil {
		s.ComposeSource = *p.ComposeSource
		if *p.ComposeSource == composeSourceRepository && p.ComposeContent == nil {
			s.ComposeContent = ""
		}
	}
	if p.ComposeContent != nil {
		s.ComposeContent = *p.ComposeContent
	}
	if p.ComposeExceptions != nil {
		s.Exceptions = *p.ComposeExceptions
	}
	if p.Variables != nil {
		s.Variables = *p.Variables
	}
	if p.SecretRefs != nil {
		s.SecretRefs = *p.SecretRefs
	}
	if p.CIPolicy != nil {
		ci := *p.CIPolicy
		s.CI = &ci
	}
	return s
}

func patchChangesNothing(p wire.AppPatch) bool {
	return p.ManifestPath == nil && p.ImagePolicy == nil && p.ComposeSource == nil && p.ComposeContent == nil &&
		p.ComposeExceptions == nil && p.Variables == nil && p.SecretRefs == nil && p.CIPolicy == nil &&
		p.AutomationIdentity == nil
}

// ---- the deployment policy of a target (spec §19.1) -------------------------------

// canonicalPolicy validates a deployment policy and returns it in the form
// that is stored and planned: defaults filled, durations normalized. What M4
// does not support is refused here (Q9, Q10); production decides whether a
// stateful target must take a backup before it deploys.
func canonicalPolicy(p wire.DeploymentPolicy, production bool) (wire.DeploymentPolicy, error) {
	if p.Snapshot {
		return wire.DeploymentPolicy{}, invalidArgument("snapshot: true is not supported in this version")
	}
	switch p.Rollback {
	case "":
		p.Rollback = rollbackManual
	case rollbackAutomatic, rollbackManual:
	default:
		return wire.DeploymentPolicy{}, invalidArgument("rollback must be %s or %s", rollbackAutomatic, rollbackManual)
	}
	if p.Stateful && p.Rollback == rollbackAutomatic {
		return wire.DeploymentPolicy{}, invalidArgument("a stateful target rolls back manually")
	}
	if p.Stateful && production && p.PreDeployBackup == nil {
		return wire.DeploymentPolicy{}, invalidArgument("a stateful target in a production environment needs a pre_deploy_backup")
	}
	var err error
	if p.PreDeployBackup, err = canonicalBackup(p.PreDeployBackup); err != nil {
		return wire.DeploymentPolicy{}, err
	}
	if p.AllowedBindAddresses, err = canonicalBindAddresses(p.AllowedBindAddresses); err != nil {
		return wire.DeploymentPolicy{}, err
	}
	if p.Health, err = canonicalHealth(p.Health); err != nil {
		return wire.DeploymentPolicy{}, err
	}
	return p, nil
}

func canonicalBackup(b *wire.BackupPolicy) (*wire.BackupPolicy, error) {
	if b == nil {
		return nil, nil
	}
	out := *b
	if out.Template != manifest.BackupPostgresV1 {
		return nil, invalidArgument("pre_deploy_backup.template must be %s in this version", manifest.BackupPostgresV1)
	}
	if err := validateTemplateArguments(out.Template, out.Args); err != nil {
		return nil, err
	}
	out.Args = appsNonNilMap(out.Args)
	timeout := defaultBackupTimeout
	if out.Timeout != "" {
		var err error
		if timeout, err = time.ParseDuration(out.Timeout); err != nil || timeout < time.Second || timeout > maxBackupTimeout {
			return nil, invalidArgument("pre_deploy_backup.timeout must be a duration between 1s and %s", maxBackupTimeout)
		}
	}
	out.Timeout = timeout.String()
	return &out, nil
}

// validateTemplateArguments checks args against the template's parameters: the
// exact set of names, each value accepted by the template's own allowlist.
func validateTemplateArguments(name string, args map[string]string) error {
	all, err := templates.Templates()
	if err != nil {
		return fmt.Errorf("read template catalog: %w", err)
	}
	i := slices.IndexFunc(all, func(t templates.Template) bool { return t.Name == name })
	if i < 0 {
		return invalidArgument("unknown template %q", name)
	}
	params := all[i].Params
	if len(args) != len(params) {
		return invalidArgument("template %s takes exactly the arguments %s", name, paramNames(params))
	}
	for _, param := range params {
		value, ok := args[param.Name]
		if !ok {
			return invalidArgument("template %s takes exactly the arguments %s", name, paramNames(params))
		}
		if err := param.Validate(value); err != nil {
			return invalidArgument("template %s argument %s: %v", name, param.Name, err)
		}
	}
	return nil
}

func paramNames(params []templates.Param) string {
	names := make([]string, len(params))
	for i, p := range params {
		names[i] = p.Name
	}
	return strings.Join(names, ", ")
}

func canonicalBindAddresses(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, text := range raw {
		addr, err := netip.ParseAddr(text)
		if err != nil || addr.Zone() != "" {
			return nil, invalidArgument("allowed_bind_addresses: %q is not an IP address", text)
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() || addr.IsMulticast() {
			return nil, invalidArgument("allowed_bind_addresses: %s is not a host address", addr)
		}
		out = append(out, addr.String())
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func bindAddressesOf(canonical []string) []netip.Addr {
	addrs := make([]netip.Addr, len(canonical))
	for i, text := range canonical {
		addrs[i] = netip.MustParseAddr(text)
	}
	return addrs
}

// canonicalHealth validates a control-plane health check and returns it with
// its defaults. Node-scope checks name a port and path (their destination is
// resolved from the frozen model later); control-plane checks name a URL.
func canonicalHealth(h *wire.HealthCheck) (*wire.HealthCheck, error) {
	if h == nil {
		return nil, nil
	}
	check, err := healthCheckOf(*h)
	if err != nil {
		return nil, err
	}
	if check.Scope == health.ScopeControlPlane {
		if _, err := health.ValidateControlPlane(check, nil, nil); err != nil {
			return nil, invalidArgument("%v", err)
		}
	}
	return &wire.HealthCheck{
		Type: check.Type, Scope: check.Scope, Port: int(check.Port), Path: check.Path, URL: check.URL,
		Timeout: check.Timeout.String(), Interval: check.Interval.String(), Attempts: check.Attempts,
	}, nil
}

// healthCheckOf converts a wire check, applying defaults and the structural
// rules of its scope and type. Types outside M4's set are refused.
func healthCheckOf(h wire.HealthCheck) (health.Check, error) {
	check := health.Check{
		Origin: health.OriginControlPlane, Type: h.Type, Scope: h.Scope, Path: h.Path, URL: h.URL, Attempts: h.Attempts,
	}
	if check.Scope == "" {
		check.Scope = health.ScopeNode
	}
	if h.Port < 0 || h.Port > 65535 {
		return health.Check{}, invalidArgument("health.port must be a TCP port")
	}
	check.Port = uint16(h.Port)
	if err := applyHealthTiming(&check, h); err != nil {
		return health.Check{}, err
	}
	switch check.Scope {
	case health.ScopeNode:
		return check, requireNodeCheckShape(check)
	case health.ScopeControlPlane:
		return check, requireControlPlaneCheckShape(check)
	}
	return health.Check{}, invalidArgument("health.scope must be %s or %s", health.ScopeNode, health.ScopeControlPlane)
}

func applyHealthTiming(c *health.Check, h wire.HealthCheck) error {
	var err error
	if c.Timeout, err = durationOr(h.Timeout, defaultHealthTimeout); err != nil || c.Timeout < time.Second || c.Timeout > maxHealthTimeout {
		return invalidArgument("health.timeout must be a duration between 1s and %s", maxHealthTimeout)
	}
	if c.Interval, err = durationOr(h.Interval, defaultHealthInterval); err != nil || c.Interval < time.Second || c.Interval > maxHealthInterval {
		return invalidArgument("health.interval must be a duration between 1s and %s", maxHealthInterval)
	}
	if c.Attempts == 0 {
		c.Attempts = defaultHealthAttempts
	}
	if c.Attempts < 1 || c.Attempts > maxHealthAttempts {
		return invalidArgument("health.attempts must be between 1 and %d", maxHealthAttempts)
	}
	return nil
}

func durationOr(text string, fallback time.Duration) (time.Duration, error) {
	if text == "" {
		return fallback, nil
	}
	return time.ParseDuration(text)
}

func requireNodeCheckShape(c health.Check) error {
	if c.URL != "" {
		return invalidArgument("a node-scope health check takes a port and path, never a URL")
	}
	switch c.Type {
	case health.TypeDockerHealth:
		if c.Port != 0 || c.Path != "" {
			return invalidArgument("health: port and path do not apply to docker-health")
		}
	case health.TypeHTTP:
		if c.Port == 0 || !healthPathPattern.MatchString(c.Path) {
			return invalidArgument("health: an http check needs a port and a path such as /health")
		}
	case health.TypeTCP:
		if c.Port == 0 || c.Path != "" {
			return invalidArgument("health: a tcp check needs a port and no path")
		}
	default:
		return invalidArgument("health.type %q is not supported for a node-scope check: use http, tcp or docker-health", c.Type)
	}
	return nil
}

func requireControlPlaneCheckShape(c health.Check) error {
	if c.URL == "" || c.Port != 0 || c.Path != "" {
		return invalidArgument("a control_plane-scope health check takes a url and nothing else")
	}
	return nil
}

// ---- checking a configuration against its targets --------------------------------------

// validationTarget is a target as the Compose pipeline sees it.
type validationTarget struct {
	ID      domain.ID
	Project string
	Policy  wire.DeploymentPolicy
}

// checkAgainstTarget runs the Compose pipeline for one target (spec §20.3
// steps 1-9, with a placeholder digest) and checks that the target's node-scope
// health check publishes a port the frozen model really exposes. A repository
// source is only known at a commit, so it is checked when a deployment
// finalizes.
func checkAgainstTarget(ctx context.Context, spec appSpec, t validationTarget) error {
	if spec.ComposeSource != composeSourceControlPlane {
		return nil
	}
	binds := bindAddressesOf(t.Policy.AllowedBindAddresses)
	frozen, err := freezeComposeSource(ctx, spec.composeSource(unboundDigest), compose.Target{Project: t.Project, Owner: t.ID, AllowedBind: binds})
	if err != nil {
		return err
	}
	return checkHealthDestination(t.Policy.Health, frozen.HostPorts, binds)
}

func checkHealthDestination(h *wire.HealthCheck, ports []compose.HostPort, binds []netip.Addr) error {
	if h == nil || h.Scope == health.ScopeControlPlane {
		return nil
	}
	check, err := healthCheckOf(*h)
	if err != nil {
		return err
	}
	if _, err := health.ValidateControlPlane(check, ports, binds); err != nil {
		return invalidArgument("%v", err)
	}
	return nil
}

// requireSourceForEnvironment refuses a repository Compose source in a
// production-risk environment (spec §19.2). The spec lets an admin set an
// exception but defines no place to record one, so none is honored.
func requireSourceForEnvironment(spec appSpec, env domain.Environment) error {
	if spec.ComposeSource == composeSourceRepository && env.RiskLevel == domain.EnvironmentProduction {
		return invalidArgument("a production environment takes its Compose content from the control plane, not from the repository")
	}
	return nil
}

func composeProjectFor(appName, environment string) (string, error) {
	project := "sm-" + appName + "-" + environment
	if !composeProjectName.MatchString(project) {
		return "", invalidArgument("environment %q cannot form a Compose project name", environment)
	}
	return project, nil
}

// ---- plan parameters ------------------------------------------------------------------
//
// What an app.write or app_target.write plan carries. The ids are generated
// when the request is made, so an approved plan names what it creates; the
// parameters are the whole change, which applying them re-validates.

type appCreateParams struct {
	AppID      domain.ID        `json:"app_id"`
	Spec       appSpec          `json:"spec"`
	Automation automationChange `json:"automation"`
}

type appUpdateParams struct {
	AppID            domain.ID        `json:"app_id"`
	ExpectedRevision int64            `json:"expected_revision"`
	Patch            wire.AppPatch    `json:"patch"`
	Automation       automationChange `json:"automation"`
}

type appTargetCreateParams struct {
	TargetID    domain.ID             `json:"target_id"`
	AppID       domain.ID             `json:"app_id"`
	Environment string                `json:"environment"`
	NodeID      domain.ID             `json:"node_id"`
	Policy      wire.DeploymentPolicy `json:"policy"`
}

type appTargetUpdateParams struct {
	TargetID         domain.ID             `json:"target_id"`
	ExpectedRevision int64                 `json:"expected_revision"`
	Policy           wire.DeploymentPolicy `json:"policy"`
}

func appRef(id domain.ID) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceApp, ID: id}
}

func appTargetRef(id domain.ID) domain.ResourceRef {
	return domain.ResourceRef{Type: domain.ResourceAppTarget, ID: id}
}

// ---- requests: apps -------------------------------------------------------------------

// Create adds an app (action app.write). When policy wraps the request in a
// job that waits for approval, Pending is set instead of Applied.
func (a *Apps) Create(ctx context.Context, by Caller, r wire.CreateAppRequest) (DirectResult[AppView], error) {
	appID := a.cfg.IDs.NewID()
	if _, err := a.authorizeGivenTarget(ctx, by, appWriteAction, appPolicyTarget(appID, r.Name)); err != nil {
		return DirectResult[AppView]{}, err
	}
	facts, err := a.linkedRepository(ctx, r)
	if err != nil {
		return DirectResult[AppView]{}, err
	}
	return commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[AppView], error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[AppView]{}, err
		}
		p, err := a.createParams(ctx, tx, appID, r, facts)
		if err != nil {
			return DirectResult[AppView]{}, err
		}
		b, err := a.planOf(ctx, tx, by, appWriteAction, appRef(appID), p)
		if err != nil {
			return DirectResult[AppView]{}, err
		}
		return applyOrSubmit(ctx, a, tx, by, actor, b, func() (AppView, error) {
			row, err := a.applyCreate(ctx, tx, actor, p)
			if err != nil {
				return AppView{}, err
			}
			return a.appView(ctx, tx, row)
		})
	})
}

// planOf builds the plan of a direct action from typed parameters.
func (a *Apps) planOf(ctx context.Context, q database.Querier, by Caller, action string, ref domain.ResourceRef, p any) (built, error) {
	params, err := toParams(p)
	if err != nil {
		return built{}, err
	}
	return a.build(ctx, q, action, by.ID, ref, params)
}

// applyOrSubmit authorizes b and either applies it inside the request
// transaction or, when policy requires approval, wraps it in a job.
func applyOrSubmit[T any](ctx context.Context, a *Apps, tx *database.Tx, by Caller, actor domain.Actor, b built, apply func() (T, error)) (DirectResult[T], error) {
	res, err := a.evaluate(ctx, tx, actor, b)
	if err != nil {
		return DirectResult[T]{}, err
	}
	if res.ApprovalRequired {
		submission, err := a.plans.planAndSubmit(ctx, tx, by, actor, b, res)
		return DirectResult[T]{Pending: &submission}, err
	}
	out, err := apply()
	if err != nil {
		return DirectResult[T]{}, err
	}
	return DirectResult[T]{Applied: &out}, nil
}

// linkedRepository resolves the repository the request names, if any, before
// the transaction opens: GitHub is not called while the database is locked.
func (a *Apps) linkedRepository(ctx context.Context, r wire.CreateAppRequest) (*repositoryFacts, error) {
	switch {
	case r.ProviderID == nil && r.RepositoryID == nil:
		return nil, nil
	case r.ProviderID == nil || r.RepositoryID == nil:
		return nil, invalidArgument("provider_id and repository_id go together")
	}
	facts, err := resolveRepository(ctx, a.clients, *r.ProviderID, *r.RepositoryID)
	if err != nil {
		return nil, err
	}
	return &facts, nil
}

func (a *Apps) createParams(ctx context.Context, q database.Querier, id domain.ID, r wire.CreateAppRequest, repo *repositoryFacts) (appCreateParams, error) {
	spec := appSpec{
		Name: r.Name, Repository: repo, ManifestPath: r.ManifestPath, DeployedService: r.DeployedService,
		ImagePolicy: r.ImagePolicy, ComposeSource: r.ComposeSource, ComposeContent: r.ComposeContent,
		Exceptions: r.ComposeExceptions, Variables: r.Variables, SecretRefs: r.SecretRefs, CI: copyCIPolicy(r.CIPolicy),
	}
	spec.complete()
	if err := spec.validate(ctx); err != nil {
		return appCreateParams{}, err
	}
	if err := a.requireFreeAppName(ctx, q, spec.Name); err != nil {
		return appCreateParams{}, err
	}
	change, err := a.automationFor(ctx, q, id, nil, r.AutomationIdentity, spec)
	return appCreateParams{AppID: id, Spec: spec, Automation: change}, err
}

func copyCIPolicy(ci *wire.CIPolicy) *wire.CIPolicy {
	if ci == nil {
		return nil
	}
	out := *ci
	return &out
}

func (a *Apps) requireFreeAppName(ctx context.Context, q database.Querier, name string) error {
	_, err := database.GetAppByName(ctx, q, name)
	switch {
	case err == nil:
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("an app named %q already exists", name))
	case isNotFoundError(err):
		return nil
	}
	return err
}

// automationFor decides what the write does to the app's automation identity.
func (a *Apps) automationFor(ctx context.Context, q database.Querier, appID domain.ID, current *domain.ID, want bool, spec appSpec) (automationChange, error) {
	if !want {
		return a.planAutomation(ctx, q, appID, current, false, 0, "")
	}
	if spec.CI == nil || spec.CI.DeployWorkflow == "" {
		return automationChange{}, invalidArgument("an automation identity needs a ci_policy with a deploy_workflow")
	}
	return a.planAutomation(ctx, q, appID, current, true, spec.CI.RepositoryID, spec.CI.DeployWorkflow)
}

func (a *Apps) applyCreate(ctx context.Context, q database.Querier, actor domain.Actor, p appCreateParams) (database.App, error) {
	spec := p.Spec
	spec.complete()
	if err := spec.validate(ctx); err != nil {
		return database.App{}, err
	}
	now := a.cfg.Clock.Now()
	row := database.App{ID: p.AppID, CreatedAt: now, UpdatedAt: now}
	if err := spec.fill(&row); err != nil {
		return database.App{}, err
	}
	if spec.Repository != nil {
		repo, err := ensureRepository(ctx, q, a.cfg.Clock, a.cfg.IDs, *spec.Repository)
		if err != nil {
			return database.App{}, err
		}
		row.RepositoryID = &repo.ID
	}
	if _, err := a.applyAutomation(ctx, q, &row, p.Automation); err != nil {
		return database.App{}, err
	}
	created, err := database.CreateApp(ctx, q, row)
	if err != nil {
		return database.App{}, err
	}
	return created, a.emit(ctx, q, actor, eventAppWritten, appRef(created.ID), domain.ResultSucceeded, map[string]any{
		"operation": "create", "name": created.Name, "compose_source": created.ComposeSource,
		"compose_source_hash": created.ComposeSourceHash, "spec_revision": created.SpecRevision,
		"automation_identity_id": idString(created.AutomationIdentityID),
	})
}

func idString(id *domain.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// Update changes the configured fields of an app (action app.write). ifMatch
// is the spec_revision the caller saw; a stale one is CONFLICT.
func (a *Apps) Update(ctx context.Context, by Caller, id domain.ID, ifMatch int64, patch wire.AppPatch) (DirectResult[AppView], error) {
	return commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[AppView], error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[AppView]{}, err
		}
		current, err := database.GetApp(ctx, tx, id)
		if err != nil {
			return DirectResult[AppView]{}, err
		}
		if current.SpecRevision != ifMatch {
			return DirectResult[AppView]{}, staleRevision("app", ifMatch, current.SpecRevision)
		}
		if patchChangesNothing(patch) {
			return DirectResult[AppView]{}, invalidArgument("the patch changes nothing")
		}
		next, err := a.prepareUpdate(ctx, tx, current, patch)
		if err != nil {
			return DirectResult[AppView]{}, err
		}
		change, err := a.automationAfter(ctx, tx, current, next, patch)
		if err != nil {
			return DirectResult[AppView]{}, err
		}
		p := appUpdateParams{AppID: id, ExpectedRevision: ifMatch, Patch: patch, Automation: change}
		b, err := a.planOf(ctx, tx, by, appWriteAction, appRef(id), p)
		if err != nil {
			return DirectResult[AppView]{}, err
		}
		return applyOrSubmit(ctx, a, tx, by, actor, b, func() (AppView, error) {
			row, err := a.applyUpdate(ctx, tx, actor, p)
			if err != nil {
				return AppView{}, err
			}
			return a.appView(ctx, tx, row)
		})
	})
}

// prepareUpdate merges patch into the stored configuration, validates it and
// checks it against every existing target.
func (a *Apps) prepareUpdate(ctx context.Context, q database.Querier, current database.App, patch wire.AppPatch) (appSpec, error) {
	stored, err := a.specOf(ctx, q, current)
	if err != nil {
		return appSpec{}, err
	}
	next := stored.patched(patch)
	next.complete()
	if err := next.validate(ctx); err != nil {
		return appSpec{}, err
	}
	states, err := a.targetStates(ctx, q, current.ID)
	if err != nil {
		return appSpec{}, err
	}
	for _, t := range states {
		if err := checkStateAgainst(ctx, next, t); err != nil {
			return appSpec{}, err
		}
	}
	return next, nil
}

// automationAfter keeps the automation identity in step with the CI policy: an
// app whose CI policy no longer names a deploy workflow cannot stay linked.
func (a *Apps) automationAfter(ctx context.Context, q database.Querier, current database.App, next appSpec, patch wire.AppPatch) (automationChange, error) {
	want := current.AutomationIdentityID != nil
	if patch.AutomationIdentity != nil {
		want = *patch.AutomationIdentity
	}
	if want && (next.CI == nil || next.CI.DeployWorkflow == "") && (patch.AutomationIdentity == nil || !*patch.AutomationIdentity) {
		want = false
	}
	return a.automationFor(ctx, q, current.ID, current.AutomationIdentityID, want, next)
}

func (a *Apps) applyUpdate(ctx context.Context, q database.Querier, actor domain.Actor, p appUpdateParams) (database.App, error) {
	current, err := database.GetApp(ctx, q, p.AppID)
	if err != nil {
		return database.App{}, err
	}
	if current.SpecRevision != p.ExpectedRevision {
		return database.App{}, staleRevision("app", p.ExpectedRevision, current.SpecRevision)
	}
	next, err := a.prepareUpdate(ctx, q, current, p.Patch)
	if err != nil {
		return database.App{}, err
	}
	row := current
	row.UpdatedAt = a.cfg.Clock.Now()
	if err := next.fill(&row); err != nil {
		return database.App{}, err
	}
	revoked, err := a.applyAutomation(ctx, q, &row, p.Automation)
	if err != nil {
		return database.App{}, err
	}
	updated, err := database.UpdateApp(ctx, q, row, p.ExpectedRevision)
	if err != nil {
		return database.App{}, err
	}
	return updated, a.emit(ctx, q, actor, eventAppWritten, appRef(updated.ID), domain.ResultSucceeded, map[string]any{
		"operation": "update", "name": updated.Name, "compose_source": updated.ComposeSource,
		"compose_source_hash": updated.ComposeSourceHash, "spec_revision": updated.SpecRevision,
		"automation_identity_id": idString(updated.AutomationIdentityID), "oidc_revocations": revoked,
	})
}

// specOf reads the configuration of a stored app with its repository.
func (a *Apps) specOf(ctx context.Context, q database.Querier, row database.App) (appSpec, error) {
	var repo *database.Repository
	if row.RepositoryID != nil {
		r, err := database.GetRepository(ctx, q, *row.RepositoryID)
		if err != nil {
			return appSpec{}, err
		}
		repo = &r
	}
	return specOfRow(row, repo)
}

// ---- requests: targets ----------------------------------------------------------------

// targetState is a stored target with the environment and policy it resolves to.
type targetState struct {
	row    database.AppTarget
	env    domain.Environment
	policy wire.DeploymentPolicy
}

func (a *Apps) targetStates(ctx context.Context, q database.Querier, appID domain.ID) ([]targetState, error) {
	rows, err := database.ListAppTargetsByApp(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	states := make([]targetState, len(rows))
	for i, row := range rows {
		if states[i], err = a.stateOf(ctx, q, row); err != nil {
			return nil, err
		}
	}
	return states, nil
}

func (a *Apps) stateOf(ctx context.Context, q database.Querier, row database.AppTarget) (targetState, error) {
	env, err := database.GetEnvironment(ctx, q, row.EnvironmentID)
	if err != nil {
		return targetState{}, err
	}
	policy, err := decodeStored[wire.DeploymentPolicy](row.DeploymentPolicyJSON, "deployment policy")
	return targetState{row: row, env: env, policy: policy}, err
}

// checkStateAgainst validates a configuration for one stored target.
func checkStateAgainst(ctx context.Context, spec appSpec, t targetState) error {
	if err := requireSourceForEnvironment(spec, t.env); err != nil {
		return err
	}
	return checkAgainstTarget(ctx, spec, validationTarget{ID: t.row.ID, Project: t.row.ComposeProject, Policy: t.policy})
}

// CreateTarget places an app in an environment on a node (action
// app_target.write). The Compose project is derived: sm-<app>-<environment>.
func (a *Apps) CreateTarget(ctx context.Context, by Caller, appID domain.ID, r wire.CreateAppTargetRequest) (DirectResult[AppTargetView], error) {
	return commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[AppTargetView], error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[AppTargetView]{}, err
		}
		p, err := a.createTargetParams(ctx, tx, appID, r)
		if err != nil {
			return DirectResult[AppTargetView]{}, err
		}
		b, err := a.planOf(ctx, tx, by, appTargetWriteAction, appTargetRef(p.TargetID), p)
		if err != nil {
			return DirectResult[AppTargetView]{}, err
		}
		return applyOrSubmit(ctx, a, tx, by, actor, b, func() (AppTargetView, error) {
			row, err := a.applyCreateTarget(ctx, tx, actor, p)
			if err != nil {
				return AppTargetView{}, err
			}
			return a.targetView(ctx, tx, row)
		})
	})
}

func (a *Apps) createTargetParams(ctx context.Context, q database.Querier, appID domain.ID, r wire.CreateAppTargetRequest) (appTargetCreateParams, error) {
	env, err := environmentNamed(ctx, q, r.Environment)
	if err != nil {
		return appTargetCreateParams{}, err
	}
	policy, err := canonicalPolicy(r.DeploymentPolicy, env.RiskLevel == domain.EnvironmentProduction)
	if err != nil {
		return appTargetCreateParams{}, err
	}
	p := appTargetCreateParams{TargetID: a.cfg.IDs.NewID(), AppID: appID, Environment: env.Name, NodeID: r.NodeID, Policy: policy}
	_, err = a.checkNewTarget(ctx, q, p)
	return p, err
}

// checkNewTarget validates a target that does not exist yet and returns its
// Compose project.
func (a *Apps) checkNewTarget(ctx context.Context, q database.Querier, p appTargetCreateParams) (string, error) {
	app, err := database.GetApp(ctx, q, p.AppID)
	if err != nil {
		return "", err
	}
	spec, err := a.specOf(ctx, q, app)
	if err != nil {
		return "", err
	}
	env, err := environmentNamed(ctx, q, p.Environment)
	if err != nil {
		return "", err
	}
	if err := a.requireManagedNode(ctx, q, p.NodeID); err != nil {
		return "", err
	}
	project, err := composeProjectFor(app.Name, env.Name)
	if err != nil {
		return "", err
	}
	if err := a.requireFreeSlot(ctx, q, p, env, project); err != nil {
		return "", err
	}
	if err := requireSourceForEnvironment(spec, env); err != nil {
		return "", err
	}
	return project, checkAgainstTarget(ctx, spec, validationTarget{ID: p.TargetID, Project: project, Policy: p.Policy})
}

func (a *Apps) requireManagedNode(ctx context.Context, q database.Querier, id domain.ID) error {
	node, err := database.GetNode(ctx, q, id)
	if err != nil {
		return err
	}
	if node.ManagementState != domain.ManagementManaged {
		return invalidArgument("node %s is not managed", node.Name)
	}
	return nil
}

// requireFreeSlot refuses a second target for the same app and environment,
// and a Compose project another target already uses on the node.
func (a *Apps) requireFreeSlot(ctx context.Context, q database.Querier, p appTargetCreateParams, env domain.Environment, project string) error {
	all, err := database.ListAppTargets(ctx, q)
	if err != nil {
		return err
	}
	for _, t := range all {
		switch {
		case t.AppID == p.AppID && t.EnvironmentID == env.ID:
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("the app already has a target in environment %s", env.Name))
		case t.NodeID == p.NodeID && t.ComposeProject == project:
			return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("compose project %s is already in use on that node", project))
		}
	}
	return nil
}

func (a *Apps) applyCreateTarget(ctx context.Context, q database.Querier, actor domain.Actor, p appTargetCreateParams) (database.AppTarget, error) {
	project, err := a.checkNewTarget(ctx, q, p)
	if err != nil {
		return database.AppTarget{}, err
	}
	env, err := environmentNamed(ctx, q, p.Environment)
	if err != nil {
		return database.AppTarget{}, err
	}
	policy, err := encodeStored(p.Policy, "deployment policy")
	if err != nil {
		return database.AppTarget{}, err
	}
	now := a.cfg.Clock.Now()
	created, err := database.CreateAppTarget(ctx, q, database.AppTarget{
		ID: p.TargetID, AppID: p.AppID, EnvironmentID: env.ID, NodeID: p.NodeID, ComposeProject: project,
		DeploymentPolicyJSON: policy, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return database.AppTarget{}, err
	}
	return created, a.emit(ctx, q, actor, eventAppTargetWritten, appTargetRef(created.ID), domain.ResultSucceeded, map[string]any{
		"operation": "create", "app_id": created.AppID.String(), "environment": env.Name,
		"node_id": created.NodeID.String(), "compose_project": project, "spec_revision": created.SpecRevision,
	})
}

// UpdateTarget changes the deployment policy of a target (action
// app_target.write). ifMatch is the spec_revision the caller saw.
func (a *Apps) UpdateTarget(ctx context.Context, by Caller, id domain.ID, ifMatch int64, patch wire.AppTargetPatch) (DirectResult[AppTargetView], error) {
	return commit(ctx, a.core, by, func(ctx context.Context, tx *database.Tx) (DirectResult[AppTargetView], error) {
		actor, err := a.beginRequest(ctx, tx, by)
		if err != nil {
			return DirectResult[AppTargetView]{}, err
		}
		row, err := database.GetAppTarget(ctx, tx, id)
		if err != nil {
			return DirectResult[AppTargetView]{}, err
		}
		if row.SpecRevision != ifMatch {
			return DirectResult[AppTargetView]{}, staleRevision("app target", ifMatch, row.SpecRevision)
		}
		if patch.DeploymentPolicy == nil {
			return DirectResult[AppTargetView]{}, invalidArgument("the patch changes nothing")
		}
		p := appTargetUpdateParams{TargetID: id, ExpectedRevision: ifMatch, Policy: *patch.DeploymentPolicy}
		if _, _, err := a.prepareTargetUpdate(ctx, tx, row, &p.Policy); err != nil {
			return DirectResult[AppTargetView]{}, err
		}
		b, err := a.planOf(ctx, tx, by, appTargetWriteAction, appTargetRef(id), p)
		if err != nil {
			return DirectResult[AppTargetView]{}, err
		}
		return applyOrSubmit(ctx, a, tx, by, actor, b, func() (AppTargetView, error) {
			updated, err := a.applyUpdateTarget(ctx, tx, actor, p)
			if err != nil {
				return AppTargetView{}, err
			}
			return a.targetView(ctx, tx, updated)
		})
	})
}

// prepareTargetUpdate canonicalizes *policy in place, validates it for the
// stored target and returns the target's state.
func (a *Apps) prepareTargetUpdate(ctx context.Context, q database.Querier, row database.AppTarget, policy *wire.DeploymentPolicy) (targetState, appSpec, error) {
	state, err := a.stateOf(ctx, q, row)
	if err != nil {
		return targetState{}, appSpec{}, err
	}
	if *policy, err = canonicalPolicy(*policy, state.env.RiskLevel == domain.EnvironmentProduction); err != nil {
		return targetState{}, appSpec{}, err
	}
	app, err := database.GetApp(ctx, q, row.AppID)
	if err != nil {
		return targetState{}, appSpec{}, err
	}
	spec, err := a.specOf(ctx, q, app)
	if err != nil {
		return targetState{}, appSpec{}, err
	}
	state.policy = *policy
	return state, spec, checkStateAgainst(ctx, spec, state)
}

func (a *Apps) applyUpdateTarget(ctx context.Context, q database.Querier, actor domain.Actor, p appTargetUpdateParams) (database.AppTarget, error) {
	row, err := database.GetAppTarget(ctx, q, p.TargetID)
	if err != nil {
		return database.AppTarget{}, err
	}
	if row.SpecRevision != p.ExpectedRevision {
		return database.AppTarget{}, staleRevision("app target", p.ExpectedRevision, row.SpecRevision)
	}
	policy := p.Policy
	if _, _, err := a.prepareTargetUpdate(ctx, q, row, &policy); err != nil {
		return database.AppTarget{}, err
	}
	if row.DeploymentPolicyJSON, err = encodeStored(policy, "deployment policy"); err != nil {
		return database.AppTarget{}, err
	}
	row.UpdatedAt = a.cfg.Clock.Now()
	updated, err := database.UpdateAppTarget(ctx, q, row, p.ExpectedRevision)
	if err != nil {
		return database.AppTarget{}, err
	}
	return updated, a.emit(ctx, q, actor, eventAppTargetWritten, appTargetRef(updated.ID), domain.ResultSucceeded, map[string]any{
		"operation": "update", "app_id": updated.AppID.String(), "compose_project": updated.ComposeProject,
		"spec_revision": updated.SpecRevision,
	})
}

// ---- reads ----------------------------------------------------------------------------

func appPolicyTarget(id domain.ID, name string) policy.Target {
	return policy.Target{Ref: appRef(id), Attrs: policy.Attributes{App: name}}
}

// Get returns one app with its targets (action app.read).
func (a *Apps) Get(ctx context.Context, by Caller, id domain.ID) (AppView, error) {
	q := a.cfg.DB.Reader()
	row, err := database.GetApp(ctx, q, id)
	if err != nil {
		return AppView{}, err
	}
	if _, err := a.authorizeGivenTarget(ctx, by, appReadAction, appPolicyTarget(row.ID, row.Name)); err != nil {
		return AppView{}, err
	}
	return a.appView(ctx, q, row)
}

// List returns the apps the caller may read, ordered by name.
func (a *Apps) List(ctx context.Context, by Caller, page wire.PageQuery) (wire.Page[AppView], error) {
	q := a.cfg.DB.Reader()
	actor, err := a.beginRequest(ctx, q, by)
	if err != nil {
		return wire.Page[AppView]{}, err
	}
	rows, err := database.ListApps(ctx, q)
	if err != nil {
		return wire.Page[AppView]{}, err
	}
	rows = slices.DeleteFunc(rows, func(row database.App) bool {
		req := policy.Request{Actor: actor, Action: appReadAction, Targets: []policy.Target{appPolicyTarget(row.ID, row.Name)}}
		return a.authorize(req).Decision != policy.DecisionAllow
	})
	paged, err := paginate(rows, page, func(row database.App) domain.ID { return row.ID })
	if err != nil {
		return wire.Page[AppView]{}, err
	}
	out := wire.Page[AppView]{Items: make([]AppView, len(paged.items)), NextCursor: paged.next}
	for i, row := range paged.items {
		if out.Items[i], err = a.appView(ctx, q, row); err != nil {
			return wire.Page[AppView]{}, err
		}
	}
	return out, nil
}

// GetTarget returns one target (action app_target.read).
func (a *Apps) GetTarget(ctx context.Context, by Caller, id domain.ID) (AppTargetView, error) {
	q := a.cfg.DB.Reader()
	row, err := database.GetAppTarget(ctx, q, id)
	if err != nil {
		return AppTargetView{}, err
	}
	if err := a.authorizeTargetRead(ctx, by, q, row); err != nil {
		return AppTargetView{}, err
	}
	return a.targetView(ctx, q, row)
}

// ListTargets returns the targets of one app the caller may read.
func (a *Apps) ListTargets(ctx context.Context, by Caller, appID domain.ID) ([]AppTargetView, error) {
	q := a.cfg.DB.Reader()
	if _, err := database.GetApp(ctx, q, appID); err != nil {
		return nil, err
	}
	rows, err := database.ListAppTargetsByApp(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	views := make([]AppTargetView, 0, len(rows))
	for _, row := range rows {
		if err := a.authorizeTargetRead(ctx, by, q, row); err != nil {
			if isTyped(err) {
				continue
			}
			return nil, err
		}
		view, err := a.targetView(ctx, q, row)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

// authorizeTargetRead evaluates app_target.read on the target's policy view:
// the environment of the target, its app's name and the tags of its node.
func (a *Apps) authorizeTargetRead(ctx context.Context, by Caller, q database.Querier, row database.AppTarget) error {
	app, err := database.GetApp(ctx, q, row.AppID)
	if err != nil {
		return err
	}
	env, err := database.GetEnvironment(ctx, q, row.EnvironmentID)
	if err != nil {
		return err
	}
	node, err := database.GetNode(ctx, q, row.NodeID)
	if err != nil {
		return err
	}
	target := policy.Target{Ref: appTargetRef(row.ID), Attrs: policy.Attributes{
		Environment: env.Name, EnvironmentRisk: env.RiskLevel, ApprovalsRequired: env.ApprovalsRequired,
		App: app.Name, Tags: node.Tags,
	}}
	_, err = a.authorizeGivenTarget(ctx, by, appTargetReadAction, target)
	return err
}

// ---- views ----------------------------------------------------------------------------

func (a *Apps) appView(ctx context.Context, q database.Querier, row database.App) (AppView, error) {
	spec, err := a.specOf(ctx, q, row)
	if err != nil {
		return AppView{}, err
	}
	view := AppView{
		ID: row.ID, Name: row.Name, ManifestPath: row.ManifestPath, DeployedService: row.DeployedService,
		ImagePolicy: spec.ImagePolicy, ComposeSource: row.ComposeSource, ComposeContent: row.ComposeContent,
		ComposeSourceHash: row.ComposeSourceHash, ComposeExceptions: spec.Exceptions, Variables: spec.Variables,
		SecretRefs: spec.SecretRefs, CIPolicy: spec.CI, AutomationIdentityID: row.AutomationIdentityID,
		SpecRevision: row.SpecRevision, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	if row.RepositoryID != nil {
		repo, err := database.GetRepository(ctx, q, *row.RepositoryID)
		if err != nil {
			return AppView{}, err
		}
		v := repositoryView(repo)
		view.Repository = &v
	}
	targets, err := database.ListAppTargetsByApp(ctx, q, row.ID)
	if err != nil {
		return AppView{}, err
	}
	view.Targets = make([]AppTargetView, len(targets))
	for i, t := range targets {
		if view.Targets[i], err = a.targetView(ctx, q, t); err != nil {
			return AppView{}, err
		}
	}
	return view, nil
}

func (a *Apps) targetView(ctx context.Context, q database.Querier, row database.AppTarget) (AppTargetView, error) {
	state, err := a.stateOf(ctx, q, row)
	if err != nil {
		return AppTargetView{}, err
	}
	return AppTargetView{
		ID: row.ID, AppID: row.AppID, EnvironmentID: row.EnvironmentID, Environment: state.env.Name,
		NodeID: row.NodeID, ComposeProject: row.ComposeProject, DeploymentPolicy: state.policy,
		SpecRevision: row.SpecRevision, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}, nil
}
