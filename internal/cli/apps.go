package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// newAppsCmd is `sm apps` (spec §20.0).
func newAppsCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apps",
		Short: "List, inspect and create applications and their targets",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newAppsListCmd(env), newAppsGetCmd(env), newAppsCreateCmd(env), newAppsTargetCmd(env),
		newAppsExposeCmd(env), newAppsUnexposeCmd(env), newAppsRoutesCmd(env))
	return cmd
}

func newAppsListCmd(env []string) *cobra.Command {
	var page *wire.PageQuery
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List applications",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			apps, err := api.ListApps(cmd.Context(), *page)
			if err != nil {
				return err
			}
			return emit(cmd, apps, func(w io.Writer) error {
				if err := writeApps(w, apps.Items); err != nil {
					return err
				}
				moreHint(w, apps.NextCursor)
				return nil
			})
		},
	}
	page = addPageFlags(cmd)
	return cmd
}

func writeApps(w io.Writer, apps []wire.App) error {
	rows := make([][]string, len(apps))
	for i, a := range apps {
		rows[i] = []string{string(a.ID), a.Name, repositoryName(a.Repository), a.DeployedService, fmt.Sprint(len(a.Targets))}
	}
	return table(w, []string{"ID", "NAME", "REPOSITORY", "DEPLOYED SERVICE", "TARGETS"}, rows)
}

func repositoryName(r *wire.Repository) string {
	if r == nil {
		return "-"
	}
	return r.Owner + "/" + r.Name
}

func newAppsGetCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <app>",
		Short: "Show one application with its targets (id or name)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveApp(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			app, err := api.GetApp(cmd.Context(), id)
			if err != nil {
				return err
			}
			routes, err := appRoutes(cmd.Context(), api, app)
			if err != nil {
				return err
			}
			return emit(cmd, app, func(w io.Writer) error {
				if err := writeApp(w, app); err != nil {
					return err
				}
				return writeAppRoutes(w, routes, app)
			})
		},
	}
}

func writeApp(w io.Writer, a wire.App) error {
	if err := fields(w, [][2]string{
		{"id", string(a.ID)},
		{"name", a.Name},
		{"repository", repositoryName(a.Repository)},
		{"deployed service", a.DeployedService},
		{"compose source", a.ComposeSource},
		{"compose source hash", orDash(a.ComposeSourceHash)},
		{"spec revision", fmt.Sprint(a.SpecRevision)},
	}); err != nil {
		return err
	}
	return writeAppTargets(w, a.Targets)
}

func writeAppTargets(w io.Writer, targets []wire.AppTarget) error {
	if len(targets) == 0 {
		return nil
	}
	rows := make([][]string, len(targets))
	for i, t := range targets {
		rows[i] = []string{string(t.ID), t.Environment, string(t.NodeID), t.ComposeProject, t.DeploymentPolicy.Rollback}
	}
	_, _ = fmt.Fprintln(w)
	return table(w, []string{"TARGET", "ENVIRONMENT", "NODE", "COMPOSE PROJECT", "ROLLBACK"}, rows)
}

func writeAppRoutes(w io.Writer, routes []wire.AppRoute, app wire.App) error {
	if len(routes) == 0 {
		return nil
	}
	_, _ = fmt.Fprintln(w)
	return writeRoutes(w, routes, targetLabels([]wire.App{app}))
}

// resolveApp accepts an app id or an exact app name.
func resolveApp(ctx context.Context, api *client.Client, ref string) (domain.ID, error) {
	if id, err := domain.ParseID(ref); err == nil {
		return id, nil
	}
	query := wire.PageQuery{Limit: wire.MaxLimit}
	var match []wire.App
	for {
		page, err := api.ListApps(ctx, query)
		if err != nil {
			return "", err
		}
		for _, a := range page.Items {
			if a.Name == ref {
				match = append(match, a)
			}
		}
		if page.NextCursor == "" {
			break
		}
		query.Cursor = page.NextCursor
	}
	switch len(match) {
	case 0:
		return "", smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no app named %q", ref))
	case 1:
		return match[0].ID, nil
	}
	return "", smerr.New(smerr.CodeConflict, smerr.ReasonAmbiguousTarget, fmt.Sprintf("%d apps are named %q; use the id", len(match), ref))
}

// appCreateFlags overlay the request read from --file; only flags the user
// set override it.
type appCreateFlags struct {
	file, composeFile, name, deployedService, manifestPath string
	variables, secretRefs                                  []string
	automationIdentity                                     bool
}

func newAppsCreateCmd(env []string) *cobra.Command {
	var f appCreateFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an application",
		Long: "Create an application from a JSON request (--file, the body of POST /apps) and/or flags. A flag the\n" +
			"command line sets wins over the same field in the file. The Compose file is the control-plane source and may\n" +
			"hold ${secret:<ref>} references, never a secret value.",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req, err := f.request(cmd)
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			direct, err := api.CreateApp(cmd.Context(), req)
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(a wire.App) string { return fmt.Sprintf("created app %s (%s)", a.Name, a.ID) })
		},
	}
	cmd.Flags().StringVar(&f.file, "file", "", "JSON file with the create request")
	cmd.Flags().StringVar(&f.name, "name", "", "app name")
	cmd.Flags().StringVar(&f.deployedService, "deployed-service", "", "the Compose service CI deploys")
	cmd.Flags().StringVar(&f.manifestPath, "manifest-path", "", "path of the manifest in the repository")
	cmd.Flags().StringVar(&f.composeFile, "compose-file", "", "Compose file to keep as the control-plane source")
	cmd.Flags().StringArrayVar(&f.variables, "var", nil, "Compose variable NAME=value (repeatable)")
	cmd.Flags().StringArrayVar(&f.secretRefs, "ref", nil, "secret reference NAME=secret://apps/... (repeatable)")
	cmd.Flags().BoolVar(&f.automationIdentity, "automation-identity", false, "link the GitHub Actions automation identity")
	return cmd
}

func (f *appCreateFlags) request(cmd *cobra.Command) (wire.CreateAppRequest, error) {
	var req wire.CreateAppRequest
	if f.file != "" {
		if err := readJSONFile(f.file, &req); err != nil {
			return req, err
		}
	}
	set := cmd.Flags().Changed
	if set("name") {
		req.Name = f.name
	}
	if set("deployed-service") {
		req.DeployedService = f.deployedService
	}
	if set("manifest-path") {
		req.ManifestPath = f.manifestPath
	}
	if set("automation-identity") {
		req.AutomationIdentity = f.automationIdentity
	}
	if set("compose-file") {
		content, err := os.ReadFile(filepath.Clean(f.composeFile))
		if err != nil {
			return req, usageErrorf("read --compose-file: %s", err)
		}
		req.ComposeSource, req.ComposeContent = "control-plane", string(content)
	}
	if err := overlayPairs("--var", f.variables, &req.Variables); err != nil {
		return req, err
	}
	if err := overlayPairs("--ref", f.secretRefs, &req.SecretRefs); err != nil {
		return req, err
	}
	if req.Name == "" {
		return req, usageErrorf("--name (or a name in --file) is required")
	}
	return req, nil
}

// overlayPairs adds NAME=value pairs to *dst, creating the map when needed.
func overlayPairs(flag string, pairs []string, dst *map[string]string) error {
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name == "" {
			return usageErrorf("%s %q must be NAME=value", flag, pair)
		}
		if *dst == nil {
			*dst = map[string]string{}
		}
		(*dst)[name] = value
	}
	return nil
}

// readJSONFile decodes path strictly: an unknown field is a typo, not a no-op.
func readJSONFile(path string, dst any) error {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return usageErrorf("read %s: %s", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return usageErrorf("%s is not a valid request: %s", path, err)
	}
	return nil
}

func newAppsTargetCmd(env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage where an application runs",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newAppsTargetAddCmd(env))
	return cmd
}

type targetAddFlags struct {
	environment, node, policyFile, rollback string
	stateful                                bool
	bindAddresses                           []string
}

func newAppsTargetAddCmd(env []string) *cobra.Command {
	var f targetAddFlags
	cmd := &cobra.Command{
		Use:   "add <app>",
		Short: "Bind an application to an environment and a node",
		Long: "Add a target: the application in one environment on one node. The Compose project is derived by the\n" +
			"daemon (sm-<app>-<environment>). The deployment policy comes from --policy-file (JSON) and/or flags; a flag\n" +
			"the command line sets wins over the file.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.environment == "" || f.node == "" {
				return usageErrorf("--environment and --node are required")
			}
			policy, err := f.policy(cmd)
			if err != nil {
				return err
			}
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			app, err := resolveApp(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			node, err := resolveNode(cmd.Context(), api, f.node)
			if err != nil {
				return err
			}
			direct, err := api.CreateAppTarget(cmd.Context(), app, wire.CreateAppTargetRequest{Environment: f.environment, NodeID: node, DeploymentPolicy: policy})
			if err != nil {
				return err
			}
			return directOutput(cmd, direct, func(t wire.AppTarget) string {
				return fmt.Sprintf("added target %s (%s, project %s)", t.ID, t.Environment, t.ComposeProject)
			})
		},
	}
	cmd.Flags().StringVar(&f.environment, "environment", "", "environment name")
	cmd.Flags().StringVar(&f.node, "node", "", "node (id or name)")
	cmd.Flags().StringVar(&f.policyFile, "policy-file", "", "JSON file with the deployment policy")
	cmd.Flags().StringVar(&f.rollback, "rollback", "", "rollback mode: automatic | manual")
	cmd.Flags().BoolVar(&f.stateful, "stateful", false, "the application holds state")
	cmd.Flags().StringArrayVar(&f.bindAddresses, "bind-address", nil, "address a published port may bind (repeatable)")
	return cmd
}

func (f *targetAddFlags) policy(cmd *cobra.Command) (wire.DeploymentPolicy, error) {
	var policy wire.DeploymentPolicy
	if f.policyFile != "" {
		if err := readJSONFile(f.policyFile, &policy); err != nil {
			return policy, err
		}
	}
	set := cmd.Flags().Changed
	if set("rollback") {
		policy.Rollback = f.rollback
	}
	if set("stateful") {
		policy.Stateful = f.stateful
	}
	if set("bind-address") {
		policy.AllowedBindAddresses = f.bindAddresses
	}
	return policy, nil
}
