package cli

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/installer"
	"github.com/autarquico/supermgmt/internal/netguard"
	"github.com/autarquico/supermgmt/internal/providers/proxmox"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	checkTimeout = 30 * time.Second
	// tlsProbeMaxBody caps what the TLS probe reads of the endpoint's answer.
	tlsProbeMaxBody = 64 << 10
)

// newProvidersCmd is `sm providers` (ADR-0024).
func newProvidersCmd(env []string) *cobra.Command {
	return newProvidersCmdWith(env, nil, nil)
}

// newProvidersCmdWith builds `sm providers` with extra options for the PVE
// client and for the guarded TLS probe; tests use them to reach a fake cluster.
func newProvidersCmdWith(env []string, clientOptions []proxmox.Option, guard []netguard.Option) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List, inspect, refresh and check providers",
		Args:  noArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newProvidersListCmd(env), newProvidersGetCmd(env), newProvidersRefreshCmd(env), newProvidersCheckCmd(env, clientOptions, guard))
	return cmd
}

func newProvidersListCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List providers with their sync status",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			page, err := api.ListProviders(cmd.Context(), wire.PageQuery{})
			if err != nil {
				return err
			}
			return emit(cmd, page, func(w io.Writer) error { return writeProviders(w, page.Items) })
		},
	}
}

func writeProviders(w io.Writer, providers []wire.Provider) error {
	rows := make([][]string, len(providers))
	for i, p := range providers {
		rows[i] = []string{string(p.ID), p.Name, p.Type, string(p.Origin), p.Status, formatTimePtr(p.LastSyncAt), orDash(p.LastError)}
	}
	return table(w, []string{"ID", "NAME", "TYPE", "ORIGIN", "STATUS", "LAST SYNC", "LAST ERROR"}, rows)
}

func newProvidersGetCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <provider>",
		Short: "Show one provider (id or name)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			provider, err := resolveProvider(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			return emit(cmd, provider, func(w io.Writer) error { return writeProvider(w, provider) })
		},
	}
}

func writeProvider(w io.Writer, p wire.Provider) error {
	return fields(w, [][2]string{
		{"id", string(p.ID)},
		{"name", p.Name},
		{"type", p.Type},
		{"origin", string(p.Origin)},
		{"status", p.Status},
		{"last sync", formatTimePtr(p.LastSyncAt)},
		{"last error", orDash(p.LastError)},
		{"spec revision", fmt.Sprint(p.SpecRevision)},
	})
}

func newProvidersRefreshCmd(env []string) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh <provider>",
		Short: "Discover a provider now instead of at the next sync",
		Long: "Run a discovery of the provider now and show how it ended. Nothing is changed on the cluster: only what\n" +
			"SuperMgmt knows about it. Exit status: 0 when the sync worked, 8 when the cluster could not be read.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := newClient(cmd, env)
			if err != nil {
				return err
			}
			provider, err := resolveProvider(cmd.Context(), api, args[0])
			if err != nil {
				return err
			}
			refreshed, err := api.RefreshProvider(cmd.Context(), provider.ID)
			if err != nil {
				return err
			}
			if err := emit(cmd, refreshed, func(w io.Writer) error { return writeProvider(w, refreshed) }); err != nil {
				return err
			}
			if refreshed.Status != "ok" {
				return &childExitError{code: installer.ExitConnectivity}
			}
			return nil
		},
	}
}

// resolveProvider accepts a provider id or an exact provider name.
func resolveProvider(ctx context.Context, api *client.Client, ref string) (wire.Provider, error) {
	page, err := api.ListProviders(ctx, wire.PageQuery{})
	if err != nil {
		return wire.Provider{}, err
	}
	for _, p := range page.Items {
		if string(p.ID) == ref || p.Name == ref {
			return p, nil
		}
	}
	return wire.Provider{}, smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no provider %q", ref))
}

// providerCheck is what `sm providers check` reports.
type providerCheck struct {
	Provider          string `json:"provider,omitempty"`
	Endpoint          string `json:"endpoint"`
	OK                bool   `json:"ok"`
	Problem           string `json:"problem,omitempty"`
	Version           string `json:"version,omitempty"`
	Nodes             int    `json:"nodes,omitempty"`
	Guests            int    `json:"guests,omitempty"`
	Storages          int    `json:"storages,omitempty"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	CertificateExpiry string `json:"certificate_expires,omitempty"`
}

type checkFlags struct {
	offline, tlsOnly bool
	endpoint, caFile string
}

func newProvidersCheckCmd(env []string, clientOptions []proxmox.Option, guard []netguard.Option) *cobra.Command {
	var f checkFlags
	cmd := &cobra.Command{
		Use:   "check --offline (<name> | --tls-only --endpoint URL --ca-file FILE)",
		Short: "Check a Proxmox provider with the service stopped",
		Long: "With a provider name, read the provider from the configuration file and its API token from the secret\n" +
			"store, then connect to the cluster and read its nodes, guests and storages. The service must be stopped.\n\n" +
			"With --tls-only, connect to the endpoint and verify the certificate it serves against the CA file for the\n" +
			"endpoint's host name. The connection goes through the same outbound filter as the provider client. The installer runs it before any token exists.\n\n" +
			"Exit status: 0 when the check passes, 8 when it fails.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := f.validate(args); err != nil {
				return err
			}
			var report providerCheck
			if f.tlsOnly {
				report = checkServedTLS(cmd.Context(), f.endpoint, f.caFile, guard)
			} else {
				var err error
				if report, err = checkProviderOffline(cmd, env, args[0], clientOptions); err != nil {
					return err
				}
			}
			return finishCheck(cmd, report)
		},
	}
	cmd.Flags().BoolVar(&f.offline, "offline", false, "check with the service stopped (required)")
	cmd.Flags().BoolVar(&f.tlsOnly, "tls-only", false, "only verify the certificate the endpoint serves")
	cmd.Flags().StringVar(&f.endpoint, "endpoint", "", "with --tls-only: the endpoint to verify, https://host[:port]")
	cmd.Flags().StringVar(&f.caFile, "ca-file", "", "with --tls-only: the CA that must have signed the certificate")
	return cmd
}

func (f checkFlags) validate(args []string) error {
	switch {
	case !f.offline:
		return usageErrorf("only --offline is supported: stop the service, then run it with --offline")
	case f.tlsOnly && len(args) > 0:
		return usageErrorf("--tls-only checks an endpoint, not a provider: drop the name %q", args[0])
	case f.tlsOnly && (f.endpoint == "" || f.caFile == ""):
		return usageErrorf("--tls-only needs --endpoint and --ca-file")
	case !f.tlsOnly && len(args) == 0:
		return usageErrorf("name the provider to check, or use --tls-only --endpoint URL --ca-file FILE")
	case !f.tlsOnly && (f.endpoint != "" || f.caFile != ""):
		return usageErrorf("--endpoint and --ca-file belong to --tls-only: a named provider brings its own")
	}
	return nil
}

// finishCheck prints the report and turns a failed check into exit status 8.
func finishCheck(cmd *cobra.Command, r providerCheck) error {
	err := emit(cmd, r, func(w io.Writer) error { return renderCheck(w, r) })
	if err != nil {
		return err
	}
	if !r.OK {
		return &childExitError{code: installer.ExitConnectivity}
	}
	return nil
}

func renderCheck(w io.Writer, r providerCheck) error {
	subject := r.Endpoint
	if r.Provider != "" {
		subject = r.Provider + " (" + r.Endpoint + ")"
	}
	if !r.OK {
		_, err := fmt.Fprintf(w, "FAILED %s: %s\n", subject, r.Problem)
		return err
	}
	pairs := [][2]string{{"endpoint", r.Endpoint}}
	if r.Version != "" {
		pairs = append(pairs, [2]string{"proxmox ve", r.Version},
			[2]string{"cluster", fmt.Sprintf("%d nodes, %d guests, %d storages", r.Nodes, r.Guests, r.Storages)})
	}
	if r.CertificateSHA256 != "" {
		pairs = append(pairs, [2]string{"certificate sha256", r.CertificateSHA256}, [2]string{"certificate expires", r.CertificateExpiry})
	}
	if _, err := fmt.Fprintf(w, "OK %s\n", subject); err != nil {
		return err
	}
	return fields(w, pairs)
}

// ---- the named provider ---------------------------------------------------------

func checkProviderOffline(cmd *cobra.Command, env []string, name string, clientOptions []proxmox.Option) (providerCheck, error) {
	session, err := openOffline(cmd, env)
	if err != nil {
		return providerCheck{}, err
	}
	defer session.close()
	p, ok := proxmoxProviderIn(session.cfg, name)
	if !ok {
		return providerCheck{}, usageErrorf("the configuration file has no Proxmox provider named %q", name)
	}
	report := providerCheck{Provider: name, Endpoint: p.Endpoint}
	token, err := tokenOf(cmd.Context(), session, p.CredentialRef)
	if err != nil {
		report.Problem = "the API token cannot be read: " + err.Error()
		return report, nil
	}
	ca, err := readCA(p.CAFile)
	if err != nil {
		report.Problem = err.Error()
		return report, nil
	}
	client, err := proxmox.New(p.Endpoint, ca, token, clientOptions...)
	if err != nil {
		report.Problem = err.Error()
		return report, nil
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), checkTimeout)
	defer cancel()
	return probeCluster(ctx, client, report, p.Endpoint), nil
}

func proxmoxProviderIn(cfg *config.Config, name string) (config.ProxmoxProvider, bool) {
	for _, p := range cfg.Providers {
		if p.Proxmox != nil && p.Proxmox.Name == name {
			return *p.Proxmox, true
		}
	}
	return config.ProxmoxProvider{}, false
}

// tokenOf reads the API token from the secret store, which the stopped
// service's database and key directory hold.
func tokenOf(ctx context.Context, s *offlineSession, ref string) (audit.Secret, error) {
	name, ok := strings.CutPrefix(ref, "secret://")
	if !ok {
		return "", fmt.Errorf("credential_ref %q is not a secret:// reference", ref)
	}
	repo, err := s.repo(ctx)
	if err != nil {
		return "", err
	}
	if repo == nil {
		return "", errors.New("there is no initialized database: run sm server init first")
	}
	readable := readableSecrets{ReadOnlySecrets: database.ReadOnlySecrets{Q: s.db.Querier()}}
	keys, err := secrets.OpenFileKeysReadOnly(ctx, s.keysDir, readable)
	if err != nil {
		return "", err
	}
	return secrets.NewStore(keys, readable, domain.UUIDv7Generator{}, domain.SystemClock{}).Get(ctx, secrets.Ref{Name: name})
}

// readableSecrets is the read-only secrets repository that can also read
// secret versions, which is all a check needs of the store.
type readableSecrets struct{ database.ReadOnlySecrets }

func (r readableSecrets) Get(ctx context.Context, name string, version int) (secrets.Record, error) {
	stored, err := database.GetSecret(ctx, r.Q, name, version)
	if err != nil {
		return secrets.Record{}, err
	}
	metadata, err := json.Marshal(stored.Metadata)
	if err != nil {
		return secrets.Record{}, fmt.Errorf("encode secret metadata: %w", err)
	}
	return secrets.Record{
		ID: stored.ID, Name: stored.Name, Version: stored.Version, EnvelopeVersion: stored.EnvelopeVersion, KEKID: stored.KEKID,
		WrappedDEK: stored.WrappedDEK, Ciphertext: stored.Ciphertext, MetadataJSON: string(metadata), CreatedAt: stored.CreatedAt,
	}, nil
}

func readCA(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read ca_file: %w", err)
	}
	return data, nil
}

// probeCluster reads what discovery reads and judges whether it is usable.
func probeCluster(ctx context.Context, client proxmox.Client, report providerCheck, endpoint string) providerCheck {
	fail := func(err error) providerCheck {
		report.Problem = explainProbeFailure(err, endpoint)
		return report
	}
	version, err := client.Version(ctx)
	if err != nil {
		return fail(err)
	}
	report.Version = version.Version
	if !version.Supported() {
		return fail(fmt.Errorf("version %s is not supported: Proxmox VE %d.x is required", version.Version, proxmox.SupportedMajor))
	}
	inventory, err := client.Resources(ctx)
	if err != nil {
		return fail(err)
	}
	if _, err := client.Permissions(ctx); err != nil {
		return fail(err)
	}
	report.Nodes, report.Guests, report.Storages = len(inventory.Nodes), len(inventory.Guests), len(inventory.Storages)
	if report.Nodes == 0 {
		return fail(errors.New("the token sees no cluster node: it needs Sys.Audit on /nodes"))
	}
	report.OK = true
	return report
}

// explainProbeFailure adds the usual cause of a connection that never got an
// answer: PVE answers on port 8006 and its firewall can block the caller.
func explainProbeFailure(err error, endpoint string) string {
	var api *proxmox.APIError
	if errors.As(err, &api) {
		return err.Error()
	}
	if u, perr := url.Parse(endpoint); perr == nil {
		return fmt.Sprintf("%v (this host must reach %s; check the Proxmox firewall for the API port)", err, u.Host)
	}
	return err.Error()
}

// ---- the served certificate -------------------------------------------------------

// checkServedTLS asks the endpoint for its root page through the outbound
// filter and verifies the chain it serves against the CA file, for the
// endpoint's own host name. Only the handshake matters: any HTTP answer, even
// an error status, proves the certificate.
func checkServedTLS(ctx context.Context, endpoint, caFile string, guard []netguard.Option) providerCheck {
	report := providerCheck{Endpoint: endpoint}
	host, address, err := splitEndpoint(endpoint)
	if err != nil {
		report.Problem = err.Error()
		return report
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		report.Problem = err.Error()
		return report
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	client := netguard.NewClient(netguard.Allow{AllowAllPrivate: true}, nil, checkTimeout, tlsProbeMaxBody,
		append([]netguard.Option{netguard.WithRootCAs(pool)}, guard...)...)
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+address+"/", http.NoBody)
	if err != nil {
		report.Problem = err.Error()
		return report
	}
	response, err := client.Do(request) //nolint:bodyclose // closed below when there is a response
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if response == nil || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		report.Problem = fmt.Sprintf("the certificate served by %s is not trusted for %s with %s: %v", address, host, caFile, err)
		return report
	}
	leaf := response.TLS.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	report.CertificateSHA256 = hex.EncodeToString(sum[:])
	report.CertificateExpiry = leaf.NotAfter.UTC().Format(time.RFC3339)
	report.OK = true
	return report
}

func splitEndpoint(endpoint string) (host, address string, err error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return "", "", fmt.Errorf("endpoint %q must look like https://host[:port]", endpoint)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname(), net.JoinHostPort(u.Hostname(), port), nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	data, err := readCA(path)
	if err != nil {
		return nil, fmt.Errorf("read the CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return pool, nil
}
