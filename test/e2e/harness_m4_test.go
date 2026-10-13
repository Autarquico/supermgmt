//go:build e2e && fixtures

package e2e_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/providers/github/ghfake"
	"github.com/autarquico/supermgmt/test/e2e/harness"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// The M4 world: a simulated GitHub with a virtual Sigstore and an OCI registry (the ghsim
// container, test/e2e/ghsim), a fixture node with its own Docker, and `sm` either as a server in
// a container or as a local daemon on the test machine. Everything the product reaches over the
// network is served over TLS under the test CA.
const (
	m4GitHubAlias   = "ghsim.test"
	m4RegistryAlias = "registry.test"
	m4RegistryHost  = m4RegistryAlias + ":5000"
	m4ServerAlias   = "sm.test"

	m4Owner     = "acme"
	m4OwnerID   = 77
	m4Repo      = "shop"
	m4RepoID    = 4242
	m4Branch    = "main"
	m4NodeName  = "m4-node"
	m4EnvName   = "staging"
	m4AppName   = "shop"
	m4Service   = "web"
	m4ImageRepo = "shop"

	// m4CIWorkflow produces the required check; m4DeployWorkflow builds and attests the image.
	m4CIWorkflow     = ".github/workflows/ci.yml"
	m4DeployWorkflow = ".github/workflows/deploy.yml"
	m4ActionsAppID   = 15368 // GitHub Actions, the app of Actions check runs

	m4GitHubTokenSecret  = "github/token"
	m4WebhookSecretName  = "github/webhook"
	m4WebhookSecretValue = "ghsim-webhook-secret-0123456789"
	m4GhsimImage         = "sm-e2e-ghsim:local"
	m4AppPort            = 8080
	m4Poll               = 2 * time.Second
	m4DeployTimeout      = 4 * time.Minute
	m4SetupJobTimeout    = 4 * time.Minute
)

// m4Compose is the control-plane Compose source of the shop: one service on loopback.
const m4Compose = `services:
  web:
    image: ` + m4RegistryHost + `/` + m4ImageRepo + `:placeholder
    ports:
      - {target: 8080, published: 8080, host_ip: 127.0.0.1}
`

// ---- ghsim ------------------------------------------------------------------------------------

// m4Sim is the running ghsim container and the ways to talk to it from the test machine.
type m4Sim struct {
	t            testing.TB
	c            *harness.Container
	ca           *harness.CA
	caFile       string // host path of the CA that signed ghsim's certificate
	apiPort      int    // published :443
	registryPort int    // published :5000
	oidcPort     int    // published :8444, the Actions issuer
	http         *http.Client
	binary       string // the Linux ghsim, also the content of every pushed image
	arch         string
}

func m4BuildGhsim(t testing.TB) (binary, arch string) {
	t.Helper()
	arch = harness.DockerArch(t)
	path, err := m3Once("ghsim-"+arch, func() (string, error) {
		out := filepath.Join(harness.WorkDir(), "ghsim-"+arch)
		env := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
		res, err := harness.Run(context.Background(), harness.RepoRoot(), env, "", "go", "build", "-trimpath", "-o", out, "./test/e2e/ghsim")
		if e := commandFailure("go build ghsim", res, err); e != nil {
			return "", e
		}
		return out, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return path, arch
}

func m4BuildGhsimImage(t testing.TB, binary string) string {
	t.Helper()
	tag, err := m3Once("ghsim-image", func() (string, error) {
		dir := filepath.Join(harness.WorkDir(), "ghsim-context")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		for src, name := range map[string]string{binary: "ghsim", filepath.Join(harness.RepoRoot(), "test", "e2e", "ghsim", "Dockerfile"): "Dockerfile"} {
			content, err := os.ReadFile(src)
			if err != nil {
				return "", err
			}
			if err := os.WriteFile(filepath.Join(dir, name), content, 0o755); err != nil {
				return "", err
			}
		}
		res, err := harness.Docker(context.Background(), "", "build", "--quiet", "--tag", m4GhsimImage, dir)
		if e := commandFailure("docker build ghsim", res, err); e != nil {
			return "", e
		}
		return m4GhsimImage, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

// startM4Sim runs ghsim on the network under the names the product reaches it by. A daemon on the
// test machine cannot use loopback (the product refuses it for providers), so with reachableAt
// set, ghsim also listens on every host interface and its certificate names that address.
func startM4Sim(t testing.TB, net *harness.Network, ca *harness.CA, reachableAt string) *m4Sim {
	t.Helper()
	binary, arch := m4BuildGhsim(t)
	dir := t.TempDir()
	ips := []string{"127.0.0.1"}
	publish := "127.0.0.1::"
	if reachableAt != "" {
		ips, publish = append(ips, reachableAt), ""
	}
	leaf := ca.Issue(t, []string{m4GitHubAlias, m4RegistryAlias, "localhost"}, ips)
	certPath, keyPath := leaf.WriteTo(t, dir, "ghsim")
	if err := os.Chmod(keyPath, 0o644); err != nil { // a throwaway key
		t.Fatal(err)
	}
	name := "sm-e2e-ghsim-" + harness.Suffix()
	harness.MustDocker(t, "create", "--name", name, "--network", net.Name,
		"--network-alias", m4GitHubAlias, "--network-alias", m4RegistryAlias,
		"--publish", publish+"443", "--publish", publish+"5000", "--publish", publish+"8444", m4BuildGhsimImage(t, binary))
	c := harness.Adopt(t, name)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("ghsim logs:\n%s", c.Logs())
		}
		_, _ = harness.Docker(context.Background(), "", "rm", "--force", "--volumes", name)
	})
	c.Copy(certPath, "/ghsim.crt")
	c.Copy(keyPath, "/ghsim.key")
	harness.MustDocker(t, "start", name)
	pool := ca.Pool()
	s := &m4Sim{
		t: t, c: c, ca: ca, caFile: ca.WriteCA(t, dir), apiPort: c.HostPort("443"), registryPort: c.HostPort("5000"), oidcPort: c.HostPort("8444"),
		http:   &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
		binary: binary, arch: arch,
	}
	s.waitReady()
	return s
}

// m4HostAddress is an address of the test machine other than loopback, or "" when it has none.
func m4HostAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ip, ok := a.(*net.IPNet)
		if !ok || ip.IP.To4() == nil || !ip.IP.IsGlobalUnicast() || ip.IP.IsLinkLocalUnicast() {
			continue
		}
		return ip.IP.String()
	}
	return ""
}

func (s *m4Sim) simURL(path string) string {
	return fmt.Sprintf("https://localhost:%d%s", s.apiPort, path)
}

func (s *m4Sim) waitReady() {
	s.t.Helper()
	deadline := harness.Now().Add(time.Minute)
	for harness.Now().Before(deadline) {
		resp, err := s.http.Get(s.simURL("/sim/health"))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	s.t.Fatalf("ghsim did not become ready\n%s", s.c.Logs())
}

// post sends a JSON control request and fails the test unless ghsim accepts it.
func (s *m4Sim) post(path string, body any) []byte {
	s.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		s.t.Fatal(err)
	}
	resp, err := s.http.Post(s.simURL(path), "application/json", bytes.NewReader(raw))
	if err != nil {
		s.t.Fatalf("ghsim POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("ghsim POST %s = %d: %s", path, resp.StatusCode, answer)
	}
	return answer
}

func (s *m4Sim) get(path string) []byte {
	s.t.Helper()
	resp, err := s.http.Get(s.simURL(path))
	if err != nil {
		s.t.Fatalf("ghsim GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("ghsim GET %s = %d: %s", path, resp.StatusCode, answer)
	}
	return answer
}

// addShopRepository registers acme/shop with its owner.
func (s *m4Sim) addShopRepository() {
	s.t.Helper()
	s.post("/sim/repos", map[string]any{"id": m4RepoID, "owner_id": m4OwnerID, "owner": m4Owner, "name": m4Repo, "default_branch": m4Branch})
}

// reportCI makes the required check of commit run with the given status and conclusion, the way
// the CI workflow's Actions run reports it.
func (s *m4Sim) reportCI(commit, status, conclusion string) {
	s.t.Helper()
	const suite, run = 9001, 5001
	s.post("/sim/workflow-runs", map[string]any{
		"repo_id": m4RepoID, "suite_id": suite, "id": run, "run_attempt": 1, "path": m4CIWorkflow,
		"head_branch": m4Branch, "head_sha": commit, "event": "push", "status": status, "conclusion": conclusion,
	})
	s.post("/sim/check-runs", map[string]any{
		"repo_id": m4RepoID, "commit": commit, "id": 7001, "name": "build", "app_id": m4ActionsAppID,
		"status": status, "conclusion": conclusion, "suite_id": suite,
	})
}

// attest makes GitHub hold a verified-by-the-product provenance attestation for digest, as the
// deploy workflow's attest step produces it.
func (s *m4Sim) attest(digest, commit string) {
	s.t.Helper()
	s.post("/sim/attestations", map[string]any{
		"digest": digest, "owner": m4Owner, "repo": m4Repo, "repository_id": m4RepoID, "workflow_path": m4DeployWorkflow,
		"branch": m4Branch, "commit_sha": commit, "run_id": 5002, "run_attempt": 1,
	})
}

// deliverWebhook has ghsim send a signed check_run webhook for commit to the server.
func (s *m4Sim) deliverWebhook(url, commit, delivery string, badSignature bool) int {
	s.t.Helper()
	var answer struct{ Status int }
	if err := json.Unmarshal(s.post("/sim/webhooks", map[string]any{
		"url": url, "secret": m4WebhookSecretValue, "ca_pem": string(s.ca.CertPEM), "event": "check_run",
		"delivery": delivery, "repository_id": m4RepoID, "head_sha": commit, "bad_signature": badSignature,
	}), &answer); err != nil {
		s.t.Fatal(err)
	}
	return answer.Status
}

// oidcToken is a token signed by the simulated Actions issuer over claims; the issuer claim is the
// issuer's public origin unless claims name another.
func (s *m4Sim) oidcToken(claims map[string]any) string {
	s.t.Helper()
	var answer struct{ Token string }
	if err := json.Unmarshal(s.post("/sim/oidc-tokens", map[string]any{"claims": claims}), &answer); err != nil {
		s.t.Fatal(err)
	}
	return answer.Token
}

// trustedRootCache is the cache document the daemon's Sigstore trust roots read: the virtual
// Sigstore as the last good copy of both the public-good and the GitHub root, fetched now. The
// daemon then never reaches the real TUF repositories, and the product build is the one that ships.
func (s *m4Sim) trustedRootCache() []byte {
	s.t.Helper()
	doc, err := json.Marshal(map[string]any{"fetched_at": harness.Now().UTC(), "trusted_root": json.RawMessage(s.get("/sim/trusted-root"))})
	if err != nil {
		s.t.Fatal(err)
	}
	return doc
}

// ---- images in the registry --------------------------------------------------------------------

// m4Image is one build of the shop: a version and whether its health endpoint answers.
type m4Image struct {
	Version   string
	Unhealthy bool
}

// pushImage uploads the image to the registry by digest and returns that digest. The image is a
// single layer holding the ghsim binary, which serves /health on :8080.
func (s *m4Sim) pushImage(img m4Image) string {
	s.t.Helper()
	binary, err := os.ReadFile(s.binary)
	if err != nil {
		s.t.Fatal(err)
	}
	layer, diffID := m4Layer(s.t, binary, img)
	config := s.imageConfig(diffID)
	layerDigest, configDigest := m4Digest(layer), m4Digest(config)
	s.uploadBlob(layerDigest, layer)
	s.uploadBlob(configDigest, config)
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(config), "digest": configDigest},
		"layers": []map[string]any{{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": len(layer), "digest": layerDigest}},
	})
	if err != nil {
		s.t.Fatal(err)
	}
	digest := m4Digest(manifest)
	s.registryPut("/v2/"+m4ImageRepo+"/manifests/"+digest, "application/vnd.docker.distribution.manifest.v2+json", manifest)
	return digest
}

func (s *m4Sim) imageConfig(diffID string) []byte {
	probe := fmt.Sprintf("http://127.0.0.1:%d/health", m4AppPort)
	config, err := json.Marshal(map[string]any{
		"architecture": s.arch, "os": "linux",
		"config": map[string]any{
			"Entrypoint":   []string{"/ghsim", "app"},
			"ExposedPorts": map[string]any{fmt.Sprintf("%d/tcp", m4AppPort): map[string]any{}},
			"Healthcheck": map[string]any{
				"Test": []string{"CMD", "/ghsim", "probe", probe}, "Interval": int64(time.Second), "Timeout": int64(3 * time.Second), "Retries": 3,
			},
		},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{diffID}},
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return config
}

func (s *m4Sim) uploadBlob(digest string, content []byte) {
	s.t.Helper()
	url := fmt.Sprintf("https://localhost:%d/v2/%s/blobs/uploads/?digest=%s", s.registryPort, m4ImageRepo, digest)
	resp, err := s.http.Post(url, "application/octet-stream", bytes.NewReader(content))
	if err != nil {
		s.t.Fatalf("registry upload %s: %v", digest, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		answer, _ := io.ReadAll(resp.Body)
		s.t.Fatalf("registry upload %s = %d: %s", digest, resp.StatusCode, answer)
	}
}

func (s *m4Sim) registryPut(path, contentType string, body []byte) {
	s.t.Helper()
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("https://localhost:%d%s", s.registryPort, path), bytes.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := s.http.Do(req)
	if err != nil {
		s.t.Fatalf("registry PUT %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		answer, _ := io.ReadAll(resp.Body)
		s.t.Fatalf("registry PUT %s = %d: %s", path, resp.StatusCode, answer)
	}
}

func m4Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// m4Layer is the image's filesystem as a gzip tar, and the digest of the tar itself (the diff id).
func m4Layer(t testing.TB, binary []byte, img m4Image) (compressed []byte, diffID string) {
	t.Helper()
	files := []struct {
		name    string
		mode    int64
		content []byte
	}{
		{"ghsim", 0o755, binary},
		{"etc/app/version", 0o644, []byte(img.Version + "\n")},
	}
	if img.Unhealthy {
		files = append(files, struct {
			name    string
			mode    int64
			content []byte
		}{"etc/app/unhealthy", 0o644, []byte("1\n")})
	}
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	for _, dir := range []string{"etc/", "etc/app/"} {
		if err := tw.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: f.mode, Size: int64(len(f.content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	if _, err := zw.Write(plain.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return zipped.Bytes(), m4Digest(plain.Bytes())
}

// m4ImageRef is where the node pulls an image digest from.
func m4ImageRef(digest string) string { return m4RegistryHost + "/" + m4ImageRepo + "@" + digest }

// ---- the node ----------------------------------------------------------------------------------

// m4Node is a fixture node (systemd, sshd, Docker with Compose) that trusts the registry and can
// be administered with a key the test holds.
type m4Node struct {
	fx         *fixture.Node
	c          *harness.Container
	adminKey   string // host path of the private key for the bootstrap account
	hostKeyPin string // the sshd host key in authorized_keys form
}

func startM4Node(t *testing.T, net *harness.Network, sim *m4Sim) *m4Node {
	t.Helper()
	ctx := context.Background()
	if err := fixture.Build(ctx); err != nil {
		t.Fatal(err)
	}
	fx, err := fixture.Start(ctx, fixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fx.Stop(context.WithoutCancel(ctx)) })
	c := harness.Adopt(t, fx.Name)
	c.Connect(net)

	// The node's Docker pulls from the registry by name over TLS under the test CA.
	c.MustExec(ctx, "sh", "-c", fmt.Sprintf("echo '%s %s' >> /etc/hosts", sim.c.Address(net.Name), m4RegistryAlias))
	c.WriteFile(ctx, "/etc/docker/certs.d/"+m4RegistryHost+"/ca.crt", sim.ca.CertPEM, "0644")

	n := &m4Node{fx: fx, c: c, hostKeyPin: strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(fx.HostKey)))}
	n.adminKey = n.authorizeAdminKey(t)
	return n
}

// authorizeAdminKey creates a key for the bootstrap account `admin` (the fixture only exposes its
// own as a signer) and returns the host path of the private key, mode 0600.
func (n *m4Node) authorizeAdminKey(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "m4 node admin")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	res := n.c.Exec(context.Background(), string(cryptossh.MarshalAuthorizedKey(sshPub)), "sh", "-c", "cat >> /home/admin/.ssh/authorized_keys")
	if res.Code != 0 {
		t.Fatalf("authorize the admin key: %s", res.Output())
	}
	return harness.WriteHostFile(t, t.TempDir(), "node-admin.key", pem.EncodeToMemory(block), 0o600)
}

// sshEndpoint is the static provider's endpoint block for a daemon that reaches the node at host:port.
func (n *m4Node) sshEndpoint(host string, port int) string {
	return fmt.Sprintf("    endpoint:\n      host: %s\n      port: %d\n      user: supermgmt\n      admin_user: %s\n      host_public_key: %q\n",
		host, port, fixture.AdminUser, n.hostKeyPin)
}

// containerImage is the image reference the node's Docker runs the named container from.
func (n *m4Node) containerImage(ctx context.Context, name string) (string, error) {
	res := n.c.Exec(ctx, "", "docker", "inspect", "--format", "{{.Config.Image}}", name)
	if res.Code != 0 {
		return "", fmt.Errorf("docker inspect %s: %s", name, res.Output())
	}
	return strings.TrimSpace(res.Stdout), nil
}

// ---- configuration shared by both modes ----------------------------------------------------------

// m4ProvidersYAML is the part of the configuration that is the same in both modes: one
// environment, the node (reached with the admin key at keyPath) and the GitHub provider (reached
// at apiURL, trusting caFile).
func m4ProvidersYAML(node *m4Node, nodeHost string, nodePort int, keyPath, apiURL, caFile string) string {
	return fmt.Sprintf(`environments:
  - name: %[1]s
    risk_level: staging
github:
  ci_poll_initial: 2s
  ci_poll_max: 4s
providers:
  - type: ssh
    name: %[2]s
%[3]s    admin_credential_ref: file://%[4]s
    environment: %[1]s
  - type: github
    name: ghsim
    api_url: %[5]s
    credential_ref: secret://%[6]s
    webhook_secret_ref: secret://%[7]s
    ca_file: %[8]s
`, m4EnvName, m4NodeName, node.sshEndpoint(nodeHost, nodePort), keyPath, apiURL, m4GitHubTokenSecret, m4WebhookSecretName, caFile)
}

// ---- driving a world ---------------------------------------------------------------------------

// m4World is a running SuperMgmt (server or local daemon) wired to ghsim and a fixture node.
type m4World struct {
	t    *testing.T
	api  *client.Client
	sim  *m4Sim
	node *m4Node
	// webhookURL is where ghsim delivers webhooks; empty in local mode, which has no webhook endpoint.
	webhookURL string
}

func (w *m4World) ctx() context.Context { return context.Background() }

// settleJob approves the job when it waits for approval and returns once it has succeeded.
func (w *m4World) settleJob(id domain.ID, timeout time.Duration) wire.JobDetail {
	w.t.Helper()
	deadline := harness.Now().Add(timeout)
	var last wire.JobDetail
	for harness.Now().Before(deadline) {
		job, err := w.api.GetJob(w.ctx(), id)
		if err != nil {
			w.t.Fatalf("get job %s: %v", id, err)
		}
		last = job
		switch {
		case job.Job.State == domain.JobSucceeded:
			return job
		case job.Job.State == domain.JobAwaitingApproval:
			harness.ApproveJob(w.ctx(), w.t, w.api, id)
		case job.Job.State.Terminal():
			w.t.Fatalf("job %s ended %s: %+v", id, job.Job.State, job.Job.Error)
		}
		time.Sleep(time.Second)
	}
	w.t.Fatalf("job %s still %s after %s", id, last.Job.State, timeout)
	return last
}

// waitFor polls until the provider and the node both exist, as the daemon's static
// configuration reconcile creates them at start.
func (w *m4World) waitForStaticConfig() (provider wire.Provider, node wire.Node) {
	w.t.Helper()
	deadline := harness.Now().Add(time.Minute)
	for harness.Now().Before(deadline) {
		providers, err := w.api.ListProviders(w.ctx(), wire.PageQuery{Limit: wire.MaxLimit})
		if err != nil {
			w.t.Fatal(err)
		}
		nodes, err := w.api.ListNodes(w.ctx(), wire.NodeQuery{PageQuery: wire.PageQuery{Limit: wire.MaxLimit}})
		if err != nil {
			w.t.Fatal(err)
		}
		provider, node = wire.Provider{}, wire.Node{}
		for _, p := range providers.Items {
			if p.Type == "github" && p.Name == "ghsim" {
				provider = p
			}
		}
		for _, n := range nodes.Items {
			if n.Name == m4NodeName {
				node = n
			}
		}
		if provider.ID != "" && node.ID != "" {
			return provider, node
		}
		time.Sleep(time.Second)
	}
	w.t.Fatalf("the static configuration did not produce the GitHub provider and the node (provider %+v, node %+v)", provider, node)
	return provider, node
}

// prepareNode runs node.setup with Docker access and probes the node until it can deploy Compose.
func (w *m4World) prepareNode(node wire.Node) wire.Node {
	w.t.Helper()
	w.probe(node)
	plan, err := w.api.CreatePlan(w.ctx(), wire.CreatePlanRequest{
		Action:     "node.setup",
		Targets:    []wire.ResourceRef{{Type: domain.ResourceNode, ID: node.ID}},
		Parameters: map[string]any{"docker_access": "true", "logs_mode": "journal-group"},
	})
	if err != nil {
		w.t.Fatalf("plan node.setup: %v", err)
	}
	submitted, err := w.api.SubmitPlan(w.ctx(), plan.PlanID, plan.PlanHash)
	if err != nil {
		w.t.Fatalf("submit node.setup: %v", err)
	}
	w.settleJob(jobOf(w.t, submitted), m4SetupJobTimeout)

	w.probe(node)
	ready, err := w.api.GetNode(w.ctx(), node.ID, true)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, c := range ready.Capabilities {
		if c.Name == "docker.compose.deploy" && c.Available {
			return ready
		}
	}
	w.t.Fatalf("the node cannot deploy Compose after setup: capabilities %+v", ready.Capabilities)
	return ready
}

// probe has the daemon discover the node's capabilities now.
func (w *m4World) probe(node wire.Node) {
	w.t.Helper()
	probe, err := w.api.ProbeNode(w.ctx(), node.ID)
	if err != nil {
		w.t.Fatalf("probe the node: %v", err)
	}
	w.settleJob(jobOf(w.t, probe), m4SetupJobTimeout)
}

// shopPolicy is the target's deployment policy: a TCP health check on the published port.
func shopPolicy() wire.DeploymentPolicy {
	return wire.DeploymentPolicy{
		Rollback: "manual",
		Health:   &wire.HealthCheck{Type: "tcp", Scope: "node", Port: m4AppPort, Timeout: "3s", Interval: "2s", Attempts: 15},
	}
}

// createShop creates the CI-gated application for acme/shop and its target on the node.
func (w *m4World) createShop(provider wire.Provider, node wire.Node) wire.AppTarget {
	w.t.Helper()
	providerID, repositoryID := provider.ID, int64(m4RepoID)
	created, err := w.api.CreateApp(w.ctx(), wire.CreateAppRequest{
		Name: m4AppName, ProviderID: &providerID, RepositoryID: &repositoryID, ManifestPath: ".supermgmt.yaml",
		DeployedService: m4Service, ImagePolicy: wire.ImagePolicy{Deployed: m4RegistryHost + "/" + m4ImageRepo},
		ComposeSource: "control-plane", ComposeContent: m4Compose,
		CIPolicy: &wire.CIPolicy{
			RepositoryID: m4RepoID, OwnerID: m4OwnerID, Branch: m4Branch, AllowedEvents: []string{"push"},
			RequiredChecks: []wire.RequiredCheck{{Name: "build", AppID: m4ActionsAppID, WorkflowPath: m4CIWorkflow}},
			DeployWorkflow: m4DeployWorkflow,
		},
	})
	if err != nil {
		w.t.Fatalf("create the app: %v", err)
	}
	if created.Pending != nil {
		w.settleJob(created.Pending.Job.ID, time.Minute)
	}
	app := w.findApp(m4AppName)
	target, err := w.api.CreateAppTarget(w.ctx(), app.ID, wire.CreateAppTargetRequest{Environment: m4EnvName, NodeID: node.ID, DeploymentPolicy: shopPolicy()})
	if err != nil {
		w.t.Fatalf("create the target: %v", err)
	}
	if target.Pending != nil {
		w.settleJob(target.Pending.Job.ID, time.Minute)
	}
	return w.findApp(m4AppName).Targets[0]
}

func (w *m4World) findApp(name string) wire.App {
	w.t.Helper()
	apps, err := w.api.ListApps(w.ctx(), wire.PageQuery{Limit: wire.MaxLimit})
	if err != nil {
		w.t.Fatal(err)
	}
	for _, a := range apps.Items {
		if a.Name == name {
			full, err := w.api.GetApp(w.ctx(), a.ID)
			if err != nil {
				w.t.Fatal(err)
			}
			return full
		}
	}
	w.t.Fatalf("no app named %q in %+v", name, apps.Items)
	return wire.App{}
}

// waitDeployment polls until the deployment is in one of the states and returns it.
func (w *m4World) waitDeployment(id domain.ID, timeout time.Duration, states ...string) wire.Deployment {
	w.t.Helper()
	deadline := harness.Now().Add(timeout)
	var last wire.Deployment
	for harness.Now().Before(deadline) {
		d, err := w.api.GetDeployment(w.ctx(), id)
		if err != nil {
			w.t.Fatalf("get deployment %s: %v", id, err)
		}
		last = d
		for _, s := range states {
			if d.State == s {
				return d
			}
		}
		time.Sleep(m4Poll)
	}
	w.t.Fatalf("deployment %s is %s (%s/%s) after %s, want one of %v\nsteps:\n%s", id, last.State, last.StateCode, last.StateReason, timeout, states, m4Timeline(last))
	return last
}

// deployShop requests the deployment of commit with the image digest.
func (w *m4World) deployShop(target wire.AppTarget, commit, digest string) wire.Deployment {
	w.t.Helper()
	d, err := w.api.CreateDeployment(w.ctx(), wire.CreateDeploymentRequest{
		AppTargetID: target.ID, Kind: "deploy", CommitSHA: commit, Images: []wire.RequestedImage{{Service: m4Service, Digest: digest}},
	})
	if err != nil {
		w.t.Fatalf("create the deployment: %v", err)
	}
	return d
}

// runningImage is the image reference of the running shop container on the node.
func (w *m4World) runningImage(target wire.AppTarget) string {
	w.t.Helper()
	ctx := w.ctx()
	out := w.node.c.MustExec(ctx, "docker", "ps", "--filter", "label=com.docker.compose.project="+target.ComposeProject, "--format", "{{.Names}}")
	names := strings.Fields(out)
	if len(names) != 1 {
		w.t.Fatalf("containers of project %s on the node = %q, want exactly one", target.ComposeProject, names)
	}
	image, err := w.node.containerImage(ctx, names[0])
	if err != nil {
		w.t.Fatal(err)
	}
	return image
}

// m4Timeline renders a deployment's steps with the error of the one that failed.
func m4Timeline(d wire.Deployment) string {
	var b strings.Builder
	for _, s := range d.Steps {
		fmt.Fprintf(&b, "  %d %s %s (attempt %d)", s.Ordinal, s.Name, s.State, s.Attempt)
		if s.Error != nil {
			fmt.Fprintf(&b, ": %s/%s cause=%q: %s", s.Error.Code, s.Error.Reason, s.Error.Cause, s.Error.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// diagnosis is what the daemon knows about a deployment's job: its error and its operation intents.
func (w *m4World) diagnosis(d wire.Deployment) string {
	if d.JobID == nil {
		return "(no job)"
	}
	job, err := w.api.GetJob(w.ctx(), *d.JobID)
	if err != nil {
		return fmt.Sprintf("(job %s unreadable: %v)", *d.JobID, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "job %s %s attempts=%d error=%+v\n", job.Job.ID, job.Job.State, job.Job.Attempts, job.Job.Error)
	for _, in := range job.Intents {
		fmt.Fprintf(&b, "  intent %s %s %s outcome=%q evidence=%s\n", in.Step, in.Operation, in.State, in.Outcome, in.Evidence)
	}
	node := w.node.c.Exec(w.ctx(), "", "sh", "-c", "id supermgmt; ls -laR /srv/supermgmt 2>&1 | head -40; docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}'")
	fmt.Fprintf(&b, "node:\n%s\n", node.Output())
	return b.String()
}

// m4SigstoreCacheFiles are the cache files of the two trust roots (public-good and GitHub).
var m4SigstoreCacheFiles = []string{"sigstore.trusted_root.json", "github.trusted_root.json"}

// ---- the server world ----------------------------------------------------------------------------

// newM4ServerWorld installs `sm server` in a Debian systemd container, makes its static
// configuration name the fixture node and ghsim, seals the secrets it needs, and signs an
// administrator in.
func newM4ServerWorld(t *testing.T) *m4World {
	t.Helper()
	ctx := context.Background()
	net, ca := harness.NewNetwork(t), harness.NewCA(t)
	sim := startM4Sim(t, net, ca, "")
	node := startM4Node(t, net, sim)
	srv := harness.StartServer(t, net, ca, harness.ServerOptions{Mode: harness.Direct, Aliases: []string{m4ServerAlias}})
	srv.WaitReady(ctx)
	c := srv.C

	c.MustExec(ctx, "systemctl", "stop", "supermgmt")
	for name, value := range map[string]string{m4GitHubTokenSecret: ghfake.DefaultToken, m4WebhookSecretName: m4WebhookSecretValue} {
		res := c.Exec(ctx, value+"\n", "runuser", "-u", "supermgmt", "--", harness.ServerBinary, "secrets", "import", "--offline", "--name", name, "--config", harness.ServerConfig)
		if res.Code != 0 {
			t.Fatalf("seal %s: exit %d\n%s", name, res.Code, res.Output())
		}
	}
	keyPath, caPath, sigstoreDir := harness.ServerData+"/node-admin.key", harness.ServerData+"/ghsim-ca.pem", harness.ServerData+"/sigstore"
	keyPEM, err := os.ReadFile(node.adminKey)
	if err != nil {
		t.Fatal(err)
	}
	c.WriteFile(ctx, keyPath, keyPEM, "0600")
	c.WriteFile(ctx, caPath, ca.CertPEM, "0644")
	c.MustExec(ctx, "install", "-d", "-m", "0700", "-o", "supermgmt", "-g", "supermgmt", sigstoreDir)
	for _, name := range m4SigstoreCacheFiles {
		c.WriteFile(ctx, sigstoreDir+"/"+name, sim.trustedRootCache(), "0600")
	}
	c.MustExec(ctx, "chown", "supermgmt:supermgmt", keyPath, caPath)
	c.MustExec(ctx, "chown", "-R", "supermgmt:supermgmt", sigstoreDir)

	srv.AppendConfig(ctx, m4ProvidersYAML(node, node.c.Address(net.Name), 22, keyPath, "https://"+m4GitHubAlias, caPath)+
		"security:\n  allow_self_approval: true\n")
	c.MustExec(ctx, "systemctl", "start", "supermgmt")
	srv.WaitReady(ctx)

	admin := harness.NewClient(t)
	admin.AddProfile(ctx, "ops", srv.URL, srv.CAFile)
	token := srv.BootstrapAdmin(ctx, admin, "m4 operator")
	return &m4World{
		t: t, api: srv.Typed(token), sim: sim, node: node,
		webhookURL: "https://" + m4ServerAlias + ":8443" + wire.PathGitHubWebhook,
	}
}

// ---- the local world -----------------------------------------------------------------------------

// newM4LocalWorld runs `sm daemon` in local mode on the test machine: no server, no identity
// provider. It reaches the node through the port the fixture publishes and ghsim through its
// published port.
func newM4LocalWorld(t *testing.T) *m4World {
	t.Helper()
	ctx := context.Background()
	hostIP := m4HostAddress()
	if hostIP == "" {
		t.Skip("the test machine has no address besides loopback, which the product refuses for a provider")
	}
	net, ca := harness.NewNetwork(t), harness.NewCA(t)
	sim := startM4Sim(t, net, ca, hostIP)
	node := startM4Node(t, net, sim)

	dir, err := os.MkdirTemp("", "sm-m4-") // short: Unix socket paths are limited to ~100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dataDir, socket := filepath.Join(dir, "data"), filepath.Join(dir, "d.sock")
	sigstoreDir := filepath.Join(dataDir, "sigstore")
	if err := os.MkdirAll(sigstoreDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range m4SigstoreCacheFiles {
		harness.WriteHostFile(t, sigstoreDir, name, sim.trustedRootCache(), 0o600)
	}
	base := fmt.Sprintf("version: 1\ninstance:\n  mode: local\n  data_dir: %s\ndaemon:\n  socket: %s\n", dataDir, socket)
	configFile := harness.WriteHostFile(t, dir, "config.yaml", []byte(base), 0o600)
	laptop := harness.NewClient(t)

	// The database and the master key exist after the daemon has run once; only then can the
	// secrets the configuration refers to be sealed offline.
	booted := laptop.Start(ctx, "", "daemon", "--config", configFile)
	waitForLocalDaemon(t, ctx, laptop, configFile)
	if res, err := harness.Run(ctx, "", nil, "", "pkill", "-TERM", "-f", "daemon --config "+configFile); err != nil || res.Code != 0 {
		t.Fatalf("stop the first daemon: %v %s", err, res.Output())
	}
	if _, err := booted.Wait(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{m4GitHubTokenSecret: ghfake.DefaultToken, m4WebhookSecretName: m4WebhookSecretValue} {
		laptop.Must(ctx, value+"\n", "secrets", "import", "--offline", "--name", name, "--config", configFile)
	}

	full := base + m4ProvidersYAML(node, node.fx.Host, node.fx.Port, node.adminKey, fmt.Sprintf("https://%s:%d", hostIP, sim.apiPort), sim.caFile)
	configFile = harness.WriteHostFile(t, dir, "config.yaml", []byte(full), 0o600)
	daemon := laptop.Start(ctx, "", "daemon", "--config", configFile)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("daemon stderr:\n%s\nghsim saw: %s", daemon.Stderr(), sim.get("/sim/requests"))
		}
	})
	waitForLocalDaemon(t, ctx, laptop, configFile)
	return &m4World{t: t, api: client.New(client.Options{Socket: socket}), sim: sim, node: node}
}
