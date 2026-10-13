//go:build fixtures

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"math/big"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// deployNode is a node that completed node.setup with Docker access and whose
// deploy_root exists, i.e. everything a deployment needs before its first step.
type deployNode struct {
	*provisioned
}

// startDeployNode provisions a fixture node the way the setup handler does
// (dedicated user, docker group, tmpfiles, markers, db-backups) and creates
// deploy_root (owned by the dedicated user) through the same template ensureDeployRoot uses.
func startDeployNode(t *testing.T) *deployNode {
	t.Helper()
	p := provision(t, fixture.Options{}, func(p *systemd.SetupParams) { p.DockerAccess = true })
	cmd, err := templates.RenderSetup("setup.deploy_root"+templates.SudoVariantSuffix, map[string]string{"user": p.params.User, "path": templates.DefaultDeployRoot}, nil)
	if err != nil {
		t.Fatalf("render setup.deploy_root: %v", err)
	}
	res, err := p.admin.Run(t.Context(), cmd)
	if err != nil || res.ExitStatus != 0 {
		t.Fatalf("setup.deploy_root: %v %+v", err, res)
	}
	return &deployNode{provisioned: p}
}

var deployMarkerSeq atomic.Int64

// deployMarker is a fresh, valid intent marker name.
func deployMarker() string { return fmt.Sprintf("deploy-t17b-%d", deployMarkerSeq.Add(1)) }

// asSupermgmt runs a rendered command over the dedicated user's connection.
func (n *deployNode) asSupermgmt(t *testing.T, cmd templates.Command) transport.Result {
	t.Helper()
	res, err := n.super.Run(t.Context(), cmd)
	if err != nil {
		t.Fatalf("run %s: %v", cmd.Template, err)
	}
	return res
}

// readTemplate renders and runs a read template as the dedicated user.
func (n *deployNode) readTemplate(t *testing.T, name string, args map[string]string) transport.Result {
	t.Helper()
	return n.asSupermgmt(t, mustRender(t, name, args))
}

func mustRender(t *testing.T, name string, args map[string]string) templates.Command {
	t.Helper()
	cmd, err := templates.Render(name, args)
	if err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return cmd
}

// mutate renders a mutating template inside its marker wrapper, runs it and
// returns the marker it used.
func (n *deployNode) mutate(t *testing.T, name string, args map[string]string, stdin []byte, project string) (transport.Result, string) {
	t.Helper()
	marker := deployMarker()
	return n.mutateMarked(t, marker, name, args, stdin, project), marker
}

func (n *deployNode) mutateMarked(t *testing.T, marker, name string, args map[string]string, stdin []byte, project string) transport.Result {
	t.Helper()
	cmd, err := templates.RenderMutatingInput(name, marker, args, stdin, project)
	if err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return n.asSupermgmt(t, cmd)
}

// markerOf reads the marker.state template the evidence source reads.
func (n *deployNode) markerOf(t *testing.T, marker string) templates.MarkerState {
	t.Helper()
	res := n.readTemplate(t, "marker.state", map[string]string{"marker": marker})
	state, err := templates.ParseMarkerState(res.Stdout)
	if err != nil {
		t.Fatalf("marker.state output: %v", err)
	}
	return state
}

const (
	deployProject    = "t17b-app"
	deployFirstID    = "018f0000-0000-7000-8000-000000000001"
	deploySecondID   = "018f0000-0000-7000-8000-000000000002"
	deployComposeYML = "services: {}\n"
)

func deployDirArgs(project, deployment string) map[string]string {
	return map[string]string{"root": templates.DefaultDeployRoot, "project": project, "deployment": deployment}
}

// materialize runs compose.materialize with the given files.
func (n *deployNode) materialize(t *testing.T, args map[string]string, files ...templates.StagedFile) transport.Result {
	t.Helper()
	stdin, err := templates.EncodeMaterialization(files)
	if err != nil {
		t.Fatalf("encode materialization: %v", err)
	}
	res, _ := n.mutate(t, "compose.materialize", args, stdin, "")
	return res
}

func composeOnly(body string) templates.StagedFile {
	return templates.StagedFile{Path: "compose.yaml", Content: []byte(body)}
}

func stderrOf(res transport.Result) string { return strings.TrimSpace(string(res.Stderr)) }

// adoptProject creates the project directory the way the rest of the stack
// expects to find it (owned by the dedicated user, 0750, ADR-0030).
func (n *deployNode) adoptProject(t *testing.T, project string) {
	t.Helper()
	n.shell(t, fmt.Sprintf("install -d -m 0750 -o %[1]s -g %[1]s %s/%s", dedicatedUser, templates.DefaultDeployRoot, project))
}

// victimDir is a directory the dedicated user could write to: if a symlink
// attack worked, this is where the files would land.
func (n *deployNode) victimDir(t *testing.T, name string) string {
	t.Helper()
	dir := "/srv/" + name
	n.shell(t, fmt.Sprintf("install -d -m 0777 %s", dir))
	return dir
}

func (n *deployNode) untouched(t *testing.T, dir string) {
	t.Helper()
	if listing := n.shell(t, "ls -A "+dir); listing != "" {
		t.Errorf("%s was written through a symlink: %s", dir, listing)
	}
}

func (n *deployNode) wantRefused(t *testing.T, res transport.Result, message string) {
	t.Helper()
	if res.ExitStatus == 0 {
		t.Fatalf("materialize succeeded; want it refused (%q)", message)
	}
	if !strings.Contains(stderrOf(res), message) {
		t.Errorf("stderr = %q; want it to contain %q", stderrOf(res), message)
	}
}

// ---- materialize ------------------------------------------------------------------------------

// A fresh node, as node.setup leaves it: deploy_root is root-owned 0755 and no
// project directory exists. The first deployment of an app must still be able
// to stage itself.
func TestFixtures_MaterializeCreatesTheProjectDirectoryOnAFreshNode(t *testing.T) {
	n := startDeployNode(t)
	res := n.materialize(t, deployDirArgs(deployProject, deployFirstID), composeOnly(deployComposeYML))
	if res.ExitStatus != 0 {
		t.Fatalf("the first materialize on a node set up by node.setup failed (exit %d): %s\n"+
			"deploy_root is %s", res.ExitStatus, stderrOf(res), n.shell(t, "stat -c '%U:%G %a' "+templates.DefaultDeployRoot))
	}
}

func TestFixtures_MaterializeWritesTheDeploymentDirectory(t *testing.T) {
	n := startDeployNode(t)
	n.adoptProject(t, deployProject)
	secret := templates.StagedFile{Path: "secrets/api.env", Content: []byte("TOKEN=a$b ${C} \"q\"\n")}
	res := n.materialize(t, deployDirArgs(deployProject, deployFirstID), composeOnly(deployComposeYML), secret)
	if res.ExitStatus != 0 {
		t.Fatalf("materialize exit %d: %s", res.ExitStatus, stderrOf(res))
	}
	dir := templates.DefaultDeployRoot + "/" + deployProject + "/" + deployFirstID
	for _, want := range []struct{ path, mode string }{
		{dir, "750"}, {dir + "/secrets", "700"}, {dir + "/compose.yaml", "640"}, {dir + "/secrets/api.env", "600"},
	} {
		if got := n.shell(t, "stat -c '%a %U' "+want.path); got != want.mode+" supermgmt" {
			t.Errorf("%s: mode and owner %q; want %q", want.path, got, want.mode+" supermgmt")
		}
	}
	if got := n.shell(t, "cat "+dir+"/secrets/api.env"); got+"\n" != string(secret.Content) {
		t.Errorf("secret file = %q; want byte-exact %q", got, secret.Content)
	}
}

func TestFixtures_MaterializeRefusesSymlinks(t *testing.T) {
	n := startDeployNode(t)
	n.adoptProject(t, deployProject)
	files := []templates.StagedFile{composeOnly(deployComposeYML), {Path: "secrets/api.env", Content: []byte("TOKEN=x\n")}}

	t.Run("a deploy root that is a symlink is refused", func(t *testing.T) {
		victim := n.victimDir(t, "victim-root")
		n.shell(t, "ln -s "+templates.DefaultDeployRoot+" /srv/linked-root")
		res := n.materialize(t, map[string]string{"root": "/srv/linked-root", "project": deployProject, "deployment": deployFirstID}, files...)
		n.wantRefused(t, res, "deploy root is not a plain directory")
		n.untouched(t, victim)
		n.untouched(t, templates.DefaultDeployRoot+"/"+deployProject)
	})

	t.Run("a project directory that is a symlink is refused", func(t *testing.T) {
		victim := n.victimDir(t, "victim-project")
		n.shell(t, "ln -s "+victim+" "+templates.DefaultDeployRoot+"/linked-project")
		res := n.materialize(t, deployDirArgs("linked-project", deployFirstID), files...)
		n.wantRefused(t, res, "project directory is not a plain directory")
		n.untouched(t, victim)
	})

	t.Run("a deployment directory that is a symlink is refused", func(t *testing.T) {
		victim := n.victimDir(t, "victim-deployment")
		n.shell(t, "ln -s "+victim+" "+templates.DefaultDeployRoot+"/"+deployProject+"/"+deploySecondID)
		res := n.materialize(t, deployDirArgs(deployProject, deploySecondID), files...)
		n.wantRefused(t, res, "deployment directory exists or cannot be created")
		n.untouched(t, victim)
	})

	t.Run("an existing deployment directory is never reused or overwritten", func(t *testing.T) {
		const id = "018f0000-0000-7000-8000-000000000003"
		first := n.materialize(t, deployDirArgs(deployProject, id), files...)
		if first.ExitStatus != 0 {
			t.Fatalf("first materialize: %s", stderrOf(first))
		}
		path := templates.DefaultDeployRoot + "/" + deployProject + "/" + id + "/compose.yaml"
		before := n.shell(t, "sha256sum "+path)
		again := n.materialize(t, deployDirArgs(deployProject, id), composeOnly("services: {tampered: {}}\n"))
		n.wantRefused(t, again, "deployment directory exists or cannot be created")
		if after := n.shell(t, "sha256sum "+path); after != before {
			t.Errorf("the second materialize changed compose.yaml: %s -> %s", before, after)
		}
	})
}

func TestFixtures_MaterializeRefusesWhatTheEncoderWouldNotFrame(t *testing.T) {
	n := startDeployNode(t)
	n.adoptProject(t, deployProject)
	victim := n.victimDir(t, "victim-framing")

	hostile := []struct{ name, stdin string }{
		{"a path outside the deployment directory", "3 ../../../srv/victim-framing/x\nabc"},
		{"a nested secrets path", "3 secrets/../../x.env\nabc"},
		{"a hidden secrets file", "3 secrets/.env\nabc"},
		{"an arbitrary file name", "3 other.txt\nabc"},
		{"a non-numeric size", "x compose.yaml\nabc"},
		{"an oversized size", "99999999 compose.yaml\nabc"},
	}
	for i, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			id := fmt.Sprintf("018f0000-0000-7000-8000-0000000001%02d", i)
			res, _ := n.mutate(t, "compose.materialize", deployDirArgs(deployProject, id), []byte(h.stdin), "")
			if res.ExitStatus == 0 {
				t.Fatalf("materialize accepted %q", h.stdin)
			}
			n.untouched(t, victim)
		})
	}

	t.Run("a body shorter than its declared size is refused as truncated", func(t *testing.T) {
		res, _ := n.mutate(t, "compose.materialize", deployDirArgs(deployProject, "018f0000-0000-7000-8000-000000000200"), []byte("50 compose.yaml\nshort"), "")
		n.wantRefused(t, res, "truncated input for compose.yaml")
	})

	t.Run("a stream without compose.yaml is refused", func(t *testing.T) {
		res, _ := n.mutate(t, "compose.materialize", deployDirArgs(deployProject, "018f0000-0000-7000-8000-000000000201"), []byte("3 secrets/api.env\nabc"), "")
		n.wantRefused(t, res, "compose.yaml was not provided")
	})
}

// ---- a registry served over TLS (T8a OQ-2) ------------------------------------------------------

const (
	registryHost = "registry.test:5443"
	registryRepo = "t17b/app"
)

// tlsRegistry is a registry:2 container inside the node, reachable by a name
// that resolves to the node's own non-loopback address, with a
// certificate signed by a test CA. It holds one image, busybox, by digest.
type tlsRegistry struct {
	n      *deployNode
	digest string
}

// ref is the digest-pinned reference of the image the registry holds.
func (r *tlsRegistry) ref() string { return registryHost + "/" + registryRepo + "@" + r.digest }

// trust installs the test CA where the node's Docker looks for it.
func (r *tlsRegistry) trust(t *testing.T) {
	t.Helper()
	r.n.shell(t, "install -D -m 0644 /srv/registry-certs/ca.crt /etc/docker/certs.d/"+registryHost+"/ca.crt")
}

// distrust removes the test CA again: the registry then presents a
// certificate the node cannot verify.
func (r *tlsRegistry) distrust(t *testing.T) {
	t.Helper()
	r.n.shell(t, "rm -rf /etc/docker/certs.d/"+registryHost)
}

// forgetLocalImage removes the pushed image from the node's own store, so the
// next use has to pull it through the registry.
func (r *tlsRegistry) forgetLocalImage(t *testing.T) {
	t.Helper()
	r.n.shell(t, "docker rmi "+registryHost+"/"+registryRepo+":1 "+busyboxImage)
}

var pushedDigest = regexp.MustCompile(`digest: (sha256:[0-9a-f]{64})`)

// startRegistry serves the registry over TLS, pushes busybox into it and leaves
// the node trusting the test CA and holding no local copy.
func (n *deployNode) startRegistry(t *testing.T) *tlsRegistry {
	t.Helper()
	seconds, err := strconv.ParseInt(n.shell(t, "date +%s"), 10, 64)
	if err != nil {
		t.Fatalf("node clock: %v", err)
	}
	ca, cert, key := newRegistryCertificates(t, time.Unix(seconds, 0))
	writeNodeFile(t, n.fixtureNode, "/srv/registry-certs/ca.crt", ca)
	writeNodeFile(t, n.fixtureNode, "/srv/registry-certs/tls.crt", cert)
	writeNodeFile(t, n.fixtureNode, "/srv/registry-certs/tls.key", key)
	// Docker treats a registry that resolves to loopback as insecure and skips
	// the certificate check, so the name must point at a non-loopback address.
	n.shell(t, "echo \"$(hostname -i | cut -d' ' -f1) registry.test\" >> /etc/hosts")
	n.shell(t, "docker run -d --name t17b-registry -p 5443:5443 -v /srv/registry-certs:/certs:ro"+
		" -e REGISTRY_HTTP_ADDR=0.0.0.0:5443 -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/tls.crt -e REGISTRY_HTTP_TLS_KEY=/certs/tls.key registry:2")
	r := &tlsRegistry{n: n}
	r.trust(t)
	n.shell(t, "docker pull -q "+busyboxImage+" && docker tag "+busyboxImage+" "+registryHost+"/"+registryRepo+":1")
	out := n.shell(t, "for i in $(seq 30); do docker push "+registryHost+"/"+registryRepo+":1 2>&1 && exit 0; sleep 1; done; exit 1")
	m := pushedDigest.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("docker push printed no digest:\n%s", out)
	}
	r.digest = m[1]
	r.forgetLocalImage(t)
	return r
}

// newRegistryCertificates returns a CA and a server certificate for registry.test, as PEM, valid around now (the node's clock).
func newRegistryCertificates(t *testing.T, now time.Time) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t17b test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "registry.test"}, DNSNames: []string{"registry.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("server certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	pemOf := func(kind string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}) }
	return pemOf("CERTIFICATE", caDER), pemOf("CERTIFICATE", serverDER), pemOf("EC PRIVATE KEY", keyDER)
}

// ---- a deployment built by the real pipeline ----------------------------------------------------

// stagedApp is one deployment staged on the node: the frozen model, the
// bundle Materialize produced and the secret values it carries.
type stagedApp struct {
	project    string
	owner      domain.ID
	deployment domain.ID
	frozen     compose.Frozen
	values     []compose.ResolvedSecret
	bundle     compose.Bundle
}

func (a stagedApp) dir() string {
	return templates.DefaultDeployRoot + "/" + a.project + "/" + a.deployment.String()
}

func (a stagedApp) args() map[string]string { return deployDirArgs(a.project, a.deployment.String()) }

// freezeApp runs the pipeline on raw: the deployed service is the registry's
// image, and every name in secrets becomes a ${secret:<name>} reference.
func freezeApp(t *testing.T, reg *tlsRegistry, project, raw string, secrets map[string]string) (domain.ID, compose.Frozen, []compose.ResolvedSecret) {
	t.Helper()
	refs := map[string]string{}
	for name := range secrets {
		refs[name] = "secret://apps/t17b/" + name
	}
	src := compose.Source{
		Raw: []byte(raw), SecretRefs: refs,
		Images:          compose.ImagePolicy{Deployed: registryHost + "/" + registryRepo},
		DeployedService: "app", ArtifactDigest: reg.digest,
		BoundDigests: map[string]string{reg.ref(): compose.BindingAttestation},
	}
	owner := domain.UUIDv7Generator{}.NewID()
	frozen, err := compose.Freeze(src, compose.Target{Project: project, Owner: owner})
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	var values []compose.ResolvedSecret
	for _, u := range frozen.Secrets {
		values = append(values, compose.ResolvedSecret{Ref: u.Ref, Version: u.Version, Value: audit.Secret(secrets[path.Base(u.Ref)])})
	}
	return owner, frozen, values
}

// stage materializes a frozen model as a new deployment directory.
func (n *deployNode) stage(t *testing.T, owner domain.ID, project string, frozen compose.Frozen, values []compose.ResolvedSecret) stagedApp {
	t.Helper()
	app := stagedApp{project: project, owner: owner, deployment: domain.UUIDv7Generator{}.NewID(), frozen: frozen, values: values}
	bundle, err := compose.Materialize(frozen, app.deployment, values)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	app.bundle = bundle
	files := []templates.StagedFile{composeOnly(string(bundle.ComposeYAML))}
	for _, p := range slices.Sorted(maps.Keys(bundle.EnvFiles)) {
		files = append(files, templates.StagedFile{Path: p, Content: []byte(bundle.EnvFiles[p].Reveal())})
	}
	n.adoptProject(t, project)
	if res := n.materialize(t, app.args(), files...); res.ExitStatus != 0 {
		t.Fatalf("compose.materialize exit %d: %s", res.ExitStatus, stderrOf(res))
	}
	return app
}

// pull runs compose.pull for the registry's image, the way the pull step does.
func (n *deployNode) pull(t *testing.T, image string) (transport.Result, string) {
	t.Helper()
	return n.mutate(t, "compose.pull", map[string]string{"image": image}, nil, "")
}

const deployedAppYAML = `services:
  app:
    image: ` + registryHost + `/` + registryRepo + `:placeholder
    command: ["httpd", "-f", "-p", "80", "-h", "/tmp"]
    ports:
      - {target: 80, published: 18081, host_ip: 127.0.0.1}
      - {target: 53, published: 18082, host_ip: 127.0.0.1, protocol: udp}
    environment:
      TOKEN: ${secret:token}
    volumes:
      - {type: volume, source: data, target: /data}
volumes:
  data:
`

// deployed pulls, stages and brings up the app, as the pull, materialize and
// deploy steps do.
func (n *deployNode) deployed(t *testing.T, reg *tlsRegistry, project string) stagedApp {
	t.Helper()
	owner, frozen, values := freezeApp(t, reg, project, deployedAppYAML, map[string]string{"token": "s3cret"})
	app := n.stage(t, owner, project, frozen, values)
	if res, _ := n.pull(t, reg.ref()); res.ExitStatus != 0 {
		t.Fatalf("compose.pull exit %d: %s", res.ExitStatus, stderrOf(res))
	}
	if res, _ := n.mutate(t, "compose.up", app.args(), nil, project); res.ExitStatus != 0 {
		t.Fatalf("compose.up exit %d: %s\n%s", res.ExitStatus, stderrOf(res), res.Stdout)
	}
	return app
}

// deployContainer is the part of `docker inspect` the preflight and the
// evidence source read.
type deployContainer struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status   string `json:"Status"`
		ExitCode int    `json:"ExitCode"`
	} `json:"State"`
	HostConfig struct {
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
}

func (n *deployNode) projectContainers(t *testing.T, project string) []deployContainer {
	t.Helper()
	res := n.readTemplate(t, "compose.project_containers", map[string]string{"project": project})
	if res.ExitStatus != 0 || res.Truncated {
		t.Fatalf("compose.project_containers exit %d truncated=%v: %s", res.ExitStatus, res.Truncated, stderrOf(res))
	}
	if strings.TrimSpace(string(res.Stdout)) == "" {
		return nil
	}
	var containers []deployContainer
	if err := json.Unmarshal(res.Stdout, &containers); err != nil {
		t.Fatalf("compose.project_containers is not a JSON array: %v\n%s", err, res.Stdout)
	}
	return containers
}

// ---- preflight reads on real Docker (T11e) ------------------------------------------------------

func TestFixtures_PreflightReadsOnRealDocker(t *testing.T) {
	n := startDeployNode(t)
	reg := n.startRegistry(t)
	const project = "t17b-pf"
	app := n.deployed(t, reg, project)

	t.Run("the project's containers carry the owner and deployment labels and the pinned image", func(t *testing.T) {
		containers := n.projectContainers(t, project)
		if len(containers) != 1 {
			t.Fatalf("project has %d containers; want 1", len(containers))
		}
		c := containers[0]
		if c.Name != "/"+project+"-app-1" {
			t.Errorf("container name = %q; want /%s-app-1", c.Name, project)
		}
		if got := c.Config.Labels[compose.LabelOwner]; got != app.owner.String() {
			t.Errorf("owner label = %q; want %q", got, app.owner)
		}
		if got := c.Config.Labels[compose.LabelDeployment]; got != app.deployment.String() {
			t.Errorf("deployment label = %q; want %q", got, app.deployment)
		}
		if got := c.Config.Labels["com.docker.compose.service"]; got != "app" {
			t.Errorf("compose service label = %q; want app", got)
		}
		if c.Config.Image != reg.ref() {
			t.Errorf("Config.Image = %q; want the frozen reference %q", c.Config.Image, reg.ref())
		}
		if c.State.Status != "running" {
			t.Errorf("state = %q; want running", c.State.Status)
		}
		if got := c.HostConfig.PortBindings["80/tcp"]; len(got) != 1 || got[0].HostPort != "18081" {
			t.Errorf("tcp port bindings = %+v; want 18081", got)
		}
		if got := c.HostConfig.PortBindings["53/udp"]; len(got) != 1 || got[0].HostPort != "18082" {
			t.Errorf("udp port bindings = %+v; want 18082", got)
		}
	})

	t.Run("a container of the same project name that another owner started is visible by its label", func(t *testing.T) {
		n.shell(t, "docker run -d --name t17b-intruder --label com.docker.compose.project="+project+" --label "+compose.LabelOwner+"=somebody-else "+busyboxImage+" sleep 600")
		var owners []string
		for _, c := range n.projectContainers(t, project) {
			owners = append(owners, c.Config.Labels[compose.LabelOwner])
		}
		slices.Sort(owners)
		want := []string{app.owner.String(), "somebody-else"}
		slices.Sort(want)
		if !slices.Equal(owners, want) {
			t.Errorf("owners of the project's containers = %v; want %v", owners, want)
		}
	})

	t.Run("volumes and networks list one kind-prefixed JSON line each with their labels", func(t *testing.T) {
		n.shell(t, "docker volume create "+project+"_foreign")
		type resource struct {
			Name   string            `json:"Name"`
			Labels map[string]string `json:"Labels"`
		}
		got := map[string]resource{}
		res := n.readTemplate(t, "compose.project_resources", map[string]string{"project": project})
		if res.ExitStatus != 0 {
			t.Fatalf("compose.project_resources exit %d: %s", res.ExitStatus, stderrOf(res))
		}
		for line := range strings.SplitSeq(strings.TrimSpace(string(res.Stdout)), "\n") {
			kind, payload, ok := strings.Cut(line, " ")
			var r resource
			if !ok || json.Unmarshal([]byte(payload), &r) != nil {
				t.Fatalf("unreadable line %q", line)
			}
			got[kind+" "+r.Name] = r
		}
		for _, owned := range []string{"volume " + project + "_data", "network " + project + "_default"} {
			r, ok := got[owned]
			if !ok {
				t.Errorf("%s is not listed; got %v", owned, slices.Sorted(maps.Keys(got)))
				continue
			}
			if r.Labels[compose.LabelOwner] != app.owner.String() {
				t.Errorf("%s: owner label = %q; want %q (the frozen model labels it)", owned, r.Labels[compose.LabelOwner], app.owner)
			}
		}
		foreign, ok := got["volume "+project+"_foreign"]
		if !ok {
			t.Fatalf("a volume with the project's name prefix is not listed; got %v", slices.Sorted(maps.Keys(got)))
		}
		if foreign.Labels[compose.LabelOwner] != "" {
			t.Errorf("foreign volume carries owner label %q", foreign.Labels[compose.LabelOwner])
		}
		if len(got) != 3 {
			t.Errorf("listed %d resources %v; want the owned volume, the owned network and the foreign volume", len(got), slices.Sorted(maps.Keys(got)))
		}
	})

	t.Run("a project nothing uses has no containers and no resources", func(t *testing.T) {
		if containers := n.projectContainers(t, "t17b-empty"); len(containers) != 0 {
			t.Errorf("unknown project lists %d containers", len(containers))
		}
		res := n.readTemplate(t, "compose.project_resources", map[string]string{"project": "t17b-empty"})
		if res.ExitStatus != 0 || strings.TrimSpace(string(res.Stdout)) != "" {
			t.Errorf("unknown project: exit %d, stdout %q; want an empty success", res.ExitStatus, res.Stdout)
		}
	})

	t.Run("listeners show published tcp ports as LISTEN and udp ports as UNCONN", func(t *testing.T) {
		res := n.readTemplate(t, "compose.listeners", nil)
		if res.ExitStatus != 0 {
			t.Fatalf("compose.listeners exit %d: %s", res.ExitStatus, stderrOf(res))
		}
		states := map[string]string{} // local address -> first column
		for _, line := range strings.Split(string(res.Stdout), "\n") {
			if fields := strings.Fields(line); len(fields) >= 4 {
				states[fields[3]] = fields[0]
			}
		}
		if got := states["127.0.0.1:18081"]; got != "LISTEN" {
			t.Errorf("127.0.0.1:18081 state = %q; want LISTEN (all: %v)", got, states)
		}
		if got := states["127.0.0.1:18082"]; got != "UNCONN" {
			t.Errorf("127.0.0.1:18082 state = %q; want UNCONN (all: %v)", got, states)
		}
	})
}

// ---- disk space (T11b, Q14) -------------------------------------------------------------------

func TestFixtures_DiskSpaceReadsOnRealNode(t *testing.T) {
	n := startDeployNode(t)
	reg := n.startRegistry(t)

	t.Run("the Docker root directory is a clean absolute path", func(t *testing.T) {
		res := n.readTemplate(t, "compose.docker_root", nil)
		root := strings.TrimSpace(string(res.Stdout))
		if res.ExitStatus != 0 || templates.ValidateCleanPath(root) != nil {
			t.Fatalf("docker_root exit %d = %q", res.ExitStatus, root)
		}
		if root != "/var/lib/docker" {
			t.Errorf("docker root = %q; want /var/lib/docker", root)
		}
	})

	t.Run("df reports the available bytes in the third column from the end of the last line", func(t *testing.T) {
		for _, dir := range []string{"/var/lib/docker", templates.DefaultDeployRoot} {
			res := n.readTemplate(t, "compose.disk_free", map[string]string{"path": dir})
			lines := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
			fields := strings.Fields(lines[len(lines)-1])
			if res.ExitStatus != 0 || len(lines) < 2 || len(fields) < 6 {
				t.Fatalf("df %s: exit %d, output %q", dir, res.ExitStatus, res.Stdout)
			}
			free, err := strconv.ParseInt(fields[len(fields)-3], 10, 64)
			if err != nil || free <= 0 {
				t.Fatalf("df %s: available column %q is not a positive number", dir, fields[len(fields)-3])
			}
			want := n.shell(t, "stat -f -c '%a %S' "+dir)
			var blocks, size int64
			if _, err := fmt.Sscanf(want, "%d %d", &blocks, &size); err != nil {
				t.Fatalf("stat -f: %v", err)
			}
			if diff := free - blocks*size; diff > 64<<20 || diff < -64<<20 {
				t.Errorf("df %s available = %d; stat -f says %d", dir, free, blocks*size)
			}
		}
	})

	t.Run("image_size is the config plus the layers of the manifest for the node's platform", func(t *testing.T) {
		res := n.readTemplate(t, "compose.image_size", map[string]string{"image": reg.ref()})
		if res.ExitStatus != 0 {
			t.Fatalf("compose.image_size exit %d: %s", res.ExitStatus, stderrOf(res))
		}
		size, err := templates.ParseImageSize(res.Stdout)
		if err != nil {
			t.Fatalf("ParseImageSize(%q): %v", res.Stdout, err)
		}
		independent := n.shell(t, "docker manifest inspect "+reg.ref()+" | jq '.config.size + ([.layers[].size] | add)'")
		if independent != strconv.FormatInt(size, 10) {
			t.Errorf("image_size = %d; the manifest sums to %s", size, independent)
		}
		if size <= 0 {
			t.Errorf("image_size = %d; want a positive size", size)
		}
	})

	t.Run("an image the registry does not hold has no size, which fails closed", func(t *testing.T) {
		missing := registryHost + "/" + registryRepo + "@sha256:" + strings.Repeat("0", 64)
		res := n.readTemplate(t, "compose.image_size", map[string]string{"image": missing})
		if res.ExitStatus == 0 {
			t.Fatalf("image_size of a missing image succeeded: %q", res.Stdout)
		}
	})

	t.Run("a registry whose certificate the node does not trust has no size either", func(t *testing.T) {
		reg.distrust(t)
		defer reg.trust(t)
		res := n.readTemplate(t, "compose.image_size", map[string]string{"image": reg.ref()})
		if res.ExitStatus == 0 {
			t.Fatalf("image_size succeeded against an untrusted registry: %q", res.Stdout)
		}
	})

	t.Run("compose.image_inspect tells a held image from a missing one", func(t *testing.T) {
		if res := n.readTemplate(t, "compose.image_inspect", map[string]string{"image": reg.ref()}); res.ExitStatus == 0 {
			t.Fatal("image_inspect succeeded for an image the node has not pulled")
		}
		if res, _ := n.pull(t, reg.ref()); res.ExitStatus != 0 {
			t.Fatalf("compose.pull exit %d: %s", res.ExitStatus, stderrOf(res))
		}
		if res := n.readTemplate(t, "compose.image_inspect", map[string]string{"image": reg.ref()}); res.ExitStatus != 0 {
			t.Fatalf("image_inspect failed after the pull: %s", stderrOf(res))
		}
	})
}

// ---- health templates (T4a, spec §21) ----------------------------------------------------------

// installCurl gives the fixture the tool the health.http capability requires.
// The fixture image ships without it, so the node reports the capability
// absent; the template itself is exercised once curl is there.
func (n *deployNode) installCurl(t *testing.T) {
	t.Helper()
	if _, err := n.tryShell(t, "command -v curl"); err == nil {
		return
	}
	if out, err := n.tryShell(t, "apt-get update -qq && apt-get install -y -qq --no-install-recommends curl"); err != nil {
		t.Skipf("curl cannot be installed on the fixture node (no apt access?): %v\n%s", err, out)
	}
}

func TestFixtures_HealthTemplates(t *testing.T) {
	n := startDeployNode(t)
	n.installCurl(t)
	n.shell(t, "docker pull -q "+busyboxImage)
	n.shell(t, `docker run -d --name t17b-www -p 127.0.0.1:18090:8080 `+busyboxImage+` sh -c 'mkdir -p /www/cgi-bin; echo ok > /www/ok;`+
		` printf "#!/bin/sh\necho \"Status: 302 Found\"\necho \"Location: /ok\"\necho\n" > /www/cgi-bin/go; chmod +x /www/cgi-bin/go; exec httpd -f -p 8080 -h /www'`)
	n.shell(t, `bash -c 'for i in $(seq 30); do (exec 3<>/dev/tcp/127.0.0.1/18090) 2>/dev/null && exit 0; sleep 1; done; exit 1'`)
	http := func(port, path string) transport.Result {
		return n.readTemplate(t, "health.http", map[string]string{"addr": "127.0.0.1", "port": port, "path": path, "timeout": "3"})
	}

	for _, c := range []struct{ name, port, path, wantStatus string }{
		{"a 2xx answer prints 200", "18090", "/ok", "200"},
		{"a missing path prints 404 and still exits 0", "18090", "/missing", "404"},
		{"a redirect is reported and not followed", "18090", "/cgi-bin/go", "302"},
	} {
		t.Run("health.http: "+c.name, func(t *testing.T) {
			res := http(c.port, c.path)
			if res.ExitStatus != 0 || strings.TrimSpace(string(res.Stdout)) != c.wantStatus {
				t.Errorf("exit %d, stdout %q, stderr %q; want status %s", res.ExitStatus, res.Stdout, res.Stderr, c.wantStatus)
			}
		})
	}

	t.Run("health.http: a closed port fails", func(t *testing.T) {
		if res := http("18099", "/"); res.ExitStatus == 0 {
			t.Errorf("a closed port answered %q", res.Stdout)
		}
	})

	t.Run("health.tcp: an open port succeeds and a closed port fails", func(t *testing.T) {
		tcp := func(port string) transport.Result {
			return n.readTemplate(t, "health.tcp", map[string]string{"addr": "127.0.0.1", "port": port, "timeout": "3"})
		}
		if res := tcp("18090"); res.ExitStatus != 0 {
			t.Errorf("open port: exit %d: %s", res.ExitStatus, stderrOf(res))
		}
		if res := tcp("18099"); res.ExitStatus == 0 {
			t.Error("closed port: exit 0")
		}
	})

	t.Run("health.docker: prints none without a health check and the status with one", func(t *testing.T) {
		docker := func(container string) string {
			res := n.readTemplate(t, "health.docker", map[string]string{"container": container})
			if res.ExitStatus != 0 {
				t.Fatalf("health.docker %s: exit %d: %s", container, res.ExitStatus, stderrOf(res))
			}
			return strings.TrimSpace(string(res.Stdout))
		}
		if got := docker("t17b-www"); got != "none" {
			t.Errorf("container without a health check = %q; want none", got)
		}
		n.shell(t, "docker run -d --name t17b-healthy --health-cmd 'true' --health-interval 1s "+busyboxImage+" sleep 600")
		var got string
		for range 30 {
			if got = docker("t17b-healthy"); got == "healthy" {
				break
			}
			time.Sleep(time.Second)
		}
		if got != "healthy" {
			t.Errorf("container with a passing health check = %q; want healthy", got)
		}
		if res := n.readTemplate(t, "health.docker", map[string]string{"container": "t17b-absent"}); res.ExitStatus == 0 {
			t.Error("a container that does not exist reported a status")
		}
	})
}
