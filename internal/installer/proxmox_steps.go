package installer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/config"
)

func applianceLayout() layout { return Options{Mode: ModeServer}.serverLayout() }

// runSteps is the §3.5 sequence after planning. The order is the failure
// matrix: each step only relies on what the earlier ones journaled.
func (p *provision) runSteps(ctx context.Context) error {
	steps := []func(context.Context) error{
		p.ensureTemplate, p.createGuest, p.startGuest, p.pushBinary, p.installServer, p.initServer,
		p.prepareBootstrapDir, p.checkEndpointTrust, p.createIdentities, p.transferToken,
		p.registerProvider, p.checkProvider, p.enableService, p.awaitReady, p.issueBootstrapCode, p.commitAndReport,
	}
	for _, step := range steps {
		if err := step(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *provision) execute(ctx context.Context) error {
	id, err := newInstallID()
	if err != nil {
		return failWrap(ExitCreation, "draw the install id", err)
	}
	p.id = id
	if p.j, err = createJournal(p.d.Files, id); err != nil {
		return failWrap(ExitCreation, "create the install journal", err)
	}
	if err := p.requirePrivate(p.j.dir, true); err != nil {
		return err // nothing was created yet, and the directory is not ours to clean up
	}
	if err := p.hit("journal:created"); err != nil {
		return err
	}
	err = p.runSteps(ctx)
	if err == nil || isCrash(err) {
		return err
	}
	return p.abort(ctx, err)
}

// create journals the intent, performs the side effect and journals its
// completion, with a crash point at each boundary. A failed effect stays
// pending: rollback reads the resource back to decide whether it is ours.
func (p *provision) create(step, resource, name string, do func() error) (int, error) {
	seq, err := p.j.begin(step, resource, name)
	if err != nil {
		return 0, failWrap(ExitCreation, "write the install journal", err)
	}
	if err := p.hit(step + ":intent"); err != nil {
		return 0, err
	}
	if err := do(); err != nil {
		return seq, err
	}
	if err := p.hit(step + ":applied"); err != nil {
		return 0, err
	}
	if err := p.j.mark(seq, phaseDone); err != nil {
		return 0, failWrap(ExitCreation, "write the install journal", err)
	}
	return seq, p.hit(step + ":recorded")
}

// createNew creates a Proxmox object that must not exist yet. When the creation fails and the
// object is there afterwards, it may have been made by somebody else in the meantime (or by this
// call, whose failure was only reported): that cannot be told apart, so the entry is marked
// ambiguous and rollback leaves the object alone.
func (p *provision) createNew(step, resource, name string, exists func() (bool, error), build func() error) error {
	if present, err := exists(); err != nil || present {
		return refuseAdopt(resource, name, err)
	}
	seq, err := p.create(step, resource, name, build)
	if err == nil || isCrash(err) || seq == 0 {
		return err
	}
	if present, lookupErr := exists(); present || lookupErr != nil {
		if markErr := p.j.mark(seq, phaseAmbiguous); markErr != nil {
			return errors.Join(err, markErr)
		}
	}
	return err
}

func (p *provision) exec(ctx context.Context, user string, sensitive bool, stdin io.Reader, argv ...string) ([]byte, error) {
	return p.pve.Exec(ctx, p.plan.VMID, user, argv, stdin, sensitive)
}

func (p *provision) root(ctx context.Context, argv ...string) ([]byte, error) {
	return p.exec(ctx, "", false, nil, argv...)
}

// sm runs the container's sm as the service user, so every file it creates is
// owned by that user.
func (p *provision) sm(ctx context.Context, sensitive bool, args ...string) ([]byte, error) {
	l := applianceLayout()
	argv := append([]string{l.Binary}, args...)
	return p.exec(ctx, ServiceUser, sensitive, nil, append(argv, "--config", l.ConfigFile)...)
}

func (p *provision) waitFor(ctx context.Context, bound time.Duration, what string, probe func() (bool, error)) error {
	attempts := int(bound / p.h.poll)
	var last error
	for i := 0; ; i++ {
		ok, err := probe()
		if ok {
			return nil
		}
		last = err
		if i >= attempts {
			return fmt.Errorf("timed out waiting for %s (last error: %w)", what, last)
		}
		if err := p.h.pause(ctx, p.h.poll); err != nil {
			return err
		}
	}
}

// ---- S6, S7 ----

func (p *provision) ensureTemplate(ctx context.Context) error {
	if p.plan.Download == "" {
		return nil
	}
	p.say("downloading template %s (kept afterwards: it is a shared cache)", p.plan.Download)
	_, err := p.create("S6", resTemplate, p.plan.Template, func() error {
		return p.pve.DownloadTemplate(ctx, p.plan.TemplateStorage, p.plan.Download)
	})
	return stepError(ExitCreation, "download the template", err)
}

func stepError(code int, what string, err error) error {
	if err == nil || isCrash(err) {
		return err
	}
	return failWrap(code, what, err)
}

func (p *provision) createGuest(ctx context.Context) error {
	pl := p.plan
	free, err := p.vmidFree(ctx, pl.VMID)
	if err != nil {
		return failWrap(ExitCreation, "check VMID", err)
	}
	if !free {
		return fail(ExitCreation, "VMID %d was taken meanwhile; it is left untouched", pl.VMID)
	}
	spec := GuestSpec{
		VMID: pl.VMID, Hostname: pl.Hostname, Template: pl.Template, Storage: pl.Storage, DiskGiB: pl.DiskGiB,
		Cores: pl.Cores, MemoryMiB: pl.MemoryMiB, SwapMiB: pl.SwapMiB, Network: pl.Network,
		Tags: []string{applianceTag}, Description: ownershipMark(p.id),
	}
	_, err = p.create("S7", resLXC, strconv.Itoa(pl.VMID), func() error { return p.pve.Create(ctx, spec) })
	if err != nil {
		return stepError(ExitCreation, "create the container", err)
	}
	cfg, err := p.pve.Config(ctx, pl.VMID)
	if err != nil {
		return failWrap(ExitCreation, "read the container back", err)
	}
	if problem := guestShapeProblem(cfg, p.id); problem != "" {
		return fail(ExitCreation, "the created container does not match the plan: %s", problem)
	}
	return nil
}

// guestShapeProblem is the post-create readback: unprivileged, no mounts, no
// raw lxc keys, tagged, and carrying this install's id.
func guestShapeProblem(c GuestConfig, id string) string {
	switch {
	case !c.Unprivileged:
		return "it is privileged"
	case c.Features["nesting"] != "0" || c.Features["keyctl"] != "0":
		return "nesting or keyctl is enabled"
	case len(c.Mounts) > 0:
		return "it has mount points " + strings.Join(c.Mounts, ",")
	case len(c.RawLXC) > 0:
		return "it has raw lxc keys " + strings.Join(c.RawLXC, ",")
	case !contains(c.Tags, applianceTag):
		return "the supermgmt tag is missing"
	case !strings.Contains(c.Description, ownershipMark(id)):
		return "the description does not carry the install id"
	}
	return ""
}

// ---- S9, S10 ----

func (p *provision) startGuest(ctx context.Context) error {
	if err := p.pve.Start(ctx, p.plan.VMID); err != nil {
		return failWrap(ExitCreation, "start the container", err)
	}
	err := p.waitFor(ctx, p.h.guestWait, "the container network", func() (bool, error) { return p.guestAddress(ctx) })
	return stepError(ExitConnectivity, "container did not come up", err)
}

func (p *provision) guestAddress(ctx context.Context) (bool, error) {
	st, err := p.pve.State(ctx, p.plan.VMID)
	if err != nil || st.Status != "running" {
		return false, err
	}
	if !p.plan.Network.DHCP {
		p.guestIP = p.plan.Network.Address.Addr()
		return true, nil
	}
	out, err := p.root(ctx, "/usr/bin/hostname", "-I")
	if err != nil {
		return false, err
	}
	for _, f := range strings.Fields(string(out)) {
		if ip, err := netip.ParseAddr(f); err == nil && ip.Is4() && !ip.IsLoopback() {
			p.guestIP = ip
			return true, nil
		}
	}
	return false, errors.New("no IPv4 address yet")
}

func (p *provision) pushBinary(ctx context.Context) error {
	want, err := p.d.Files.Hash(p.o.Binary)
	if err != nil {
		return failWrap(ExitConfiguration, "hash the running sm", err)
	}
	return pushStaged(ctx, p.pve, p.plan.VMID, p.o.Binary, want)
}

// ---- S11, S11b ----

func (p *provision) installServer(ctx context.Context) error {
	p.publicURL = "https://" + net.JoinHostPort(p.guestIP.String(), applianceListenPort)
	_, err := p.root(ctx, stagedBinary, "install", "server", "--no-start", "--tls", "self-signed",
		"--public-url", p.publicURL, "--non-interactive", "--yes")
	if err != nil {
		return failWrap(ExitConfiguration, "install the server inside the container", err)
	}
	if err := unstage(ctx, p.pve, p.plan.VMID); err != nil {
		return failWrap(ExitConfiguration, "remove the staged binary", err)
	}
	pem, err := p.fetchApplianceCA(ctx)
	if err != nil {
		return failWrap(ExitConfiguration, "read the appliance CA", err)
	}
	p.appliancePEM = pem
	return nil
}

// fetchApplianceCA reads ca.pem next to the served certificate, or the CA
// certificates of the served chain file when there is no ca.pem.
func (p *provision) fetchApplianceCA(ctx context.Context) ([]byte, error) {
	l := applianceLayout()
	cfgRaw, err := p.root(ctx, "/usr/bin/cat", l.ConfigFile)
	if err != nil {
		return nil, err
	}
	res, err := config.LoadBytes(cfgRaw, nil)
	if err != nil {
		return nil, err
	}
	certFile := res.Config.Server.TLS.CertFile
	if err := validPath(certFile); err != nil {
		return nil, err
	}
	if out, err := p.root(ctx, "/usr/bin/cat", path.Join(path.Dir(certFile), "ca.pem")); err == nil {
		if _, perr := parseCertificates(out); perr == nil {
			return out, nil
		}
	}
	chain, err := p.root(ctx, "/usr/bin/cat", certFile)
	if err != nil {
		return nil, err
	}
	return caCertificatesPEM(chain)
}

func (p *provision) initServer(ctx context.Context) error {
	if _, err := p.sm(ctx, false, "server", "init"); err != nil {
		return failWrap(ExitConfiguration, "initialize the data directory", err)
	}
	return nil
}

// ---- S11c, S11d ----

// prepareBootstrapDir verifies where the token will live before any token
// exists: /run must be tmpfs and the service account present.
func (p *provision) prepareBootstrapDir(ctx context.Context) error {
	out, err := p.root(ctx, "/usr/bin/stat", "-f", "-c", "%T", "/run")
	if err != nil || strings.TrimSpace(string(out)) != "tmpfs" {
		return fail(ExitConfiguration, "/run inside the container is not tmpfs; refusing to stage a secret there")
	}
	if _, err := p.root(ctx, "/usr/bin/id", "-u", ServiceUser); err != nil {
		return failWrap(ExitConfiguration, "service account "+ServiceUser+" is missing in the container", err)
	}
	seq, err := p.create("S11c", resBootstrapDir, strconv.Itoa(p.plan.VMID), func() error {
		_, err := p.root(ctx, "/usr/bin/install", "-d", "-m", "0700", "-o", ServiceUser, "-g", ServiceUser, bootstrapDir)
		return err
	})
	if err != nil {
		return stepError(ExitConfiguration, "create "+bootstrapDir, err)
	}
	p.bootstrapSeq = seq
	out, err = p.root(ctx, "/usr/bin/stat", "-c", "%U:%G:%a", bootstrapDir)
	if err != nil || strings.TrimSpace(string(out)) != ServiceUser+":"+ServiceUser+":700" {
		return fail(ExitConfiguration, "%s inside the container is not 0700 %s", bootstrapDir, ServiceUser)
	}
	return nil
}

// checkEndpointTrust puts the Proxmox CA in the container and verifies, from
// inside it, the chain the endpoint really serves. Nothing secret exists yet.
func (p *provision) checkEndpointTrust(ctx context.Context) error {
	if err := p.writeContainerFile(ctx, pveCAInContainer, "0640", p.plan.CAPEM); err != nil {
		return failWrap(ExitConfiguration, "install the Proxmox CA in the container", err)
	}
	_, err := p.sm(ctx, false, "providers", "check", "--offline", "--tls-only",
		"--endpoint", p.plan.Endpoint, "--ca-file", pveCAInContainer)
	return p.checkFailure("the Proxmox endpoint's certificate chain is not trusted from the container", err)
}

// checkFailure maps `sm providers check` results: exit 8 is a connectivity
// failure, anything else a configuration one.
func (p *provision) checkFailure(what string, err error) error {
	if err == nil {
		return nil
	}
	var status *ExitStatus
	if errors.As(err, &status) && status.Code == ExitConnectivity {
		return failWrap(ExitConnectivity, what+" (is port "+pveAPIPort+" on the host reachable from the container?)", err)
	}
	return failWrap(ExitConfiguration, what, err)
}

// writeContainerFile creates path root:supermgmt with mode and fills it from stdin.
func (p *provision) writeContainerFile(ctx context.Context, file, mode string, data []byte) error {
	if _, err := p.root(ctx, "/usr/bin/install", "-m", mode, "-o", "root", "-g", ServiceUser, "/dev/null", file); err != nil {
		return err
	}
	_, err := p.exec(ctx, "", false, bytes.NewReader(data), "/usr/bin/tee", file)
	return err
}

// ---- S12 ----

var (
	auditPrivileges = []string{"VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit"}
	// VM.Audit is repeated because PVE replaces inherited permissions at a deeper path (ADR-0023).
	powerPrivileges = []string{"VM.Audit", "VM.PowerMgmt"}
)

type roleGrant struct {
	role       string
	privileges []string
	path       string
}

func (p *provision) grants() []roleGrant {
	grants := []roleGrant{{auditRoleFor(p.id), auditPrivileges, "/"}}
	if p.plan.Power {
		grants = append(grants, roleGrant{powerRoleFor(p.id), powerPrivileges, "/vms"})
	}
	return grants
}

func (p *provision) createIdentities(ctx context.Context) error {
	user := userIDFor(p.id)
	if err := p.createNew("S12a", resUser, user,
		func() (bool, error) { return p.pve.UserExists(ctx, user) },
		func() error { return p.pve.CreateUser(ctx, user, ownershipMark(p.id)) }); err != nil {
		return stepError(ExitCreation, "create the Proxmox user", err)
	}
	for _, g := range p.grants() {
		if err := p.createNew("S12b", resRole, g.role,
			func() (bool, error) { return p.pve.RoleExists(ctx, g.role) },
			func() error { return p.pve.CreateRole(ctx, g.role, g.privileges) }); err != nil {
			return stepError(ExitCreation, "create the Proxmox role", err)
		}
	}
	for _, g := range p.grants() {
		if err := p.grantACL(ctx, "S12c", ACL{Path: g.path, Role: g.role, User: user}); err != nil {
			return err
		}
	}
	return nil
}

func refuseAdopt(kind, name string, err error) error {
	if err != nil {
		return failWrap(ExitCreation, "look up Proxmox "+kind+" "+name, err)
	}
	return fail(ExitCreation, "Proxmox %s %s already exists and was not created by this install; it is left untouched", kind, name)
}

func (p *provision) grantACL(ctx context.Context, step string, acl ACL) error {
	_, err := p.create(step, resACL, aclName(acl), func() error { return p.pve.AddACL(ctx, acl) })
	return stepError(ExitCreation, "grant the Proxmox role", err)
}

func aclName(a ACL) string {
	if a.User != "" {
		return a.Path + "|" + a.Role + "|u:" + a.User
	}
	return a.Path + "|" + a.Role + "|t:" + a.Token
}

func parseACLName(name string) (ACL, bool) {
	parts := strings.SplitN(name, "|", 3)
	if len(parts) != 3 {
		return ACL{}, false
	}
	acl := ACL{Path: parts[0], Role: parts[1]}
	switch {
	case strings.HasPrefix(parts[2], "u:"):
		acl.User = parts[2][2:]
	case strings.HasPrefix(parts[2], "t:"):
		acl.Token = parts[2][2:]
	default:
		return ACL{}, false
	}
	return acl, true
}

// transferToken is S12d-S13: create the token, hand it to the container's
// tmpfs through a short-lived host file, import it offline, and leave no copy.
func (p *provision) transferToken(ctx context.Context) error {
	user := userIDFor(p.id)
	defer func() { p.tokenSecret = "" }()
	if err := p.createNew("S12d", resToken, user+"!"+pveTokenID,
		func() (bool, error) { return p.pve.TokenExists(ctx, user, pveTokenID) },
		func() error {
			secret, err := p.pve.AddToken(ctx, user, pveTokenID)
			p.tokenSecret = user + "!" + pveTokenID + "=" + secret.Reveal()
			return err
		}); err != nil {
		return stepError(ExitCreation, "create the Proxmox token", err)
	}
	for _, g := range p.grants() {
		if err := p.grantACL(ctx, "S12d", ACL{Path: g.path, Role: g.role, Token: user + "!" + pveTokenID}); err != nil {
			return err
		}
	}
	stage, err := p.stageTokenFile(ctx)
	if err != nil {
		return err
	}
	if err := p.pushToken(ctx, stage); err != nil {
		return err
	}
	if err := p.removeStage(stage); err != nil {
		return err
	}
	return p.importToken(ctx)
}

// stageTokenFile writes the secret to a file in a fresh 0700 directory under
// the journal directory (itself 0700 and new). The path is journaled first.
func (p *provision) stageTokenFile(_ context.Context) (stage stagedToken, err error) {
	dir := path.Join(p.j.dir, stageDirName)
	if p.d.Files.Exists(dir) {
		return stagedToken{}, fail(ExitCreation, "%s already exists", dir)
	}
	seq, err := p.create("S12e", resHostTemp, dir, func() error {
		if err := p.d.Files.MkdirAll(dir, 0o700, Owner{}); err != nil {
			return err
		}
		return p.d.Files.WriteFile(path.Join(dir, "pve-token"), []byte(p.tokenSecret), 0o600, Owner{})
	})
	if err != nil {
		return stagedToken{}, stepError(ExitCreation, "stage the token on the host", err)
	}
	return stagedToken{dir: dir, file: path.Join(dir, "pve-token"), seq: seq}, nil
}

type stagedToken struct {
	dir, file string
	seq       int
}

func (p *provision) pushToken(ctx context.Context, s stagedToken) error {
	owner := Owner{User: ServiceUser, Group: ServiceUser}
	if err := p.pve.Push(ctx, p.plan.VMID, s.file, bootstrapTokenFile, owner, 0o600); err != nil {
		return failWrap(ExitConfiguration, "push the token into the container", err)
	}
	if err := p.hit("S12f:pushed"); err != nil {
		return err
	}
	want := ServiceUser + ":" + ServiceUser + ":600"
	if p.tokenFileOwner(ctx) == want {
		return nil
	}
	for _, argv := range [][]string{
		{"/usr/bin/chown", ServiceUser + ":" + ServiceUser, bootstrapTokenFile},
		{"/usr/bin/chmod", "0600", bootstrapTokenFile},
	} {
		if _, err := p.root(ctx, argv...); err != nil {
			return failWrap(ExitConfiguration, "fix the token file owner", err)
		}
	}
	if got := p.tokenFileOwner(ctx); got != want {
		return fail(ExitConfiguration, "the token file in the container is %q, want %q", got, want)
	}
	return nil
}

func (p *provision) tokenFileOwner(ctx context.Context) string {
	out, err := p.root(ctx, "/usr/bin/stat", "-c", "%U:%G:%a", bootstrapTokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (p *provision) removeStage(s stagedToken) error {
	if err := p.d.Files.RemoveAll(s.dir); err != nil || p.d.Files.Exists(s.file) {
		return fail(ExitConfiguration, "could not remove the staged token from the host")
	}
	if err := p.j.mark(s.seq, phaseUndone); err != nil {
		return failWrap(ExitConfiguration, "write the install journal", err)
	}
	return p.hit("S12h:removed")
}

func (p *provision) importToken(ctx context.Context) error {
	_, err := p.sm(ctx, true, "secrets", "import", "--offline", "--name", providerSecretName,
		"--from-file", bootstrapTokenFile, "--delete-source")
	if err != nil {
		return failWrap(ExitConfiguration, "import the token into the secret store", err)
	}
	if err := p.hit("S13:imported"); err != nil {
		return err
	}
	if _, err := p.root(ctx, "/usr/bin/test", "!", "-e", bootstrapTokenFile); err != nil {
		return fail(ExitConfiguration, "the token file is still present in the container after import")
	}
	if _, err := p.root(ctx, "/usr/bin/rm", "-rf", bootstrapDir); err != nil {
		return failWrap(ExitConfiguration, "remove "+bootstrapDir, err)
	}
	if err := p.j.mark(p.bootstrapSeq, phaseUndone); err != nil {
		return failWrap(ExitConfiguration, "write the install journal", err)
	}
	return nil
}

// ---- S14, S15 ----

func (p *provision) registerProvider(ctx context.Context) error {
	l := applianceLayout()
	current, err := p.root(ctx, "/usr/bin/cat", l.ConfigFile)
	if err != nil {
		return failWrap(ExitConfiguration, "read the container configuration", err)
	}
	block, err := yaml.Marshal(struct {
		Providers []config.ProxmoxProvider `yaml:"providers"`
	}{[]config.ProxmoxProvider{{
		Type: config.ProviderProxmox, Name: providerName, Endpoint: p.plan.Endpoint, CredentialRef: providerSecretRef,
		VerifyTLS: true, CAFile: pveCAInContainer, SyncInterval: 30 * time.Second,
	}}})
	if err != nil {
		return failWrap(ExitConfiguration, "render the provider", err)
	}
	updated := append(bytes.TrimRight(current, "\n"), '\n')
	updated = append(updated, block...)
	if _, err := config.LoadBytes(updated, nil); err != nil {
		return failWrap(ExitConfiguration, "the provider configuration is invalid", err)
	}
	if _, err := p.exec(ctx, "", false, bytes.NewReader(updated), "/usr/bin/tee", l.ConfigFile); err != nil {
		return failWrap(ExitConfiguration, "write the container configuration", err)
	}
	return nil
}

func (p *provision) checkProvider(ctx context.Context) error {
	_, err := p.sm(ctx, false, "providers", "check", "--offline", providerName)
	return p.checkFailure("the Proxmox provider check failed", err)
}

func (p *provision) enableService(ctx context.Context) error {
	if _, err := p.root(ctx, "/usr/bin/systemctl", "enable", "--now", UnitName); err != nil {
		return failWrap(ExitConfiguration, "enable the service", err)
	}
	return p.hit("S15b:enabled")
}

// awaitReady waits for /health/ready over the appliance's own CA and then for
// the admin doctor to report the first Proxmox discovery.
func (p *provision) awaitReady(ctx context.Context) error {
	probe := Probe{URL: p.publicURL + "/health/ready", ServerName: p.guestIP.String(), RootPEM: p.appliancePEM}
	if err := p.d.Health.WaitReady(ctx, probe, p.h.readyWait); err != nil {
		return failWrap(ExitConnectivity, "the service did not become ready", err)
	}
	err := p.waitFor(ctx, p.h.readyWait, "the first Proxmox discovery", func() (bool, error) { return p.providersHealthy(ctx) })
	return stepError(ExitConnectivity, "first discovery not confirmed", err)
}

func (p *provision) providersHealthy(ctx context.Context) (bool, error) {
	out, _ := p.sm(ctx, false, "doctor", "--json") // a failing doctor still prints its report
	var report struct {
		Checks []struct{ Name, Status, Detail string } `json:"checks"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		return false, errors.New("doctor gave no report")
	}
	for _, c := range report.Checks {
		if c.Name == "providers" {
			return c.Status == "ok", fmt.Errorf("providers check is %s: %s", c.Status, c.Detail)
		}
	}
	return false, errors.New("doctor has no providers check")
}

func (p *provision) issueBootstrapCode(ctx context.Context) error {
	out, err := p.sm(ctx, true, "admin", "bootstrap-code")
	if err != nil {
		return failWrap(ExitConfiguration, "obtain the bootstrap code", err)
	}
	p.bootstrapCode = strings.TrimSpace(string(out))
	if p.bootstrapCode == "" {
		return fail(ExitConfiguration, "obtain the bootstrap code: empty output")
	}
	return nil
}

// ---- S16 ----

func (p *provision) commitAndReport(_ context.Context) error {
	return p.commitInstall()
}

func caFingerprint(pemBytes []byte) string {
	certs, err := parseCertificates(pemBytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(certs[0].Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
