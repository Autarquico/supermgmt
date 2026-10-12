package installer

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Fixed names of the appliance (spec §3.5, ADR-0023, ADR-0026).
const (
	installerLockPath   = "/run/lock/supermgmt-installer.lock"
	appliancesDir       = "/var/lib/supermgmt-installer/appliances"
	bootstrapDir        = "/run/supermgmt-bootstrap"
	bootstrapTokenFile  = bootstrapDir + "/pve-token"
	stagedBinary        = "/tmp/supermgmt-sm"
	providerName        = "pve"
	providerSecretName  = "providers/" + providerName + "/token"
	providerSecretRef   = "secret://" + providerSecretName
	pveTokenID          = "sm"
	pveCAInContainer    = "/etc/supermgmt/pve-root-ca.pem"
	defaultPVECAFile    = "/etc/pve/pve-root-ca.pem"
	applianceTag        = "supermgmt"
	defaultHostname     = "supermgmt"
	defaultVMIDFrom     = 900
	supportedPVEMajor   = 9
	templatePrefix      = "debian-13-standard_"
	templateSuffix      = "_amd64.tar.zst"
	pveAPIPort          = "8006"
	applianceListenPort = "8443"
)

// applianceHost holds the file-system seams only the appliance installer
// needs. The real host implements them; Files stays the frozen M2 interface.
type applianceHost interface {
	// Lock takes the exclusive installer lock and returns its release.
	Lock(path string) (release func(), err error)
	// ListDir lists the entry names of dir; a missing directory is empty.
	ListDir(dir string) ([]string, error)
}

// bridgeAddresser tells the host's own address on a bridge, which is where the
// container reaches the Proxmox API when no endpoint is given.
type bridgeAddresser interface {
	BridgeAddress(ctx context.Context, bridge string) (netip.Addr, error)
}

// provisionHooks are the timing and fault-injection seams of one run.
type provisionHooks struct {
	crash     func(point string) error // crashpoints builds only
	pause     func(ctx context.Context, d time.Duration) error
	poll      time.Duration
	guestWait time.Duration // network up inside the container
	lockWait  time.Duration // a PVE task still holding the guest during rollback
	readyWait time.Duration // readiness and first discovery
}

// at lets a crashpoints test end the run at point; it does nothing otherwise.
func (h provisionHooks) at(point string) error {
	if !crashpointsEnabled || h.crash == nil {
		return nil
	}
	return h.crash(point)
}

func (p *provision) hit(point string) error { return p.h.at(point) }

func (u undoer) hit(point string) error { return u.h.at(point) }

func defaultHooks() provisionHooks {
	return provisionHooks{
		pause: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		},
		poll: 2 * time.Second, guestWait: 120 * time.Second, lockWait: 5 * time.Minute, readyWait: 120 * time.Second,
	}
}

// runProxmoxLXC creates the appliance container (spec §3.5, ADR-0026).
func (in *Installer) runProxmoxLXC(ctx context.Context, o Options) error {
	return in.provision(ctx, o, defaultHooks())
}

// appliancePlan is everything decided before the first side effect.
type appliancePlan struct {
	PVEVersion      string
	VMID            int
	Hostname        string
	Storage         string
	TemplateStorage string
	Bridge          string
	Template        string // volume id
	Download        string // template name to download, "" when already present
	Network         GuestNetwork
	Cores           int
	MemoryMiB       int
	SwapMiB         int
	DiskGiB         int
	Endpoint        string
	CAPEM           []byte
	Power           bool
}

// provision is one appliance install: its seams, plan, journal and the facts
// learned inside the container.
type provision struct {
	in   *Installer
	d    Deps
	o    Options
	h    provisionHooks
	pve  PVE
	host applianceHost
	plan appliancePlan

	id string
	j  *journal

	guestIP       netip.Addr
	publicURL     string
	appliancePEM  []byte // the appliance's own CA, for the readiness probe and the operator
	bootstrapSeq  int
	bootstrapCode string
	committed     bool   // the appliance record is written: never roll back
	tokenSecret   string // "<user>!<id>=<secret>", alive only between creation and staging
}

func (in *Installer) provision(ctx context.Context, o Options, h provisionHooks) error {
	p, err := in.newProvision(o, h)
	if err != nil {
		return err
	}
	release, err := p.host.Lock(installerLockPath)
	if err != nil {
		return failWrap(ExitPrerequisite, "another SuperMgmt installer is running", err)
	}
	defer release()
	if err := p.recoverStale(ctx); err != nil {
		return err
	}
	if err := p.resolvePlan(ctx); err != nil {
		return err
	}
	if err := p.confirmPlan(); err != nil {
		return err
	}
	return p.execute(ctx)
}

func (in *Installer) newProvision(o Options, h provisionHooks) (*provision, error) {
	d := in.d
	in.reportHost()
	switch {
	case d.PVE == nil:
		return nil, fail(ExitUnsupported, "this host is not a Proxmox VE host (pveversion not found)")
	case d.Host.GOOS != "linux" || d.Host.GOARCH != "amd64":
		return nil, fail(ExitUnsupported, "proxmox-lxc supports Proxmox VE on linux/amd64 only (got %s/%s)", d.Host.GOOS, d.Host.GOARCH)
	case d.Host.UID != 0:
		return nil, fail(ExitPrerequisite, "proxmox-lxc must run as root on the Proxmox host")
	case o.Binary == "":
		return nil, fail(ExitInvalid, "the running sm binary is unknown")
	}
	host, ok := d.Files.(applianceHost)
	if !ok {
		return nil, fail(ExitPrerequisite, "this host cannot take the installer lock")
	}
	return &provision{in: in, d: d, o: o, h: h, pve: d.PVE, host: host}, nil
}

func (p *provision) say(format string, args ...any) { p.in.say(format, args...) }

// ---- plan ----

func (p *provision) resolvePlan(ctx context.Context) error {
	version, err := p.pve.Version(ctx)
	if err != nil {
		return failWrap(ExitPrerequisite, "read the Proxmox VE version", err)
	}
	major, _, _ := strings.Cut(version, ".")
	if major != strconv.Itoa(supportedPVEMajor) {
		return fail(ExitUnsupported, "Proxmox VE %s is not supported; only %d.x is (docs/compatibility.md)", version, supportedPVEMajor)
	}
	a := p.o.Appliance
	plan := appliancePlan{
		PVEVersion: version, Hostname: firstNonEmpty(a.Hostname, defaultHostname),
		Cores: positiveOr(a.Cores, 2), MemoryMiB: positiveOr(a.MemoryMiB, 2048),
		SwapMiB: positiveOr(a.SwapMiB, 512), DiskGiB: positiveOr(a.DiskGiB, 16), Power: a.Power,
	}
	if err := validHostname(plan.Hostname); err != nil {
		return failWrap(ExitInvalid, "SUPERMGMT_HOSTNAME", err)
	}
	steps := []func(context.Context, *appliancePlan) error{
		p.pickVMID, p.pickStorages, p.pickBridge, p.pickTemplate, p.pickNetwork, p.pickEndpoint,
	}
	for _, step := range steps {
		if err := step(ctx, &plan); err != nil {
			return err
		}
	}
	p.plan = plan
	return nil
}

func positiveOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func (p *provision) pickVMID(ctx context.Context, plan *appliancePlan) error {
	want := p.o.Appliance.VMID
	if want == 0 {
		id, err := p.pve.NextID(ctx, defaultVMIDFrom)
		if err != nil {
			return failWrap(ExitPrerequisite, "find a free VMID", err)
		}
		plan.VMID = id
		return nil
	}
	if err := validVMID(want); err != nil {
		return failWrap(ExitInvalid, "SUPERMGMT_VMID", err)
	}
	free, err := p.vmidFree(ctx, want)
	if err != nil {
		return failWrap(ExitPrerequisite, "check VMID", err)
	}
	if !free {
		return fail(ExitInvalid, "VMID %d is already in use; it is left untouched", want)
	}
	plan.VMID = want
	return nil
}

func (p *provision) vmidFree(ctx context.Context, vmid int) (bool, error) {
	st, err := p.pve.State(ctx, vmid)
	if err != nil || st.Exists {
		return false, err
	}
	next, err := p.pve.NextID(ctx, vmid)
	return err == nil && next == vmid, err
}

func (p *provision) pickStorages(ctx context.Context, plan *appliancePlan) error {
	all, err := p.pve.Storages(ctx)
	if err != nil {
		return failWrap(ExitPrerequisite, "list storages", err)
	}
	a := p.o.Appliance
	if plan.Storage, err = p.choose("storage", "SUPERMGMT_STORAGE", a.Storage, storagesWith(all, "rootdir")); err != nil {
		return err
	}
	plan.TemplateStorage, err = p.choose("template storage", "SUPERMGMT_TEMPLATE_STORAGE", a.TemplateStorage, storagesWith(all, "vztmpl"))
	return err
}

func storagesWith(all []PVEStorage, content string) []string {
	var ids []string
	for _, s := range all {
		if s.Active && contains(s.Content, content) {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

func (p *provision) pickBridge(ctx context.Context, plan *appliancePlan) error {
	bridges, err := p.pve.Bridges(ctx)
	if err != nil {
		return failWrap(ExitPrerequisite, "list bridges", err)
	}
	want := p.o.Appliance.Bridge
	if want == "" && contains(bridges, "vmbr0") {
		want = "vmbr0"
	}
	plan.Bridge, err = p.choose("bridge", "SUPERMGMT_BRIDGE", want, bridges)
	return err
}

// choose returns want when it is a candidate, the only candidate when there is
// one, and otherwise asks (interactive) or fails rather than guess.
func (p *provision) choose(kind, env, want string, candidates []string) (string, error) {
	if want != "" {
		if err := validName(kind, want); err != nil {
			return "", failWrap(ExitInvalid, env, err)
		}
		if !contains(candidates, want) {
			return "", fail(ExitInvalid, "%s %q is not available on this host (found: %s)", kind, want, strings.Join(candidates, ", "))
		}
		return want, nil
	}
	switch {
	case len(candidates) == 0:
		return "", fail(ExitPrerequisite, "no usable %s found on this host", kind)
	case len(candidates) == 1:
		return candidates[0], nil
	case !p.in.interactive():
		return "", fail(ExitInvalid, "several %ss are possible (%s); set %s", kind, strings.Join(candidates, ", "), env)
	}
	answer, err := p.d.Prompter.Ask(fmt.Sprintf("Which %s (%s)", kind, strings.Join(candidates, ", ")))
	if err != nil {
		return "", failWrap(ExitCancelled, "read answer", err)
	}
	if !contains(candidates, answer) {
		return "", fail(ExitInvalid, "%s %q is not one of %s", kind, answer, strings.Join(candidates, ", "))
	}
	return answer, nil
}

// pickTemplate prefers a Debian 13 template already on the storage (highest
// version); otherwise it plans to download the highest one on offer.
func (p *provision) pickTemplate(ctx context.Context, plan *appliancePlan) error {
	local, err := p.pve.Templates(ctx, plan.TemplateStorage)
	if err != nil {
		return failWrap(ExitPrerequisite, "list templates", err)
	}
	if vol := highestTemplate(local, func(v string) string { return v[strings.LastIndex(v, "/")+1:] }); vol != "" {
		plan.Template = vol
		return nil
	}
	offered, err := p.pve.AvailableTemplates(ctx)
	if err != nil {
		return failWrap(ExitPrerequisite, "list downloadable templates", err)
	}
	name := highestTemplate(offered, func(v string) string { return v })
	if name == "" {
		return fail(ExitPrerequisite, "no Debian 13 standard template is available (pveam update?)")
	}
	plan.Download, plan.Template = name, plan.TemplateStorage+":vztmpl/"+name
	return nil
}

func highestTemplate(items []string, base func(string) string) string {
	best, bestVersion := "", []int(nil)
	for _, item := range items {
		name := base(item)
		if !strings.HasPrefix(name, templatePrefix) || !strings.HasSuffix(name, templateSuffix) {
			continue
		}
		v := templateVersion(strings.TrimSuffix(strings.TrimPrefix(name, templatePrefix), templateSuffix))
		if best == "" || compareInts(v, bestVersion) > 0 {
			best, bestVersion = item, v
		}
	}
	return best
}

var reDigits = regexp.MustCompile(`\d+`)

func templateVersion(s string) []int {
	var out []int
	for _, d := range reDigits.FindAllString(s, -1) {
		n, _ := strconv.Atoi(d)
		out = append(out, n)
	}
	return out
}

func compareInts(a, b []int) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x - y
		}
	}
	return 0
}

func (p *provision) pickNetwork(_ context.Context, plan *appliancePlan) error {
	a := p.o.Appliance
	plan.Network = GuestNetwork{Bridge: plan.Bridge}
	switch a.Network {
	case "", "dhcp":
		plan.Network.DHCP = true
		return nil
	case "static":
	default:
		return fail(ExitInvalid, "SUPERMGMT_NETWORK must be dhcp or static, got %q", a.Network)
	}
	var err error
	if plan.Network.Address, err = netip.ParsePrefix(a.IP); err != nil {
		return failWrap(ExitInvalid, "SUPERMGMT_IP must be an address in CIDR form", err)
	}
	if plan.Network.Gateway, err = netip.ParseAddr(a.Gateway); err != nil {
		return failWrap(ExitInvalid, "SUPERMGMT_GATEWAY", err)
	}
	for _, field := range strings.FieldsFunc(a.DNS, func(r rune) bool { return r == ',' || r == ' ' }) {
		addr, err := netip.ParseAddr(field)
		if err != nil {
			return failWrap(ExitInvalid, "SUPERMGMT_DNS", err)
		}
		plan.Network.DNS = append(plan.Network.DNS, addr)
	}
	return nil
}

// pickEndpoint fixes the Proxmox API address the container will use and the
// CA it is verified against (Q4). Both are read now, before anything exists.
func (p *provision) pickEndpoint(ctx context.Context, plan *appliancePlan) error {
	a := p.o.Appliance
	endpoint := a.PVEEndpoint
	if endpoint == "" {
		addr, ok := p.pve.(bridgeAddresser)
		if !ok {
			return fail(ExitInvalid, "cannot detect the host address; set SUPERMGMT_PVE_ENDPOINT")
		}
		ip, err := addr.BridgeAddress(ctx, plan.Bridge)
		if err != nil {
			return failWrap(ExitInvalid, "detect the host address (set SUPERMGMT_PVE_ENDPOINT)", err)
		}
		endpoint = "https://" + net.JoinHostPort(ip.String(), pveAPIPort)
	}
	var err error
	if plan.Endpoint, err = normalizeEndpoint(endpoint); err != nil {
		return err
	}
	caFile := firstNonEmpty(a.PVECAFile, defaultPVECAFile)
	if err := validPath(caFile); err != nil {
		return failWrap(ExitInvalid, "SUPERMGMT_PVE_CA_FILE", err)
	}
	pemBytes, err := p.d.Files.ReadFile(caFile)
	if err != nil {
		return failWrap(ExitPrerequisite, "read the Proxmox CA", err)
	}
	if _, err := parseCertificates(pemBytes); err != nil {
		return failWrap(ExitInvalid, "Proxmox CA "+caFile, err)
	}
	plan.CAPEM = pemBytes
	return nil
}

func normalizeEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fail(ExitInvalid, "SUPERMGMT_PVE_ENDPOINT %q must be https://host[:port]", raw)
	}
	if u.Port() == "" {
		return "https://" + net.JoinHostPort(u.Hostname(), pveAPIPort), nil
	}
	return "https://" + u.Host, nil
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return certs, nil
}

func (p *provision) confirmPlan() error {
	pl := p.plan
	power := "read-only"
	if pl.Power {
		power = "read + power on/off of guests"
	}
	p.say("SuperMgmt installation plan\n\n"+
		"Environment: Proxmox VE %s\nMode:        dedicated unprivileged LXC\nVMID:        %d\nHostname:    %s\n"+
		"Template:    %s%s\nStorage:     %s\nBridge:      %s\nNetwork:     %s\nCPU:         %d cores\nMemory:      %d MiB\nDisk:        %d GiB\n"+
		"Proxmox API: %s (certificate verified against %s)\nAccess:      %s\n\n"+
		"Will create:\n- LXC %d\n- SuperMgmt service inside LXC\n- per-install Proxmox user, roles and token (names end in the install id)\n- provider registration for this cluster\n\n"+
		"Will NOT:\n- open router ports\n- install Docker on the Proxmox host\n- mount the host filesystem into the LXC\n- create a privileged container\n- delete the template cache or any pre-existing resource",
		pl.PVEVersion, pl.VMID, pl.Hostname, pl.Template, map[bool]string{true: " (will be downloaded)", false: ""}[pl.Download != ""],
		pl.Storage, pl.Bridge, describeNetwork(pl.Network), pl.Cores, pl.MemoryMiB, pl.DiskGiB,
		pl.Endpoint, firstNonEmpty(p.o.Appliance.PVECAFile, defaultPVECAFile), power, pl.VMID)
	return p.in.confirmPlan(p.o)
}

func describeNetwork(n GuestNetwork) string {
	if n.DHCP {
		return "DHCP"
	}
	return "static " + n.Address.String() + " via " + n.Gateway.String()
}

// ---- identity ----

func newInstallID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ownershipMark is what the container description carries: the proof that a
// guest was created by this install.
func ownershipMark(id string) string { return "supermgmt install " + id }

func userIDFor(id string) string    { return "sm-" + id + "@pve" }
func auditRoleFor(id string) string { return "SMAudit-" + id }
func powerRoleFor(id string) string { return "SMPower-" + id }
