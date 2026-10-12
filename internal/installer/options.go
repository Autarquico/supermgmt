package installer

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/config"
)

// Mode is one installer mode (spec §3.4).
type Mode string

const (
	ModeLocal      Mode = "local"
	ModeServer     Mode = "server"
	ModeClient     Mode = "client"
	ModeRestore    Mode = "restore"
	ModeAuto       Mode = "auto"
	ModeProxmoxLXC Mode = "proxmox-lxc"
	ModeUpgrade    Mode = "upgrade"
	ModeUninstall  Mode = "uninstall"
)

// Fixed names of the server installation (spec §8.1, Appendix A).
const (
	ServiceUser = "supermgmt"
	UnitName    = "supermgmt.service"
	binaryName  = "sm"

	defaultProxyListen  = "127.0.0.1:8787"
	defaultDirectListen = "0.0.0.0:8443"
	defaultProxyCIDR    = "127.0.0.1/32"
	readyTimeout        = 60 * time.Second
)

// Options is the whole operator input of one `sm install` run. Nothing in it
// is a secret: passphrases flow through Stdin to the `sm` subprocess.
type Options struct {
	Mode           Mode
	Binary         string // the running sm, copied into place
	TLS            config.TLSMode
	CertFile       string
	KeyFile        string
	TrustedProxies []string
	Listen         string
	PublicURL      string
	InstanceName   string
	Resident       bool // local mode: keep a resident daemon under the user service manager
	Yes            bool // skip the plan confirmation
	Archive        string
	KeyExport      string
	InstallDir     string // SUPERMGMT_INSTALL_DIR
	ConfigDir      string // SUPERMGMT_CONFIG_DIR
	DataDir        string // SUPERMGMT_DATA_DIR
	Stdin          io.Reader

	// Server mode (ADR-0026): NoStart writes and loads the unit without
	// enabling or starting it; SelfSigned (with TLS direct) generates a CA and
	// a server certificate instead of taking CertFile/KeyFile.
	NoStart    bool
	SelfSigned bool

	Appliance Appliance // proxmox-lxc

	// Upgrade and uninstall (ADR-0027). VMID selects an appliance on a
	// Proxmox host (0: the only one).
	UpgradeBinary  string
	AllowDowngrade bool
	PurgeData      bool
	VMID           int
}

// Appliance is the proxmox-lxc input (spec §2.3, §3.5, §3.6). Zero values mean
// "choose": the installer detects, or asks, or (non-interactive) fails on an
// ambiguous choice. Nothing here is a secret.
type Appliance struct {
	VMID            int    // SUPERMGMT_VMID; 0 = first free from 900
	Hostname        string // SUPERMGMT_HOSTNAME; default supermgmt
	Storage         string // SUPERMGMT_STORAGE (rootdir)
	TemplateStorage string // SUPERMGMT_TEMPLATE_STORAGE (vztmpl)
	Bridge          string // SUPERMGMT_BRIDGE; default vmbr0 when present
	Network         string // SUPERMGMT_NETWORK: dhcp | static
	IP              string // SUPERMGMT_IP (CIDR) for static
	Gateway         string // SUPERMGMT_GATEWAY for static
	DNS             string // SUPERMGMT_DNS (comma-separated) for static
	Cores           int    // SUPERMGMT_CORES; default 2
	MemoryMiB       int    // SUPERMGMT_MEMORY; default 2048
	SwapMiB         int    // SUPERMGMT_SWAP; default 512
	DiskGiB         int    // SUPERMGMT_DISK_GIB; default 16
	Power           bool   // SUPERMGMT_PVE_POWER != "0": grant the power role
	PVEEndpoint     string // SUPERMGMT_PVE_ENDPOINT; default the detected host address
	PVECAFile       string // SUPERMGMT_PVE_CA_FILE; default /etc/pve/pve-root-ca.pem
}

// layout holds every path the installer touches for one run.
type layout struct {
	BinDir      string
	Binary      string
	ConfigDir   string
	ConfigFile  string
	DataDir     string
	KeysDir     string
	BackupsDir  string
	UnitPath    string
	ProfileFile string
}

func (o Options) layout(h Host) layout {
	if o.Mode == ModeServer || o.Mode == ModeRestore {
		return o.serverLayout()
	}
	return o.userLayout(h)
}

func (o Options) serverLayout() layout {
	p := config.ServerPaths()
	l := layout{
		BinDir:    firstNonEmpty(o.InstallDir, "/usr/local/bin"),
		ConfigDir: firstNonEmpty(o.ConfigDir, filepath.Dir(p.Config)),
		DataDir:   firstNonEmpty(o.DataDir, p.DataDir),
		UnitPath:  "/etc/systemd/system/" + UnitName,
	}
	l.ConfigFile = filepath.Join(l.ConfigDir, "config.yaml")
	l.KeysDir = filepath.Join(l.DataDir, "secrets", "keys")
	l.BackupsDir = filepath.Join(l.DataDir, "backups")
	l.Binary = filepath.Join(l.BinDir, binaryName)
	return l
}

func (o Options) userLayout(h Host) layout {
	p := config.Resolve(h.GOOS, h.Env, h.Home)
	l := layout{
		BinDir:    firstNonEmpty(o.InstallDir, filepath.Join(h.Home, ".local", "bin")),
		ConfigDir: firstNonEmpty(o.ConfigDir, filepath.Dir(p.Config)),
		DataDir:   firstNonEmpty(o.DataDir, p.DataDir),
	}
	l.ConfigFile = filepath.Join(l.ConfigDir, "config.yaml")
	l.ProfileFile = filepath.Join(l.ConfigDir, "profiles.yaml")
	l.Binary = filepath.Join(l.BinDir, binaryName)
	return l
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// serverSettings are the validated TLS arrangement and addresses of a server install.
type serverSettings struct {
	Name           string
	Listen         string
	PublicURL      string
	TLS            config.TLSMode
	CertFile       string
	KeyFile        string
	TrustedProxies []string
}

// resolveServer applies defaults and validates the TLS arrangement (spec
// §23.1, ADR-0019). Certificates are read through files; none is generated.
func resolveServer(o Options, files Files, now time.Time) (serverSettings, error) {
	s := serverSettings{
		Name:           firstNonEmpty(o.InstanceName, "supermgmt"),
		Listen:         o.Listen,
		PublicURL:      strings.TrimRight(o.PublicURL, "/"),
		TLS:            o.TLS,
		CertFile:       o.CertFile,
		KeyFile:        o.KeyFile,
		TrustedProxies: o.TrustedProxies,
	}
	if s.TLS == "" {
		s.TLS = config.TLSProxy
	}
	host, err := publicHost(s.PublicURL)
	if err != nil {
		return s, err
	}
	switch s.TLS {
	case config.TLSProxy:
		err = s.applyProxy()
	case config.TLSDirect:
		err = s.applyDirect(files, host, now)
	default:
		err = fail(ExitInvalid, "--tls must be proxy or direct, got %q", s.TLS)
	}
	if err != nil {
		return s, err
	}
	return s, nil
}

func (s *serverSettings) applyProxy() error {
	if s.CertFile != "" || s.KeyFile != "" {
		return fail(ExitInvalid, "--tls-cert and --tls-key apply only to --tls direct")
	}
	if s.Listen == "" {
		s.Listen = defaultProxyListen
	}
	if len(s.TrustedProxies) == 0 {
		s.TrustedProxies = []string{defaultProxyCIDR}
	}
	for _, p := range s.TrustedProxies {
		if !isIPOrCIDR(p) {
			return fail(ExitInvalid, "trusted proxy %q is not an IP address or CIDR", p)
		}
	}
	return nil
}

func (s *serverSettings) applyDirect(files Files, host string, now time.Time) error {
	if len(s.TrustedProxies) > 0 {
		return fail(ExitInvalid, "--trusted-proxy applies only to --tls proxy")
	}
	if s.CertFile == "" || s.KeyFile == "" {
		return fail(ExitInvalid, "--tls direct requires --tls-cert and --tls-key")
	}
	if s.Listen == "" {
		s.Listen = defaultDirectListen
	}
	return checkKeyPair(files, s.CertFile, s.KeyFile, host, now)
}

// checkKeyPair requires a readable, matching, unexpired pair whose leaf covers host.
func checkKeyPair(files Files, certFile, keyFile, host string, now time.Time) error {
	certPEM, err := files.ReadFile(certFile)
	if err != nil {
		return failWrap(ExitInvalid, "read --tls-cert", err)
	}
	keyPEM, err := files.ReadFile(keyFile)
	if err != nil {
		return failWrap(ExitInvalid, "read --tls-key", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return failWrap(ExitInvalid, "certificate and key do not form a valid pair", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return failWrap(ExitInvalid, "parse certificate", err)
	}
	if now.After(leaf.NotAfter) {
		return fail(ExitInvalid, "certificate expired on %s", leaf.NotAfter.UTC().Format(time.DateOnly))
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return failWrap(ExitInvalid, "certificate does not cover the public URL host", err)
	}
	return nil
}

// publicHost requires an https URL: clients and proxies must see https.
func publicHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fail(ExitInvalid, "--public-url %q is not a valid URL", raw)
	}
	if u.Scheme != "https" {
		return "", fail(ExitInvalid, "--public-url must use https, got %q", u.Scheme)
	}
	return u.Hostname(), nil
}

func isIPOrCIDR(v string) bool {
	if _, err := netip.ParsePrefix(v); err == nil {
		return true
	}
	return net.ParseIP(v) != nil
}
