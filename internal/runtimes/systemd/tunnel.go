package systemd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// TunnelParams asks node.setup to install the Cloudflare tunnel connector
// (ADR-0037). The token is the tunnel's run token: it reaches the node only as
// stdin of one staging step and is never rendered into a command, a step name
// or an error.
type TunnelParams struct{ Token audit.Secret }

// tokenRE is the alphabet of a tunnel token (base64 of a small JSON document).
// It admits no whitespace, so the file content is exactly token plus newline.
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9+/_=-]+$`)

const (
	minTokenLength = 16
	maxTokenLength = 4096
)

// Validate checks the token shape and that this build pins Cloudflare's key,
// before anything touches the node.
func (t TunnelParams) Validate() error {
	if token := t.Token.Reveal(); len(token) < minTokenLength || len(token) > maxTokenLength || !tokenRE.MatchString(token) {
		return invalid("tunnel token is not a valid tunnel token")
	}
	_, err := cloudflarePin.keyring()
	return err
}

// supportedDistributions maps /etc/os-release ID to the VERSION_CODENAME of the
// one release of it that is supported (spec: Debian 13 and Ubuntu 24.04).
var supportedDistributions = map[string]string{"debian": "trixie", "ubuntu": "noble"}

// parseOSRelease reads "<ID> <VERSION_CODENAME>" and returns the codename of a
// supported distribution.
func parseOSRelease(out string) (string, error) {
	fields := strings.Fields(out)
	if len(fields) == 2 && supportedDistributions[fields[0]] == fields[1] {
		return fields[1], nil
	}
	return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "the cloudflared transport supports Debian 13 and Ubuntu 24.04 nodes only")
}

// parsePackageStatus reads `dpkg-query -W -f='${db:Status-Abbrev} ${Version}'`:
// installed means status "ii".
func parsePackageStatus(out string) bool {
	fields := strings.Fields(out)
	return len(fields) > 0 && fields[0] == "ii"
}

// parseSHA256 reads the output of `sha256sum < file`: 64 lower-case hex digits.
func parseSHA256(out string) (string, bool) {
	fields := strings.Fields(out)
	if len(fields) == 0 || len(fields[0]) != sha256.Size*2 {
		return "", false
	}
	if _, err := hex.DecodeString(fields[0]); err != nil || fields[0] != strings.ToLower(fields[0]) {
		return "", false
	}
	return fields[0], true
}

func sha256Hex(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// cloudflareSource is the apt source line of the one repository setup adds.
// cloudflareSource is the apt source line of Cloudflare's install guide, whose
// suite is "any" for every Debian and Ubuntu release.
func cloudflareSource() string {
	return "deb [signed-by=" + templates.CloudflareKeyringPath + "] https://pkg.cloudflare.com/cloudflared any main\n"
}

// cloudflaredUnit is the SuperMgmt-owned unit. The token is read from its
// root-only file by cloudflared itself: it is in neither argv nor environment.
func cloudflaredUnit() string {
	return `[Unit]
Description=Cloudflare Tunnel (managed by SuperMgmt)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
TimeoutStartSec=30
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file ${CREDENTIALS_DIRECTORY}/token
Restart=on-failure
RestartSec=5s
# The token is handed over by systemd (read as root, exposed read-only to the
# dynamic user); the process itself never runs as root.
DynamicUser=yes
LoadCredential=token:` + templates.CloudflaredTokenPath + `
# cloudflared only dials out and notifies systemd over a unix socket.
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
`
}

func tokenFile(t TunnelParams) string { return t.Token.Reveal() + "\n" }

// ensureTunnel installs cloudflared from Cloudflare's signed repository (the
// pinned key, nothing fetched), the token file and the SuperMgmt unit, and
// starts it. Every file is rewritten only when its hash differs, so a re-run
// changes nothing and a changed token is the only reason to restart.
func (s stepper) ensureTunnel(ctx context.Context, t TunnelParams) error {
	keyring, err := cloudflarePin.keyring()
	if err != nil {
		return err
	}
	if err := s.requireSupportedDistribution(ctx); err != nil {
		return err
	}
	source := cloudflareSource()
	installed, err := s.cloudflaredInstalled(ctx)
	if err != nil {
		return err
	}
	owned, foreign, err := s.sourceOwnership(ctx, source)
	if err != nil {
		return err
	}
	if !installed && foreign {
		return smerr.New(smerr.CodeConflict, "", templates.CloudflaredSourcePath+" already exists with other content and cloudflared is not installed")
	}
	managed := !installed || owned
	if managed {
		if err := s.ensureRepository(ctx, string(keyring), source); err != nil {
			return err
		}
		if !installed {
			if err := s.installCloudflared(ctx); err != nil {
				return err
			}
		}
	}
	return s.ensureTunnelService(ctx, t)
}

// sourceOwnership reads the apt source file: owned when it is exactly the one
// setup writes, foreign when a file with other content sits at that path
// (Cloudflare's own install guide writes it). A foreign source is never
// replaced or removed; it only stops setup from installing the package.
func (s stepper) sourceOwnership(ctx context.Context, source string) (owned, foreign bool, err error) {
	have, present, err := s.fileHash(ctx, templates.CloudflaredSourcePath)
	if err != nil || !present {
		return false, false, err
	}
	owned = have == sha256Hex(source)
	return owned, !owned, nil
}

func (s stepper) ensureRepository(ctx context.Context, keyring, source string) error {
	if err := s.ensureDir(ctx, "0755", "root", "root", templates.AptKeyringDir); err != nil {
		return err
	}
	if _, err := s.ensureFile(ctx, templates.CloudflareKeyringPath, "0644", keyring); err != nil {
		return err
	}
	_, err := s.ensureFile(ctx, templates.CloudflaredSourcePath, "0644", source)
	return err
}

func (s stepper) installCloudflared(ctx context.Context) error {
	if err := s.do(ctx, "setup.apt_update_cloudflared", nil, nil); err != nil {
		return err
	}
	return s.do(ctx, "setup.apt_install_cloudflared", nil, nil)
}

func (s stepper) ensureTunnelService(ctx context.Context, t TunnelParams) error {
	wasActive, err := s.tunnelActive(ctx)
	if err != nil {
		return err
	}
	for _, dir := range []struct{ mode, path string }{{"0755", templates.BrokerConfigDir}, {"0700", templates.CloudflaredDir}} {
		if err := s.ensureDir(ctx, dir.mode, "root", "root", dir.path); err != nil {
			return err
		}
	}
	tokenChanged, err := s.sensitive().ensureFile(ctx, templates.CloudflaredTokenPath, "0600", tokenFile(t))
	if err != nil {
		return err
	}
	unitChanged, err := s.ensureFile(ctx, templates.CloudflaredUnitPath, "0644", cloudflaredUnit())
	if err != nil {
		return err
	}
	unit := map[string]string{"unit": templates.CloudflaredUnitName}
	if err := s.do(ctx, "setup.daemon_reload", nil, nil); err != nil {
		return err
	}
	if err := s.do(ctx, "setup.tunnel_enable", unit, nil); err != nil {
		return err
	}
	if wasActive && (tokenChanged || unitChanged) {
		if err := s.do(ctx, "setup.tunnel_restart", unit, nil); err != nil {
			return err
		}
	}
	active, err := s.tunnelActive(ctx)
	if err != nil {
		return err
	}
	if !active {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", templates.CloudflaredUnitName+" is not active after it was started")
	}
	return nil
}

// tunnelActive reads the unit's state with the unprivileged systemd.show read.
func (s stepper) tunnelActive(ctx context.Context) (bool, error) {
	res, err := read(ctx, s.ex, "systemd.show", map[string]string{"unit": templates.CloudflaredUnitName})
	if err != nil {
		return false, err
	}
	if res.ExitStatus != 0 {
		return false, smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("reading %s failed (exit %d)", templates.CloudflaredUnitName, res.ExitStatus))
	}
	return parseProps(string(res.Stdout)).first("ActiveState") == "active", nil
}

// requireSupportedDistribution refuses a node that is not Debian 13 or Ubuntu
// 24.04, the releases the tunnel transport is tested on.
func (s stepper) requireSupportedDistribution(ctx context.Context) error {
	out, err := succeeded(ctx, s.ex, "setup.os_release", nil)
	if err != nil {
		return err
	}
	_, err = parseOSRelease(out)
	return err
}

func (s stepper) cloudflaredInstalled(ctx context.Context) (bool, error) {
	res, err := read(ctx, s.ex, "setup.cloudflared_package", nil)
	if err != nil {
		return false, err
	}
	if res.ExitStatus > 1 { // 1: dpkg-query knows no such package
		return false, smerr.New(smerr.CodeCapabilityUnavailable, "", "dpkg-query is not available on the node")
	}
	return res.ExitStatus == 0 && parsePackageStatus(string(res.Stdout)), nil
}

// fileHash returns the sha256 of a file setup manages, read by root so the
// token directory is reachable; the content itself is never read back.
func (s stepper) fileHash(ctx context.Context, path string) (hash string, present bool, err error) {
	res, err := s.run(ctx, "setup.file_sha256", map[string]string{"path": path}, nil)
	if err != nil {
		return "", false, err
	}
	switch res.ExitStatus {
	case 0:
		if hash, ok := parseSHA256(string(res.Stdout)); ok {
			return hash, true, nil
		}
		return "", false, smerr.New(smerr.CodeCapabilityUnavailable, "", "hashing "+path+" returned an unreadable result")
	case fileAbsentExit:
		return "", false, nil
	}
	return "", false, smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("hashing %s failed (exit %d)", path, res.ExitStatus))
}

// fileAbsentExit is the exit status of setup.file_sha256 for a missing file.
const fileAbsentExit = 3

// ensureFile installs content at path unless the node already holds exactly
// it, then proves by hash that the node holds exactly it. It reports whether
// it wrote.
func (s stepper) ensureFile(ctx context.Context, path, mode, content string) (bool, error) {
	want := sha256Hex(content)
	if have, present, err := s.fileHash(ctx, path); err != nil || (present && have == want) {
		return false, err
	}
	if err := s.installFile(ctx, path, mode, "root", "root", content, nil); err != nil {
		return false, err
	}
	have, present, err := s.fileHash(ctx, path)
	if err != nil {
		return false, err
	}
	if !present || have != want {
		return false, smerr.New(smerr.CodeCapabilityUnavailable, "", path+" does not hold the expected content after it was installed")
	}
	return true, nil
}

func (s stepper) sensitive() stepper {
	s.secret = true
	return s
}

// RemoveTunnelParams is what RemoveTunnel needs; AdminIsRoot as in SetupParams.
type RemoveTunnelParams struct{ AdminIsRoot bool }

// RemoveTunnel undoes ensureTunnel and nothing else: it stops and disables the
// unit, removes the unit, the token file and its (empty) directory, and, only
// while the apt source on the node is still exactly the one setup wrote, that
// source, the keyring and the cloudflared package. A cloudflared installed by
// somebody else, and any other repository configuration, stay. Every step is
// idempotent, so an interrupted removal is simply run again.
func RemoveTunnel(ctx context.Context, ex transport.Executor, p RemoveTunnelParams) error {
	s := stepper{ex: ex, sudo: !p.AdminIsRoot}
	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"service", s.removeTunnelService},
		{"files", s.removeTunnelFiles},
		{"package", s.removeCloudflared},
	}
	for _, step := range steps {
		if err := step.run(ctx); err != nil {
			return fmt.Errorf("node.tunnel.disable step %s: %w", step.name, err)
		}
	}
	return nil
}

func (s stepper) removeTunnelService(ctx context.Context) error {
	if err := s.do(ctx, "setup.tunnel_disable", map[string]string{"unit": templates.CloudflaredUnitName}, nil); err != nil {
		return err
	}
	if err := s.do(ctx, "setup.file_remove", map[string]string{"path": templates.CloudflaredUnitPath}, nil); err != nil {
		return err
	}
	return s.do(ctx, "setup.daemon_reload", nil, nil)
}

func (s stepper) removeTunnelFiles(ctx context.Context) error {
	for _, path := range []string{templates.CloudflaredTokenPath, templates.CloudflaredUnitPath} {
		if err := s.do(ctx, "setup.file_discard", map[string]string{"path": templates.StagingPath(path)}, nil); err != nil {
			return err
		}
	}
	if err := s.do(ctx, "setup.file_remove", map[string]string{"path": templates.CloudflaredTokenPath}, nil); err != nil {
		return err
	}
	return s.do(ctx, "setup.dir_remove", map[string]string{"path": templates.CloudflaredDir}, nil)
}

func (s stepper) removeCloudflared(ctx context.Context) error {
	have, present, err := s.fileHash(ctx, templates.CloudflaredSourcePath)
	if err != nil || !present || have != sha256Hex(cloudflareSource()) {
		return err // the repository is not ours: neither it nor the package is touched
	}
	installed, err := s.cloudflaredInstalled(ctx)
	if err != nil {
		return err
	}
	if installed {
		if err := s.do(ctx, "setup.apt_remove_cloudflared", nil, nil); err != nil {
			return err
		}
	}
	// The source first: a key without a source is harmless, a source without
	// its key makes every later apt update fail.
	for _, path := range []string{templates.CloudflaredSourcePath, templates.CloudflareKeyringPath} {
		if err := s.do(ctx, "setup.file_remove", map[string]string{"path": path}, nil); err != nil {
			return err
		}
	}
	return nil
}
