package installer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/config"
)

// Installer runs one `sm install` mode against the seams in Deps.
type Installer struct{ d Deps }

// New returns an Installer over d.
func New(d Deps) *Installer { return &Installer{d: d} }

// Run installs according to o.Mode. Every failure is an *Error with its §3.7 exit code.
func (in *Installer) Run(ctx context.Context, o Options) error {
	switch o.Mode {
	case ModeServer:
		return in.runServer(ctx, o)
	case ModeRestore:
		return in.runRestore(ctx, o)
	case ModeLocal:
		return in.runLocal(ctx, o)
	case ModeClient:
		return in.runClient(o)
	case ModeAuto:
		return in.runAuto(ctx, o)
	case ModeProxmoxLXC:
		return in.runProxmoxLXC(ctx, o)
	case ModeUpgrade:
		return in.runUpgrade(ctx, o)
	case ModeUninstall:
		return in.runUninstall(ctx, o)
	default:
		return fail(ExitInvalid, "unsupported install mode %q", o.Mode)
	}
}

func (in *Installer) say(format string, args ...any) {
	_, _ = fmt.Fprintf(in.d.Out, format+"\n", args...)
}

func (in *Installer) interactive() bool { return in.d.Prompter != nil }

func (in *Installer) reportHost() {
	h := in.d.Host
	in.say("detected: os=%s root=%t systemd=%t interactive=%t", h.GOOS, h.UID == 0, h.HasSystemd, in.interactive())
}

// ---- server and restore ----

func (in *Installer) runServer(ctx context.Context, o Options) error {
	l, s, err := in.prepareServer(o)
	if err != nil {
		return err
	}
	if err := in.installServerFiles(ctx, o, l, s); err != nil {
		return err
	}
	if err := in.startAndWait(ctx, l); err != nil {
		return err
	}
	return in.printBootstrap(ctx, l)
}

func (in *Installer) runRestore(ctx context.Context, o Options) error {
	if o.Archive == "" || o.KeyExport == "" {
		return fail(ExitInvalid, "restore requires --archive and --key-export")
	}
	for _, f := range []string{o.Archive, o.KeyExport} {
		if !in.d.Files.Exists(f) {
			return fail(ExitInvalid, "file not found: %s", f)
		}
	}
	l, s, err := in.prepareServer(o)
	if err != nil {
		return err
	}
	if err := in.installServerFiles(ctx, o, l, s); err != nil {
		return err
	}
	if err := in.restoreOffline(ctx, o, l); err != nil {
		return err
	}
	if err := in.startAndWait(ctx, l); err != nil {
		return err
	}
	in.say("restored; the service is in restore hold. Review `sm doctor` and the interrupted jobs, then run `sm admin restore-complete`.")
	return nil
}

// prepareServer detects, validates and confirms; it changes nothing on disk.
func (in *Installer) prepareServer(o Options) (layout, serverSettings, error) {
	in.reportHost()
	l := o.layout(in.d.Host)
	if err := in.requireSystemdRoot(); err != nil {
		return l, serverSettings{}, err
	}
	o, err := in.withPublicURL(o)
	if err != nil {
		return l, serverSettings{}, err
	}
	s, err := resolveServer(o, in.d.Files, in.d.Clock.Now())
	if err != nil {
		return l, s, err
	}
	if _, err := renderServerConfig(l, s); err != nil {
		return l, s, err
	}
	if err := in.checkExisting(l, o); err != nil {
		return l, s, err
	}
	in.say("plan: %s; tls=%s listen=%s public_url=%s", describe(l), s.TLS, s.Listen, s.PublicURL)
	return l, s, in.confirmPlan(o)
}

func (in *Installer) requireSystemdRoot() error {
	h := in.d.Host
	if h.GOOS != "linux" || !h.HasSystemd {
		return fail(ExitUnsupported, "server mode needs Linux with systemd (os=%s systemd=%t)", h.GOOS, h.HasSystemd)
	}
	if h.UID != 0 {
		return fail(ExitPrerequisite, "server mode must run as root")
	}
	return nil
}

func (in *Installer) withPublicURL(o Options) (Options, error) {
	if o.PublicURL != "" {
		return o, nil
	}
	if !in.interactive() {
		return o, fail(ExitInvalid, "--public-url is required in non-interactive mode")
	}
	answer, err := in.d.Prompter.Ask("Public https URL of this server (for example https://mgmt.example.com)")
	if err != nil {
		return o, failWrap(ExitCancelled, "read answer", err)
	}
	o.PublicURL = strings.TrimSpace(answer)
	return o, nil
}

func (in *Installer) confirmPlan(o Options) error {
	if !in.interactive() || o.Yes {
		return nil
	}
	return in.confirm("Proceed?")
}

func (in *Installer) confirm(question string) error {
	ok, err := in.d.Prompter.Confirm(question)
	if err != nil {
		return failWrap(ExitCancelled, "read answer", err)
	}
	if !ok {
		return fail(ExitCancelled, "cancelled")
	}
	return nil
}

// checkExisting refuses to guess when an installation or several candidate
// configurations are present: it fails without a terminal and asks with one.
// Config and data are never overwritten either way.
func (in *Installer) checkExisting(l layout, o Options) error {
	if o.Mode == ModeClient {
		return nil
	}
	found := in.existingPaths(l)
	configs := in.configCandidates(l)
	if len(found) == 0 && len(configs) <= 1 {
		return nil
	}
	detail := fmt.Sprintf("existing files: %s; candidate configs: %s", strings.Join(found, ", "), strings.Join(configs, ", "))
	if !in.interactive() {
		return fail(ExitPrerequisite, "existing installation or ambiguous configuration; refusing to guess (%s)", detail)
	}
	in.say("%s", detail)
	return in.confirm("Replace the binary and unit, keeping the existing configuration and data?")
}

func (in *Installer) existingPaths(l layout) []string {
	var found []string
	for _, p := range []string{l.Binary, l.UnitPath, l.ConfigFile, filepath.Join(l.DataDir, "supermgmt.db")} {
		if p != "" && in.d.Files.Exists(p) {
			found = append(found, p)
		}
	}
	return found
}

func (in *Installer) configCandidates(l layout) []string {
	h := in.d.Host
	local := config.Resolve(h.GOOS, h.Env, h.Home).Config
	var found []string
	for _, p := range []string{l.ConfigFile, config.ServerPaths().Config, local} {
		if in.d.Files.Exists(p) && !contains(found, p) {
			found = append(found, p)
		}
	}
	return found
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (in *Installer) installServerFiles(ctx context.Context, o Options, l layout, s serverSettings) error {
	if err := in.ensureServiceUser(ctx, l); err != nil {
		return err
	}
	if err := in.makeServerDirs(l); err != nil {
		return err
	}
	if err := in.d.Files.CopyFile(o.Binary, l.Binary, 0o755, Owner{}); err != nil {
		return failWrap(ExitConfiguration, "install binary", err)
	}
	if err := in.writeServerConfig(l, s); err != nil {
		return err
	}
	unit := Unit{Name: UnitName, Path: l.UnitPath}
	if err := in.d.Files.WriteFile(unit.Path, renderServerUnit(l), 0o644, Owner{}); err != nil {
		return failWrap(ExitConfiguration, "write systemd unit", err)
	}
	if err := in.d.Services.Register(ctx, unit); err != nil {
		return failWrap(ExitConfiguration, "register systemd unit", err)
	}
	return nil
}

func (in *Installer) ensureServiceUser(ctx context.Context, l layout) error {
	exists, err := in.d.Accounts.UserExists(ServiceUser)
	if err != nil {
		return failWrap(ExitCreation, "look up service user", err)
	}
	if exists {
		return nil
	}
	if err := in.d.Accounts.CreateServiceUser(ctx, ServiceUser, l.DataDir); err != nil {
		return failWrap(ExitCreation, "create service user", err)
	}
	return nil
}

func (in *Installer) makeServerDirs(l layout) error {
	svc := Owner{User: ServiceUser, Group: ServiceUser}
	dirs := []struct {
		path  string
		mode  fs.FileMode
		owner Owner
	}{
		{l.ConfigDir, 0o750, Owner{User: "root", Group: ServiceUser}},
		{l.DataDir, 0o750, svc},
		{filepath.Dir(l.KeysDir), 0o700, svc},
		{l.KeysDir, 0o700, svc},
		{l.BackupsDir, 0o750, svc},
	}
	for _, d := range dirs {
		if err := in.d.Files.MkdirAll(d.path, d.mode, d.owner); err != nil {
			return failWrap(ExitCreation, "create "+d.path, err)
		}
	}
	return nil
}

func (in *Installer) writeServerConfig(l layout, s serverSettings) error {
	if in.d.Files.Exists(l.ConfigFile) {
		in.say("keeping existing configuration %s", l.ConfigFile)
		return nil
	}
	data, err := renderServerConfig(l, s)
	if err != nil {
		return err
	}
	if err := in.d.Files.WriteFile(l.ConfigFile, data, 0o640, Owner{User: "root", Group: ServiceUser}); err != nil {
		return failWrap(ExitConfiguration, "write configuration", err)
	}
	return nil
}

func (in *Installer) startAndWait(ctx context.Context, l layout) error {
	if err := in.d.Services.Start(ctx, Unit{Name: UnitName, Path: l.UnitPath}); err != nil {
		return failWrap(ExitConfiguration, "start service", err)
	}
	probe, err := in.probe(l)
	if err != nil {
		return err
	}
	if err := in.d.Health.WaitReady(ctx, probe, readyTimeout); err != nil {
		return failWrap(ExitConnectivity, "service did not become ready", err)
	}
	return nil
}

// probe derives the readiness check from the configuration actually in place.
func (in *Installer) probe(l layout) (Probe, error) {
	data, err := in.d.Files.ReadFile(l.ConfigFile)
	if err != nil {
		return Probe{}, failWrap(ExitConfiguration, "read configuration", err)
	}
	res, err := config.LoadBytes(data, nil)
	if err != nil {
		return Probe{}, failWrap(ExitConfiguration, "load configuration", err)
	}
	srv := res.Config.Server
	hostport, err := dialAddress(srv.Listen)
	if err != nil {
		return Probe{}, err
	}
	if srv.TLS.Mode == config.TLSProxy {
		return Probe{URL: "http://" + hostport + "/health/ready", ForwardedProto: "https"}, nil
	}
	pem, err := in.d.Files.ReadFile(srv.TLS.CertFile)
	if err != nil {
		return Probe{}, failWrap(ExitConfiguration, "read certificate", err)
	}
	host, err := publicHost(srv.PublicURL)
	if err != nil {
		return Probe{}, failWrap(ExitConfiguration, "public URL", err)
	}
	return Probe{URL: "https://" + hostport + "/health/ready", ServerName: host, RootPEM: pem}, nil
}

// dialAddress turns a listen address into one the installer can dial locally.
func dialAddress(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if _, numeric := strconv.Atoi(port); err != nil || numeric != nil {
		return "", fail(ExitConfiguration, "cannot probe listen address %q", listen)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

func (in *Installer) printBootstrap(ctx context.Context, l layout) error {
	out, err := in.d.Runner.Run(ctx, Command{Name: l.Binary, Args: []string{"admin", "bootstrap-code", "--config", l.ConfigFile}})
	if err != nil {
		return failWrap(ExitConfiguration, "obtain bootstrap code", err)
	}
	code := strings.TrimSpace(string(out))
	if code == "" {
		return fail(ExitConfiguration, "obtain bootstrap code: empty output")
	}
	in.say("SuperMgmt is running.\nBootstrap code (shown once, single use): %s\nRun `sm login --bootstrap` against your public URL and enter the code to become admin.", code)
	return nil
}

// restoreOffline runs the frozen ADR-0020 commands as the service user so
// the restored files belong to it. Passphrases flow through Stdin untouched.
func (in *Installer) restoreOffline(ctx context.Context, o Options, l layout) error {
	steps := [][]string{
		{"secrets", "import-key", "--offline", "--from", o.KeyExport},
		{"backup", "restore", "--offline", o.Archive},
	}
	for _, args := range steps {
		cmd := Command{Name: l.Binary, Args: append(args, "--config", l.ConfigFile), User: ServiceUser, Stdin: o.Stdin}
		if _, err := in.d.Runner.Run(ctx, cmd); err != nil {
			return restoreFailure(strings.Join(args[:2], " "), err)
		}
	}
	return nil
}

// restoreFailure keeps the documented child codes 2 and 4; anything else is a restore failure.
func restoreFailure(step string, err error) error {
	var status *ExitStatus
	code := ExitRestore
	if errors.As(err, &status) && (status.Code == ExitInvalid || status.Code == ExitPrerequisite) {
		code = status.Code
	}
	return failWrap(code, "sm "+step, err)
}

// ---- local and client ----

func (in *Installer) runLocal(ctx context.Context, o Options) error {
	in.reportHost()
	h := in.d.Host
	if h.GOOS != "linux" && h.GOOS != "darwin" {
		return fail(ExitUnsupported, "unsupported OS %q", h.GOOS)
	}
	if o.Resident && h.GOOS == "linux" && !h.HasSystemd {
		return fail(ExitUnsupported, "--resident needs systemd on Linux")
	}
	l := o.layout(h)
	if err := in.checkExisting(l, o); err != nil {
		return err
	}
	in.say("plan: %s", describe(l))
	if err := in.confirmPlan(o); err != nil {
		return err
	}
	if err := in.installBinary(o, l); err != nil {
		return err
	}
	if err := in.makeLocalDirs(l); err != nil {
		return err
	}
	if err := in.writeLocalConfig(l, o); err != nil {
		return err
	}
	if o.Resident {
		if err := in.installResident(ctx, l); err != nil {
			return err
		}
	}
	in.say("installed %s; make sure %s is on your PATH", l.Binary, l.BinDir)
	return nil
}

func (in *Installer) runClient(o Options) error {
	in.reportHost()
	l := o.layout(in.d.Host)
	if err := in.installBinary(o, l); err != nil {
		return err
	}
	if err := in.d.Files.MkdirAll(l.ConfigDir, 0o700, Owner{}); err != nil {
		return failWrap(ExitCreation, "create "+l.ConfigDir, err)
	}
	if !in.d.Files.Exists(l.ProfileFile) {
		if err := in.d.Files.WriteFile(l.ProfileFile, []byte(emptyProfiles), 0o600, Owner{}); err != nil {
			return failWrap(ExitConfiguration, "write client profile", err)
		}
	}
	in.say("installed %s with an empty profile at %s; make sure %s is on your PATH", l.Binary, l.ProfileFile, l.BinDir)
	return nil
}

func (in *Installer) installBinary(o Options, l layout) error {
	if err := in.d.Files.MkdirAll(l.BinDir, 0o755, Owner{}); err != nil {
		return failWrap(ExitCreation, "create "+l.BinDir, err)
	}
	if err := in.d.Files.CopyFile(o.Binary, l.Binary, 0o755, Owner{}); err != nil {
		return failWrap(ExitConfiguration, "install binary", err)
	}
	return nil
}

func (in *Installer) makeLocalDirs(l layout) error {
	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{{l.ConfigDir, 0o700}, {l.DataDir, 0o700}} {
		if err := in.d.Files.MkdirAll(d.path, d.mode, Owner{}); err != nil {
			return failWrap(ExitCreation, "create "+d.path, err)
		}
	}
	return nil
}

func (in *Installer) writeLocalConfig(l layout, o Options) error {
	if in.d.Files.Exists(l.ConfigFile) {
		in.say("keeping existing configuration %s", l.ConfigFile)
		return nil
	}
	data, err := renderLocalConfig(l, firstNonEmpty(o.InstanceName, "local"), o.Resident)
	if err != nil {
		return err
	}
	if err := in.d.Files.WriteFile(l.ConfigFile, data, 0o600, Owner{}); err != nil {
		return failWrap(ExitConfiguration, "write configuration", err)
	}
	return nil
}

func (in *Installer) installResident(ctx context.Context, l layout) error {
	unit, content := in.residentUnit(l)
	if err := in.d.Files.MkdirAll(filepath.Dir(unit.Path), 0o755, Owner{}); err != nil {
		return failWrap(ExitCreation, "create "+filepath.Dir(unit.Path), err)
	}
	if err := in.d.Files.WriteFile(unit.Path, content, 0o644, Owner{}); err != nil {
		return failWrap(ExitConfiguration, "write resident unit", err)
	}
	if err := in.d.UserServices.Register(ctx, unit); err != nil {
		return failWrap(ExitConfiguration, "register resident unit", err)
	}
	if err := in.d.UserServices.Start(ctx, unit); err != nil {
		return failWrap(ExitConfiguration, "start resident daemon", err)
	}
	return nil
}

func (in *Installer) residentUnit(l layout) (Unit, []byte) {
	h := in.d.Host
	if h.GOOS == "darwin" {
		return Unit{Name: LaunchdLabel, Path: filepath.Join(h.Home, "Library", "LaunchAgents", LaunchdLabel+".plist")}, renderLaunchAgent(l)
	}
	configHome := firstNonEmpty(h.Env["XDG_CONFIG_HOME"], filepath.Join(h.Home, ".config"))
	return Unit{Name: UnitName, Path: filepath.Join(configHome, "systemd", "user", UnitName)}, renderUserUnit(l)
}
