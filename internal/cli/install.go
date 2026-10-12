package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/installer"
)

// depsFactory builds the installer seams; interactive says whether to prompt.
type depsFactory func(cmd *cobra.Command, interactive bool) installer.Deps

// newInstallCmd is `sm install <mode>` (spec §3.4, ADR-0019). Secrets are never
// flags: restore passes stdin through to the offline `sm` commands.
func newInstallCmd(env []string) *cobra.Command {
	return newInstallCmdWith(env, func(cmd *cobra.Command, interactive bool) installer.Deps {
		var prompts io.Reader
		if interactive {
			prompts = cmd.InOrStdin()
		}
		return installer.SystemDeps(cmd.OutOrStdout(), prompts, env)
	})
}

func newInstallCmdWith(env []string, deps depsFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install <auto|local|server|client|proxmox-lxc|upgrade|uninstall|restore>",
		Short: "Install SuperMgmt (invoked by install.sh)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return usageErrorf("unknown install mode %q", args[0])
		},
	}
	for _, mode := range []installer.Mode{
		installer.ModeAuto, installer.ModeLocal, installer.ModeServer, installer.ModeClient,
		installer.ModeProxmoxLXC, installer.ModeUpgrade, installer.ModeUninstall, installer.ModeRestore,
	} {
		cmd.AddCommand(newInstallModeCmd(mode, env, deps))
	}
	return cmd
}

type installFlags struct {
	tls            string
	tlsCert        string
	tlsKey         string
	trustedProxies []string
	listen         string
	publicURL      string
	name           string
	resident       bool
	archive        string
	keyExport      string
	nonInteractive bool
	yes            bool
	noStart        bool
	binary         string
	vmid           int
	allowDowngrade bool
	purgeData      bool
}

func newInstallModeCmd(mode installer.Mode, env []string, deps depsFactory) *cobra.Command {
	var f installFlags
	cmd := &cobra.Command{
		Use:   string(mode),
		Short: "Install in " + string(mode) + " mode",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := f.options(mode, env, cmd)
			if err != nil {
				return err
			}
			interactive := !f.nonInteractive && !envFlag(env, "SUPERMGMT_NONINTERACTIVE") && isTerminal(cmd.InOrStdin())
			err = installer.New(deps(cmd, interactive)).Run(cmd.Context(), opts)
			return installFailure(cmd, err, installer.ExitCode(err))
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&f.nonInteractive, "non-interactive", false, "never prompt; fail instead of guessing (SUPERMGMT_NONINTERACTIVE)")
	fl.BoolVar(&f.yes, "yes", false, "do not ask for confirmation of the plan (SUPERMGMT_YES)")
	switch mode {
	case installer.ModeServer, installer.ModeRestore:
		fl.StringVar(&f.tls, "tls", string(config.TLSProxy), "TLS arrangement: proxy (behind a reverse proxy), direct, or self-signed (direct with a generated CA)")
		fl.StringVar(&f.tlsCert, "tls-cert", "", "certificate file for --tls direct")
		fl.StringVar(&f.tlsKey, "tls-key", "", "private key file for --tls direct")
		fl.StringSliceVar(&f.trustedProxies, "trusted-proxy", nil, "trusted proxy IP or CIDR for --tls proxy (default 127.0.0.1/32)")
		fl.StringVar(&f.listen, "listen", "", "listen address (default 127.0.0.1:8787 for proxy, 0.0.0.0:8443 for direct)")
		fl.StringVar(&f.publicURL, "public-url", "", "public https URL of the server")
		fl.StringVar(&f.name, "name", "", "instance name")
	case installer.ModeLocal:
		fl.BoolVar(&f.resident, "resident", false, "keep a resident daemon under the user service manager")
		fl.StringVar(&f.name, "name", "", "instance name")
	case installer.ModeUpgrade:
		fl.StringVar(&f.binary, "binary", "", "verified sm binary to install (default: the running sm)")
		fl.IntVar(&f.vmid, "vmid", 0, "on a Proxmox host: the appliance to upgrade (required when there are several)")
		fl.BoolVar(&f.allowDowngrade, "allow-downgrade", false, "allow installing a lower version (audited)")
	case installer.ModeUninstall:
		fl.IntVar(&f.vmid, "vmid", 0, "on a Proxmox host: the appliance to uninstall (required when there are several)")
		fl.BoolVar(&f.purgeData, "purge-data", false, "also delete data (asks for a typed confirmation; non-interactive needs SUPERMGMT_YES=1)")
	case installer.ModeClient, installer.ModeAuto, installer.ModeProxmoxLXC:
	}
	if mode == installer.ModeServer {
		fl.BoolVar(&f.noStart, "no-start", false, "write and load the service unit without enabling or starting it")
	}
	if mode == installer.ModeRestore {
		fl.StringVar(&f.archive, "archive", "", "backup archive to restore")
		fl.StringVar(&f.keyExport, "key-export", "", "exported key file to import (its unlock phrase is read from stdin or the terminal, never a flag)")
	}
	return cmd
}

func (f installFlags) options(mode installer.Mode, env []string, cmd *cobra.Command) (installer.Options, error) {
	exe, err := os.Executable()
	if err != nil {
		return installer.Options{}, fmt.Errorf("locate the running sm: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	values := envMap(env)
	appliance, err := applianceOptions(values)
	if err != nil {
		return installer.Options{}, err
	}
	tls, selfSigned := config.TLSMode(f.tls), false
	if f.tls == tlsSelfSigned {
		tls, selfSigned = config.TLSDirect, true
	}
	return installer.Options{
		Mode: mode, Binary: exe,
		TLS: tls, SelfSigned: selfSigned, CertFile: f.tlsCert, KeyFile: f.tlsKey, TrustedProxies: f.trustedProxies,
		Listen: f.listen, PublicURL: f.publicURL, InstanceName: f.name, Resident: f.resident,
		Yes:     f.yes || envFlag(env, "SUPERMGMT_YES"),
		Archive: f.archive, KeyExport: f.keyExport,
		InstallDir: values["SUPERMGMT_INSTALL_DIR"], ConfigDir: values["SUPERMGMT_CONFIG_DIR"], DataDir: values["SUPERMGMT_DATA_DIR"],
		Stdin:         cmd.InOrStdin(),
		NoStart:       f.noStart,
		Appliance:     appliance,
		UpgradeBinary: f.binary, AllowDowngrade: f.allowDowngrade, PurgeData: f.purgeData, VMID: f.vmid,
	}, nil
}

// tlsSelfSigned is the --tls value for direct TLS with a generated CA (ADR-0026).
const tlsSelfSigned = "self-signed"

// applianceOptions reads the proxmox-lxc variables of spec §3.6. Only their
// syntax is checked here; the installer validates them against the host.
func applianceOptions(values map[string]string) (installer.Appliance, error) {
	a := installer.Appliance{
		Hostname: values["SUPERMGMT_HOSTNAME"], Storage: values["SUPERMGMT_STORAGE"],
		TemplateStorage: values["SUPERMGMT_TEMPLATE_STORAGE"], Bridge: values["SUPERMGMT_BRIDGE"],
		Network: values["SUPERMGMT_NETWORK"], IP: values["SUPERMGMT_IP"], Gateway: values["SUPERMGMT_GATEWAY"],
		DNS: values["SUPERMGMT_DNS"], Power: values["SUPERMGMT_PVE_POWER"] != "0",
		PVEEndpoint: values["SUPERMGMT_PVE_ENDPOINT"], PVECAFile: values["SUPERMGMT_PVE_CA_FILE"],
	}
	for name, dst := range map[string]*int{
		"SUPERMGMT_VMID": &a.VMID, "SUPERMGMT_CORES": &a.Cores, "SUPERMGMT_MEMORY": &a.MemoryMiB,
		"SUPERMGMT_SWAP": &a.SwapMiB, "SUPERMGMT_DISK_GIB": &a.DiskGiB,
	} {
		raw := values[name]
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return installer.Appliance{}, usageErrorf("%s must be a non-negative integer, got %q", name, raw)
		}
		*dst = n
	}
	return a, nil
}

// installFailure prints the failure and carries its §3.7 exit code; nil stays nil.
func installFailure(cmd *cobra.Command, err error, code int) error {
	if err == nil {
		return nil
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error: %v\n", err)
	return &childExitError{code: code}
}

func envFlag(env []string, name string) bool {
	v := envMap(env)[name]
	return v != "" && v != "0"
}
