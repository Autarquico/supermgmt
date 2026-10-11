package installer

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/config"
)

// serverUnitTemplate is the Appendix A unit; the placeholders are the only
// parts that follow the layout. A test pins it to packaging/systemd.
const serverUnitTemplate = `[Unit]
Description=SuperMgmt control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=supermgmt
Group=supermgmt
ExecStart=@BINARY@ server --config @CONFIG@
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=@DATA@
RuntimeDirectory=supermgmt
RuntimeDirectoryMode=0750
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
`

const userUnitTemplate = `[Unit]
Description=SuperMgmt local daemon

[Service]
Type=simple
ExecStart=@BINARY@ daemon --config @CONFIG@
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
`

const launchAgentTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>@LABEL@</string>
	<key>ProgramArguments</key>
	<array>
		<string>@BINARY@</string>
		<string>daemon</string>
		<string>--config</string>
		<string>@CONFIG@</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`

// LaunchdLabel names the macOS launch agent of the resident local daemon.
const LaunchdLabel = "dev.supermgmt.daemon"

func renderServerUnit(l layout) []byte { return fill(serverUnitTemplate, l, "") }

func renderUserUnit(l layout) []byte { return fill(userUnitTemplate, l, "") }

func renderLaunchAgent(l layout) []byte { return fill(launchAgentTemplate, l, LaunchdLabel) }

func fill(template string, l layout, label string) []byte {
	return []byte(strings.NewReplacer(
		"@BINARY@", l.Binary, "@CONFIG@", l.ConfigFile, "@DATA@", l.DataDir, "@LABEL@", label,
	).Replace(template))
}

type configDoc struct {
	Version  int         `yaml:"version"`
	Instance instanceDoc `yaml:"instance"`
	Server   *serverDoc  `yaml:"server,omitempty"`
	Daemon   *daemonDoc  `yaml:"daemon,omitempty"`
}

type instanceDoc struct {
	Name    string      `yaml:"name,omitempty"`
	Mode    config.Mode `yaml:"mode"`
	DataDir string      `yaml:"data_dir,omitempty"`
}

type serverDoc struct {
	Listen         string   `yaml:"listen"`
	PublicURL      string   `yaml:"public_url"`
	TLS            tlsDoc   `yaml:"tls"`
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
}

type tlsDoc struct {
	Mode     config.TLSMode `yaml:"mode"`
	CertFile string         `yaml:"cert_file,omitempty"`
	KeyFile  string         `yaml:"key_file,omitempty"`
}

type daemonDoc struct {
	Resident bool `yaml:"resident"`
}

// renderServerConfig writes only what the installer decided; the loader
// supplies every default. The result is validated by the real loader.
func renderServerConfig(l layout, s serverSettings) ([]byte, error) {
	doc := configDoc{
		Version:  1,
		Instance: instanceDoc{Name: s.Name, Mode: config.ModeServer, DataDir: l.DataDir},
		Server: &serverDoc{
			Listen: s.Listen, PublicURL: s.PublicURL,
			TLS:            tlsDoc{Mode: s.TLS, CertFile: s.CertFile, KeyFile: s.KeyFile},
			TrustedProxies: s.TrustedProxies,
		},
	}
	return marshalValidated(doc)
}

func renderLocalConfig(l layout, name string, resident bool) ([]byte, error) {
	doc := configDoc{
		Version:  1,
		Instance: instanceDoc{Name: name, Mode: config.ModeLocal, DataDir: l.DataDir},
	}
	if resident {
		doc.Daemon = &daemonDoc{Resident: true}
	}
	return marshalValidated(doc)
}

func marshalValidated(doc configDoc) ([]byte, error) {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, failWrap(ExitConfiguration, "render configuration", err)
	}
	if _, err := config.LoadBytes(data, nil); err != nil {
		return nil, failWrap(ExitInvalid, "configuration is invalid", err)
	}
	return data, nil
}

const emptyProfiles = "version: 1\ncurrent: \"\"\nprofiles: {}\n"

func describe(l layout) string {
	return fmt.Sprintf("binary %s, config %s, data %s", l.Binary, l.ConfigFile, l.DataDir)
}
