// Package config defines the SuperMgmt master configuration (spec §8): the
// typed schema, strict decoding, defaults, environment overrides and
// validation. It performs no I/O beyond reading the config file in Load.
package config

//go:generate go run ./gen -out ../../docs/configuration.md

import "time"

// Mode is the instance mode (spec §2).
type Mode string

const (
	ModeLocal  Mode = "local"
	ModeServer Mode = "server"
)

// TLSMode says who terminates TLS in server mode (spec §23.1).
type TLSMode string

const (
	TLSDirect TLSMode = "direct"
	TLSProxy  TLSMode = "proxy"
)

// Config is the whole master configuration (spec §8.2).
type Config struct {
	Version      int           `yaml:"version"`
	Instance     Instance      `yaml:"instance"`
	Server       Server        `yaml:"server"`
	Daemon       Daemon        `yaml:"daemon"`
	UI           UI            `yaml:"ui"`
	Refresh      Refresh       `yaml:"refresh"`
	Storage      Storage       `yaml:"storage"`
	Security     Security      `yaml:"security"`
	Auth         Auth          `yaml:"auth"`
	SSH          SSH           `yaml:"ssh"`
	Jobs         Jobs          `yaml:"jobs"`
	Health       Health        `yaml:"health"`
	Outbound     Outbound      `yaml:"outbound"`
	GitHub       GitHub        `yaml:"github"`
	MCP          MCP           `yaml:"mcp"`
	Environments []Environment `yaml:"environments"`
	Providers    []Provider    `yaml:"providers"`
	Backup       Backup        `yaml:"backup"`
}

type Instance struct {
	Name    string `yaml:"name"`
	Mode    Mode   `yaml:"mode"`
	DataDir string `yaml:"data_dir"`
}

type Server struct {
	Listen          string        `yaml:"listen"`
	PublicURL       string        `yaml:"public_url"`
	TLS             TLS           `yaml:"tls"`
	TrustedProxies  []string      `yaml:"trusted_proxies"`
	AdminSocket     string        `yaml:"admin_socket"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

type TLS struct {
	Mode     TLSMode `yaml:"mode"`
	CertFile string  `yaml:"cert_file"`
	KeyFile  string  `yaml:"key_file"`
}

type Daemon struct {
	Socket   string        `yaml:"socket"`
	IdleExit time.Duration `yaml:"idle_exit"`
	Resident bool          `yaml:"resident"`
}

type UI struct {
	Theme string `yaml:"theme"`
}

type Refresh struct {
	FocusedInterval   time.Duration `yaml:"focused_interval"`
	InventoryInterval time.Duration `yaml:"inventory_interval"`
	MetricsInterval   time.Duration `yaml:"metrics_interval"`
	DiscoveryInterval time.Duration `yaml:"discovery_interval"`
}

type Storage struct {
	SQLite SQLite `yaml:"sqlite"`
}

type SQLite struct {
	Path        string        `yaml:"path"`
	BusyTimeout time.Duration `yaml:"busy_timeout"`
	WAL         bool          `yaml:"wal"`
}

type Security struct {
	KeysDir     string        `yaml:"keys_dir"`
	PolicyFile  string        `yaml:"policy_file"`
	SessionTTL  time.Duration `yaml:"session_ttl"`
	ApprovalTTL time.Duration `yaml:"approval_ttl"`
	// AllowSelfApproval is tri-state in the file; Load resolves it from the
	// mode (spec §11.4), so it is never nil in a loaded Config.
	AllowSelfApproval   *bool `yaml:"allow_self_approval"`
	RedactCommandOutput bool  `yaml:"redact_command_output"`
}

type Auth struct {
	Bootstrap Bootstrap `yaml:"bootstrap"`
	OIDC      OIDC      `yaml:"oidc"`
}

type Bootstrap struct {
	CodeTTL time.Duration `yaml:"code_ttl"`
}

type OIDC struct {
	Enabled         bool     `yaml:"enabled"`
	Issuer          string   `yaml:"issuer"`
	ClientID        string   `yaml:"client_id"`
	ClientSecretRef string   `yaml:"client_secret_ref"`
	RedirectURL     string   `yaml:"redirect_url"`
	AllowedDomains  []string `yaml:"allowed_domains"`
	// AllowedEndpointOrigins lists extra https origins the discovery document
	// may point to (token, device, JWKS endpoints). Empty: issuer origin only.
	AllowedEndpointOrigins []string `yaml:"allowed_endpoint_origins"`
}

type SSH struct {
	ConnectTimeout           time.Duration `yaml:"connect_timeout"`
	CommandTimeout           time.Duration `yaml:"command_timeout"`
	KeepaliveInterval        time.Duration `yaml:"keepalive_interval"`
	MaxDialsInFlight         int           `yaml:"max_dials_in_flight"`
	MaxConnections           int           `yaml:"max_connections"`
	MaxSessionsPerConnection int           `yaml:"max_sessions_per_connection"`
	IdleConnectionTTL        time.Duration `yaml:"idle_connection_ttl"`
	KnownHostsFile           string        `yaml:"known_hosts_file"`
	HostKeyPolicy            string        `yaml:"host_key_policy"`
	LogsMode                 string        `yaml:"logs_mode"`
}

type Jobs struct {
	Workers        int           `yaml:"workers"`
	Lease          time.Duration `yaml:"lease"`
	Heartbeat      time.Duration `yaml:"heartbeat"`
	ReconcileGrace time.Duration `yaml:"reconcile_grace"`
	RetryBase      time.Duration `yaml:"retry_base"`
}

type Health struct {
	AllowedPrivateCIDRs []string `yaml:"allowed_private_cidrs"`
}

type Outbound struct {
	Proxy string `yaml:"proxy"`
}

type GitHub struct {
	OIDCAudience  string        `yaml:"oidc_audience"`
	CIPollInitial time.Duration `yaml:"ci_poll_initial"`
	CIPollMax     time.Duration `yaml:"ci_poll_max"`
	CITimeout     time.Duration `yaml:"ci_timeout"`
}

type MCP struct {
	Enabled              bool     `yaml:"enabled"`
	RemoteEnabled        bool     `yaml:"remote_enabled"`
	OAuth                MCPOAuth `yaml:"oauth"`
	AllowInteractiveExec bool     `yaml:"allow_interactive_exec"`
	WriteToolsEnabled    bool     `yaml:"write_tools_enabled"`
}

type MCPOAuth struct {
	Issuer           string   `yaml:"issuer"`
	Resource         string   `yaml:"resource"`
	JWKSURL          string   `yaml:"jwks_url"`
	IntrospectionURL string   `yaml:"introspection_url"`
	RequiredScopes   []string `yaml:"required_scopes"`
}

type Backup struct {
	Schedule  string `yaml:"schedule"`
	Retention int    `yaml:"retention"`
	Directory string `yaml:"directory"`
}

// Defaults returns the configuration every key falls back to when absent
// (the values of the spec §8.2 example). Mode-dependent values are resolved
// later by Load.
func Defaults() Config {
	return Config{
		Version: 1,
		Server: Server{
			Listen:          "127.0.0.1:8787",
			TLS:             TLS{Mode: TLSProxy},
			TrustedProxies:  []string{"127.0.0.1/32"},
			AdminSocket:     "/run/supermgmt/admin.sock",
			RequestTimeout:  30 * time.Second,
			ShutdownTimeout: 20 * time.Second,
		},
		Daemon: Daemon{IdleExit: 10 * time.Minute},
		UI:     UI{Theme: "auto"},
		Refresh: Refresh{
			FocusedInterval:   5 * time.Second,
			InventoryInterval: 60 * time.Second,
			MetricsInterval:   30 * time.Second,
			DiscoveryInterval: 5 * time.Minute,
		},
		Storage: Storage{SQLite: SQLite{BusyTimeout: 5 * time.Second, WAL: true}},
		Security: Security{
			SessionTTL:          12 * time.Hour,
			ApprovalTTL:         15 * time.Minute,
			RedactCommandOutput: true,
		},
		Auth: Auth{Bootstrap: Bootstrap{CodeTTL: 24 * time.Hour}},
		SSH: SSH{
			ConnectTimeout:           8 * time.Second,
			CommandTimeout:           30 * time.Second,
			KeepaliveInterval:        30 * time.Second,
			MaxDialsInFlight:         16,
			MaxConnections:           512,
			MaxSessionsPerConnection: 4,
			IdleConnectionTTL:        10 * time.Minute,
			HostKeyPolicy:            "strict",
			LogsMode:                 "journal-group",
		},
		Jobs: Jobs{
			Workers:        4,
			Lease:          60 * time.Second,
			Heartbeat:      15 * time.Second,
			ReconcileGrace: 45 * time.Second,
			RetryBase:      2 * time.Second,
		},
		GitHub: GitHub{
			CIPollInitial: 15 * time.Second,
			CIPollMax:     2 * time.Minute,
			CITimeout:     2 * time.Hour,
		},
		MCP:    MCP{Enabled: true, OAuth: MCPOAuth{RequiredScopes: []string{"supermgmt:mcp"}}},
		Backup: Backup{Retention: 14},
	}
}
