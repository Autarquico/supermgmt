package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Result is a loaded, validated configuration plus non-fatal findings.
type Result struct {
	Config *Config
	// Warnings lists SUPERMGMT_* variables that are neither configuration
	// overrides nor installer variables; doctor prints them.
	Warnings []string
}

// Load reads and validates the config file at path. env is the process
// environment ("KEY=value" entries): SUPERMGMT_ variables override file
// values, HOME and XDG_* locate local-mode default paths.
//
// Order: defaults, file, environment overrides, mode-dependent defaults,
// validation. Environment overrides come before mode defaults so that
// SUPERMGMT_INSTANCE_MODE selects the right defaults.
func Load(path string, env []string) (Result, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		code := smerr.CodeInvalidArgument
		if errors.Is(err, fs.ErrNotExist) {
			code = smerr.CodeNotFound
		}
		return Result{}, smerr.Wrap(err, code, "", "cannot open configuration file")
	}
	defer func() { _ = f.Close() }()

	cfg := Defaults()
	if err := DecodeStrict(f, &cfg); err != nil {
		return Result{}, fmt.Errorf("%s: %w", path, err)
	}
	unknown, err := applyEnv(&cfg, env)
	if err != nil {
		return Result{}, err
	}
	cfg.applyModeDefaults(localPaths(env))
	if err := cfg.Validate(); err != nil {
		return Result{}, fmt.Errorf("%s: %w", path, err)
	}
	return Result{Config: &cfg, Warnings: unknownWarnings(unknown)}, nil
}

func localPaths(env []string) Paths {
	values := parseEnv(env)
	return Resolve(runtime.GOOS, values, values["HOME"])
}

func unknownWarnings(names []string) []string {
	warnings := make([]string, len(names))
	for i, name := range names {
		warnings[i] = fmt.Sprintf("unknown environment variable %s ignored", name)
	}
	return warnings
}

// applyModeDefaults fills what depends on instance.mode or on other keys.
// local holds the user paths used when mode is not server.
func (c *Config) applyModeDefaults(local Paths) {
	base := local
	if c.Instance.Mode == ModeServer {
		base = ServerPaths()
	}
	setDefault(&c.Instance.DataDir, base.DataDir)
	setDefault(&c.Storage.SQLite.Path, filepath.Join(c.Instance.DataDir, "supermgmt.db"))
	setDefault(&c.Security.KeysDir, filepath.Join(c.Instance.DataDir, "secrets", "keys"))
	setDefault(&c.SSH.KnownHostsFile, filepath.Join(c.Instance.DataDir, "known_hosts"))
	setDefault(&c.Backup.Directory, filepath.Join(c.Instance.DataDir, "backups"))
	setDefault(&c.GitHub.OIDCAudience, c.Server.PublicURL)
	if c.Instance.Mode == ModeServer {
		setDefault(&c.Backup.Schedule, "0 3 * * *")
	}
	if c.Security.AllowSelfApproval == nil {
		allow := c.Instance.Mode != ModeServer
		c.Security.AllowSelfApproval = &allow
	}
}

func setDefault(field *string, value string) {
	if *field == "" {
		*field = value
	}
}
