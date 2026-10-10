package config

import "path/filepath"

// Paths are the well-known filesystem locations of one instance (spec §8.1, §2.1.1).
type Paths struct {
	Config   string
	DataDir  string
	DB       string
	StateDir string
	Socket   string
}

// ServerPaths are the fixed Linux server locations (spec §8.1).
func ServerPaths() Paths {
	return Paths{
		Config:   "/etc/supermgmt/config.yaml",
		DataDir:  "/var/lib/supermgmt",
		DB:       "/var/lib/supermgmt/supermgmt.db",
		StateDir: "/var/lib/supermgmt",
		Socket:   "/run/supermgmt/admin.sock",
	}
}

// Resolve computes the local-user paths for goos ("darwin"; anything else
// follows the XDG layout). env holds XDG_CONFIG_HOME, XDG_DATA_HOME,
// XDG_STATE_HOME and XDG_RUNTIME_DIR; per the XDG specification an empty or
// relative value counts as unset. Resolve performs no I/O.
func Resolve(goos string, env map[string]string, home string) Paths {
	darwin := goos == "darwin"
	appSupport := filepath.Join(home, "Library", "Application Support", "SuperMgmt")
	fallback := func(linux, mac string) string {
		if darwin {
			return mac
		}
		return filepath.Join(home, linux, "supermgmt")
	}

	configDir := appDir(env, "XDG_CONFIG_HOME", fallback(".config", appSupport))
	dataDir := appDir(env, "XDG_DATA_HOME", fallback(".local/share", appSupport))
	stateDir := appDir(env, "XDG_STATE_HOME", fallback(".local/state", filepath.Join(appSupport, "state")))

	p := Paths{
		Config:   filepath.Join(configDir, "config.yaml"),
		DataDir:  dataDir,
		DB:       filepath.Join(dataDir, "supermgmt.db"),
		StateDir: stateDir,
		Socket:   filepath.Join(stateDir, "run", "sm.sock"),
	}
	if runtimeDir := xdgDir(env, "XDG_RUNTIME_DIR"); runtimeDir != "" && !darwin {
		p.Socket = filepath.Join(runtimeDir, "supermgmt", "sm.sock")
	}
	return p
}

// appDir is <XDG var>/supermgmt when the variable is set, else fallback.
func appDir(env map[string]string, name, fallback string) string {
	if dir := xdgDir(env, name); dir != "" {
		return filepath.Join(dir, "supermgmt")
	}
	return fallback
}

func xdgDir(env map[string]string, name string) string {
	if dir := env[name]; filepath.IsAbs(dir) {
		return dir
	}
	return ""
}
