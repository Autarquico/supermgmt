package cli

import (
	"os"
	"runtime"
	"strings"

	"github.com/autarquico/supermgmt/internal/config"
)

func envMap(env []string) map[string]string {
	values := make(map[string]string, len(env))
	for _, kv := range env {
		if name, value, ok := strings.Cut(kv, "="); ok {
			values[name] = value
		}
	}
	return values
}

// localPaths are the local-mode default paths for the given environment.
func localPaths(env []string) config.Paths {
	values := envMap(env)
	return config.Resolve(runtime.GOOS, values, values["HOME"])
}

// configPath is the --config value, else the local default location, else
// the server location when only that one exists.
func configPath(flagValue string, env []string) string {
	if flagValue != "" {
		return flagValue
	}
	local := localPaths(env).Config
	if fileExists(local) {
		return local
	}
	if server := config.ServerPaths().Config; fileExists(server) {
		return server
	}
	return local
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
