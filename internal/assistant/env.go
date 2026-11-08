package assistant

import (
	"sort"
	"strings"
)

// childEnvNames are the only variables the child inherits (spec: allowlist,
// not denylist). HOME, USER and LOGNAME let `claude` find its own sign-in
// (the macOS keychain lookup fails without USER or LOGNAME); the rest is
// locale, temp, proxy and XDG layout.
var childEnvNames = map[string]bool{
	"HOME": true, "USER": true, "LOGNAME": true, "PATH": true, "TMPDIR": true,
	"TERM": true, "LANG": true, "TZ": true,
	"XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true, "XDG_STATE_HOME": true, "XDG_CACHE_HOME": true, "XDG_RUNTIME_DIR": true,
	"CLAUDE_CONFIG_DIR": true,
	"HTTP_PROXY":        true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true,
}

const apiKeyVar = "ANTHROPIC_API_KEY" //nolint:gosec // the variable name, not a credential

// childEnv filters the operator's environment. The API key passes only in
// AuthAPIKey mode; without it that mode refuses.
func childEnv(auth Auth, environ []string) ([]string, error) {
	kept := map[string]string{}
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if childEnvNames[name] || strings.HasPrefix(name, "LC_") || (auth == AuthAPIKey && name == apiKeyVar) {
			kept[name] = value
		}
	}
	if auth == AuthAPIKey && kept[apiKeyVar] == "" {
		return nil, ErrNoAPIKey
	}
	out := make([]string, 0, len(kept))
	for name, value := range kept {
		out = append(out, name+"="+value)
	}
	sort.Strings(out)
	return out, nil
}
