package app

import (
	"regexp"
	"strings"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/runtimes"
)

// The configuration of an app is redacted for every reader, whatever security.redact_command_output says:
// it is what the runtime reports, and the runtime keeps secrets in it.

var urlUserinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)

// sensitiveFlagParts mark a command line flag whose next argument is a secret (--password hunter2).
var sensitiveFlagParts = []string{"password", "passwd", "secret", "token", "api-key", "apikey", "credential", "passphrase"}

func redactText(s string) string {
	return audit.ScrubCredentials(urlUserinfo.ReplaceAllString(s, "${1}"+audit.Redacted+"@"))
}

// redactedPair masks the value of key=value by its key and by what it contains. A Traefik basic auth list is
// a credential whatever its label is called.
func redactedPair(key, value string) string {
	if strings.Contains(strings.ToLower(key), "basicauth") {
		return key + "=" + audit.Redacted
	}
	return redactText(key + "=" + value)
}

func redactedEnv(env []string) []string {
	out := make([]string, len(env))
	for i, pair := range env {
		if key, value, ok := strings.Cut(pair, "="); ok {
			out[i] = redactedPair(key, value)
		} else {
			out[i] = redactText(pair)
		}
	}
	return out
}

func redactedLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		masked, ok := strings.CutPrefix(redactedPair(key, value), key+"=")
		if !ok {
			masked = audit.Redacted
		}
		out[key] = masked
	}
	return out
}

// redactedArgs scrubs each argument and masks the one that follows a flag naming a secret.
func redactedArgs(args []string) []string {
	out := make([]string, len(args))
	maskNext := false
	for i, arg := range args {
		switch {
		case maskNext:
			out[i], maskNext = audit.Redacted, false
		default:
			out[i] = redactText(arg)
			maskNext = sensitiveFlag(arg)
		}
	}
	return out
}

func sensitiveFlag(arg string) bool {
	if !strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
		return false
	}
	lower := strings.ToLower(arg)
	for _, part := range sensitiveFlagParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

func appConfigOf(d runtimes.ContainerDetail) *wire.AppConfig {
	return &wire.AppConfig{
		RestartPolicy: d.RestartPolicy,
		Env:           redactedEnv(d.Env),
		Command:       redactedArgs(d.Cmd),
		Entrypoint:    redactedArgs(d.Entrypoint),
		Labels:        redactedLabels(d.Labels),
	}
}
