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

var urlUserinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]*:[^/\s@]+@`)

// sensitiveFlagParts mark a command line flag whose next argument is a secret (--password hunter2).
var sensitiveFlagParts = []string{"password", "passwd", "secret", "token", "api-key", "apikey", "credential", "passphrase"}

func redactText(s string) string {
	return audit.ScrubCredentials(urlUserinfo.ReplaceAllString(s, "${1}"+audit.Redacted+"@"))
}

// sensitiveKey asks the rule RedactMap applies to the keys of events, so the two cannot drift apart.
func sensitiveKey(key string) bool {
	return audit.RedactMap(map[string]any{key: "x"})[key] == audit.Redacted
}

// redactedPair masks the value of key=value by its key, whole, and by what it contains. A Traefik basic auth
// list is a credential whatever its label is called.
func redactedPair(key, value string) string {
	if strings.Contains(strings.ToLower(key), "basicauth") || sensitiveKey(key) {
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

// redactedArgs scrubs each argument and masks the one that follows a flag naming a secret, and the value of
// --flag=value and KEY=value arguments whose name does.
func redactedArgs(args []string) []string {
	out := make([]string, len(args))
	maskNext := false
	for i, arg := range args {
		switch name, _, assigned := strings.Cut(arg, "="); {
		case maskNext:
			out[i], maskNext = audit.Redacted, false
		case assigned && sensitiveName(name):
			out[i] = name + "=" + audit.Redacted
		default:
			out[i] = redactText(arg)
			maskNext = !assigned && strings.HasPrefix(arg, "-") && sensitiveFlagName(arg)
		}
	}
	return out
}

func sensitiveName(name string) bool {
	return sensitiveKey(strings.TrimLeft(name, "-")) || sensitiveFlagName(name)
}

func sensitiveFlagName(flag string) bool {
	lower := strings.ToLower(flag)
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
