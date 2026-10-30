// Package version exposes build identity, injected at link time.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Set via -ldflags "-X github.com/autarquico/supermgmt/internal/version.Version=...".
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

const unknown = "unknown"

// Build describes the running binary.
type Build struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
	Platform  string
}

// Info returns the build identity, falling back to VCS data embedded by the
// Go toolchain when the linker flags were not provided.
func Info() Build {
	bi, _ := debug.ReadBuildInfo()
	return resolve(Version, Commit, Date, bi)
}

func resolve(version, commit, date string, bi *debug.BuildInfo) Build {
	if bi != nil {
		if commit == unknown {
			commit = setting(bi, "vcs.revision", commit)
		}
		if date == unknown {
			date = setting(bi, "vcs.time", date)
		}
	}
	return Build{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func setting(bi *debug.BuildInfo, key, fallback string) string {
	for _, s := range bi.Settings {
		if s.Key == key && s.Value != "" {
			return s.Value
		}
	}
	return fallback
}

// Channel is the release channel the running binary was published on, as the join line names it:
// "beta" for a pre-release version such as 0.1.0-rc.3, "" (stable) for a release or an unversioned build.
func Channel() string { return channelOf(Version) }

func channelOf(v string) string {
	v = strings.TrimPrefix(v, "v")
	core, _, _ := strings.Cut(v, "+")
	if core == "" || core[0] < '0' || core[0] > '9' || !strings.Contains(core, "-") {
		return ""
	}
	return "beta"
}
