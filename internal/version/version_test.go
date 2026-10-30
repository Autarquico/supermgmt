package version

import (
	"runtime"
	"runtime/debug"
	"testing"
)

func TestResolve(t *testing.T) {
	vcs := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "abc123"},
		{Key: "vcs.time", Value: "2026-01-02T03:04:05Z"},
	}}
	tests := []struct {
		name       string
		commit     string
		date       string
		bi         *debug.BuildInfo
		wantCommit string
		wantDate   string
	}{
		{"ldflags win over vcs", "ldcommit", "ldDate", vcs, "ldcommit", "ldDate"},
		{"vcs fills defaults", unknown, unknown, vcs, "abc123", "2026-01-02T03:04:05Z"},
		{"no build info keeps defaults", unknown, unknown, nil, unknown, unknown},
		{"missing vcs keys keep defaults", unknown, unknown, &debug.BuildInfo{}, unknown, unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolve("v1", tt.commit, tt.date, tt.bi)
			if got.Version != "v1" || got.Commit != tt.wantCommit || got.Date != tt.wantDate {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestInfoReportsRuntime(t *testing.T) {
	got := Info()
	if got.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q", got.GoVersion)
	}
	if want := runtime.GOOS + "/" + runtime.GOARCH; got.Platform != want {
		t.Errorf("Platform = %q, want %q", got.Platform, want)
	}
	if got.Version == "" {
		t.Error("Version empty")
	}
}

func TestChannelOf(t *testing.T) {
	for v, want := range map[string]string{
		"0.1.0-rc.3": "beta", "v0.1.0-rc.3": "beta", "1.2.3-beta.1+abc": "beta",
		"0.1.0": "", "v1.2.3": "", "1.2.3+build-5": "", "dev": "", "": "", "dev-abc": "",
	} {
		if got := channelOf(v); got != want {
			t.Errorf("channelOf(%q) = %q, want %q", v, got, want)
		}
	}
}
