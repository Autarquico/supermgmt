package client_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/client"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const installerProfiles = "version: 1\ncurrent: \"\"\nprofiles: {}\n"

func profilesPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "config", client.ProfilesFileName)
}

func TestMissingAndInstallerEmptyProfilesAreEmptySets(t *testing.T) {
	path := profilesPath(t)
	missing, err := client.LoadProfiles(path)
	if err != nil || len(missing.Profiles) != 0 || missing.Current != "" {
		t.Fatalf("missing: %+v, %v", missing, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(installerProfiles), 0o600); err != nil {
		t.Fatal(err)
	}
	empty, err := client.LoadProfiles(path)
	if err != nil || len(empty.Profiles) != 0 {
		t.Fatalf("installer file: %+v, %v", empty, err)
	}
}

func TestSavedProfilesAreOwnerOnlyAndSurviveAReload(t *testing.T) {
	path := profilesPath(t)
	p, _ := client.LoadProfiles(path)
	remote := client.Profile{Type: client.ProfileRemote, URL: "https://mgmt.example.com", Auth: client.AuthOIDC, CAFile: "/etc/ssl/private-ca.pem"}
	if err := p.Add("home", remote); err != nil {
		t.Fatal(err)
	}
	if err := p.Add("laptop", client.Profile{Type: client.ProfileLocal, Config: "/home/a/config.yaml"}); err != nil {
		t.Fatal(err)
	}

	if err := client.SaveProfiles(path, p); err != nil {
		t.Fatal(err)
	}

	assertMode(t, path, 0o600)
	assertMode(t, filepath.Dir(path), 0o700)
	again, err := client.LoadProfiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Profiles["home"]; got != remote || again.Current != "home" || len(again.Names()) != 2 {
		t.Errorf("reloaded %+v (current %q)", again, again.Current)
	}
}

func TestSavingProfilesLeavesAnExistingFileOwnerOnly(t *testing.T) {
	path := profilesPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(installerProfiles), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _ := client.LoadProfiles(path)

	if err := client.SaveProfiles(path, p); err != nil {
		t.Fatal(err)
	}

	assertMode(t, path, 0o600)
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files were left behind: %v", entries)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %04o, want %04o", path, got, want)
	}
}

func TestProfileOperations(t *testing.T) {
	p, _ := client.LoadProfiles(profilesPath(t))
	home := client.Profile{Type: client.ProfileRemote, URL: "https://home.example.com"}
	work := client.Profile{Type: client.ProfileRemote, URL: "https://work.example.com"}

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(p.Add("home", home))
	must(p.Add("work", work))
	if p.Current != "home" {
		t.Errorf("the first profile must become current, got %q", p.Current)
	}
	if err := p.Add("home", work); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("duplicate add: %v", err)
	}
	must(p.Use("work"))
	if name, profile, ok := p.Active(); !ok || name != "work" || profile != work {
		t.Errorf("Active = %q %+v %v", name, profile, ok)
	}
	if err := p.Use("absent"); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("use unknown: %v", err)
	}
	must(p.Remove("work"))
	if _, _, ok := p.Active(); ok || p.Current != "" {
		t.Errorf("removing the current profile must leave none current, got %q", p.Current)
	}
	if err := p.Remove("work"); smerr.CodeOf(err) != smerr.CodeNotFound {
		t.Errorf("remove twice: %v", err)
	}
}

func TestInvalidProfilesAreRefused(t *testing.T) {
	tests := map[string]client.Profile{
		"http url":         {Type: client.ProfileRemote, URL: "http://mgmt.example.com"},
		"no url":           {Type: client.ProfileRemote},
		"relative ca":      {Type: client.ProfileRemote, URL: "https://m.example.com", CAFile: "ca.pem"},
		"unknown auth":     {Type: client.ProfileRemote, URL: "https://m.example.com", Auth: "password"},
		"local with a url": {Type: client.ProfileLocal, URL: "https://m.example.com"},
		"unknown type":     {Type: "ssh"},
	}
	for name, profile := range tests {
		p, _ := client.LoadProfiles(profilesPath(t))
		if err := p.Add("p", profile); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: err = %v, want INVALID_ARGUMENT", name, err)
		}
	}
	for _, name := range []string{"", "Home", "-x", "a b", "a/b", strings.Repeat("a", 64)} {
		p, _ := client.LoadProfiles(profilesPath(t))
		if err := p.Add(name, client.Profile{Type: client.ProfileLocal}); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("name %q: err = %v, want INVALID_ARGUMENT", name, err)
		}
	}
}

func TestACorruptProfilesFileIsAnErrorNotAnEmptySet(t *testing.T) {
	bad := map[string]string{
		"unknown key":     "version: 1\ncurrent: \"\"\nprofiles: {}\ntoken: abc\n",
		"wrong version":   "version: 9\ncurrent: \"\"\nprofiles: {}\n",
		"dangling":        "version: 1\ncurrent: ghost\nprofiles: {}\n",
		"a token in file": "version: 1\ncurrent: h\nprofiles:\n  h:\n    type: remote\n    url: https://m.example.com\n    token: smt_leak\n",
		"not yaml":        "[: nope",
	}
	for name, content := range bad {
		path := profilesPath(t)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := client.LoadProfiles(path); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
			t.Errorf("%s: err = %v, want INVALID_ARGUMENT", name, err)
		}
	}
}
