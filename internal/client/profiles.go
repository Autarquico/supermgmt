package client

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ProfilesFileName is the profiles file inside the configuration directory
// (spec Appendix B). It holds no secret: tokens live in the credential store.
const ProfilesFileName = "profiles.yaml"

const (
	profilesVersion  = 1
	maxProfilesBytes = 1 << 20
)

// ProfileType says what a profile points at.
type ProfileType string

const (
	ProfileRemote ProfileType = "remote"
	ProfileLocal  ProfileType = "local"
)

// Auth methods recorded in a remote profile.
const (
	AuthOIDC  = "oidc"
	AuthToken = "token"
)

var profileName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Profile is one place sm can talk to.
type Profile struct {
	Type   ProfileType `yaml:"type"`
	URL    string      `yaml:"url,omitempty"`
	Auth   string      `yaml:"auth,omitempty"`
	CAFile string      `yaml:"ca_file,omitempty"`
	Config string      `yaml:"config,omitempty"`
}

// Profiles is the content of profiles.yaml.
type Profiles struct {
	Version  int                `yaml:"version"`
	Current  string             `yaml:"current"`
	Profiles map[string]Profile `yaml:"profiles"`
}

// LoadProfiles reads the profiles file. A missing file is an empty set, so a
// fresh machine needs no setup.
func LoadProfiles(path string) (*Profiles, error) {
	f, err := os.Open(path) //nolint:gosec // the user's own configuration directory
	if errors.Is(err, fs.ErrNotExist) {
		return &Profiles{Version: profilesVersion, Profiles: map[string]Profile{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open profiles: %w", err)
	}
	defer func() { _ = f.Close() }()
	var p Profiles
	decoder := yaml.NewDecoder(io.LimitReader(f, maxProfilesBytes))
	decoder.KnownFields(true) // a stray key (a pasted token, say) is an error, not silently ignored
	if err := decoder.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return &Profiles{Version: profilesVersion, Profiles: map[string]Profile{}}, nil
		}
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("profiles file %s is invalid: %v", path, err))
	}
	if err := p.validate(); err != nil {
		return nil, smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf("profiles file %s is invalid: %v", path, err))
	}
	return &p, nil
}

func (p *Profiles) validate() error {
	if p.Version != profilesVersion {
		return fmt.Errorf("version %d is not supported (want %d)", p.Version, profilesVersion)
	}
	if p.Profiles == nil {
		p.Profiles = map[string]Profile{}
	}
	for name, profile := range p.Profiles {
		if err := ValidateProfile(name, profile); err != nil {
			return err
		}
	}
	if p.Current != "" {
		if _, ok := p.Profiles[p.Current]; !ok {
			return fmt.Errorf("current profile %q does not exist", p.Current)
		}
	}
	return nil
}

// ValidateProfile checks one profile without touching the network.
func ValidateProfile(name string, p Profile) error {
	if !profileName.MatchString(name) {
		return fmt.Errorf("profile name %q must be lowercase letters, digits, dot, dash or underscore", name)
	}
	switch p.Type {
	case ProfileRemote:
		if _, err := ValidateServerURL(p.URL); err != nil {
			return fmt.Errorf("profile %s: %w", name, err)
		}
		if p.CAFile != "" && !filepath.IsAbs(p.CAFile) {
			return fmt.Errorf("profile %s: ca_file must be an absolute path", name)
		}
		if p.Auth != "" && p.Auth != AuthOIDC && p.Auth != AuthToken {
			return fmt.Errorf("profile %s: auth must be %s or %s", name, AuthOIDC, AuthToken)
		}
	case ProfileLocal:
		if p.URL != "" || p.CAFile != "" {
			return fmt.Errorf("profile %s: a local profile has no url or ca_file", name)
		}
	default:
		return fmt.Errorf("profile %s: type must be %s or %s", name, ProfileRemote, ProfileLocal)
	}
	return nil
}

// Names lists the profiles alphabetically.
func (p *Profiles) Names() []string {
	names := make([]string, 0, len(p.Profiles))
	for name := range p.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Active is the current profile, if one is selected.
func (p *Profiles) Active() (string, Profile, bool) {
	profile, ok := p.Profiles[p.Current]
	return p.Current, profile, ok && p.Current != ""
}

// Add records a new profile; the first one becomes current. An existing name
// is a conflict: replacing a profile silently would orphan its token.
func (p *Profiles) Add(name string, profile Profile) error {
	if err := ValidateProfile(name, profile); err != nil {
		return smerr.New(smerr.CodeInvalidArgument, "", err.Error())
	}
	if _, exists := p.Profiles[name]; exists {
		return smerr.New(smerr.CodeConflict, "", fmt.Sprintf("profile %q already exists: remove it first", name))
	}
	if p.Profiles == nil {
		p.Profiles = map[string]Profile{}
	}
	p.Profiles[name] = profile
	if p.Current == "" {
		p.Current = name
	}
	return nil
}

// Use selects the current profile.
func (p *Profiles) Use(name string) error {
	if _, ok := p.Profiles[name]; !ok {
		return smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no profile named %q", name))
	}
	p.Current = name
	return nil
}

// Remove deletes a profile; when it was current, none is.
func (p *Profiles) Remove(name string) error {
	if _, ok := p.Profiles[name]; !ok {
		return smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no profile named %q", name))
	}
	delete(p.Profiles, name)
	if p.Current == name {
		p.Current = ""
	}
	return nil
}

// Set replaces the content of an existing profile (login records its method).
func (p *Profiles) Set(name string, profile Profile) error {
	if _, ok := p.Profiles[name]; !ok {
		return smerr.New(smerr.CodeNotFound, "", fmt.Sprintf("no profile named %q", name))
	}
	if err := ValidateProfile(name, profile); err != nil {
		return smerr.New(smerr.CodeInvalidArgument, "", err.Error())
	}
	p.Profiles[name] = profile
	return nil
}

// SaveProfiles writes the file owner-only, atomically: a crash leaves the old
// file or the new one.
func SaveProfiles(path string, p *Profiles) error {
	p.Version = profilesVersion
	if p.Profiles == nil {
		p.Profiles = map[string]Profile{}
	}
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode profiles: %w", err)
	}
	return writeFileAtomic(path, data)
}

// writeFileAtomic writes data to path with mode 0600 through a temporary file
// in the same directory, creating the directory 0700 when it is missing.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("restrict temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// Describe is a one-line summary of a profile for listings.
func (p Profile) Describe() string {
	switch p.Type {
	case ProfileLocal:
		if p.Config == "" {
			return "local daemon"
		}
		return "local daemon, config " + p.Config
	case ProfileRemote:
		parts := []string{p.URL}
		if p.CAFile != "" {
			parts = append(parts, "ca "+p.CAFile)
		}
		return strings.Join(parts, ", ")
	}
	return string(p.Type)
}
