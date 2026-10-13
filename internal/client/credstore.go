package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrNoCredential means no token is stored for the profile.
var ErrNoCredential = errors.New("no stored credential")

const (
	credentialService  = "supermgmt"
	credentialsFile    = "credentials.json"
	credentialsVersion = 1
	storeCommandWait   = 15 * time.Second

	locationKeychain     = "the macOS keychain"
	locationSecretTool   = "the desktop secret service (secret-tool)"
	locationFileTemplate = "%s (mode 0600; no OS credential store was usable)"
)

// CredentialStore keeps the bearer token of each profile (spec Appendix B,
// user decision Q7). A token is a secret: it is handed to the OS tools on
// their standard input, never in an argument or an environment variable.
type CredentialStore interface {
	Get(ctx context.Context, profile string) (string, error)
	// Set stores token and says where it ended up, for the user to read.
	Set(ctx context.Context, profile, token string) (location string, err error)
	Delete(ctx context.Context, profile string) error
}

// safeToken is the alphabet of every token SuperMgmt issues (sm<k>_<base64url>).
// The OS tools get tokens through a line of text, so anything else is refused
// instead of quoted.
var safeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{8,512}$`)

// runner runs an OS tool with stdin and returns its standard output.
type runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)

// OpenCredentialStore picks the strongest store this machine has: the macOS
// keychain (`security`) or the Secret Service (`secret-tool`) when the tool is
// on the PATH of env, with a mode-0600 file in configDir as the fallback for
// a headless host.
func OpenCredentialStore(goos string, env []string, configDir string) CredentialStore {
	file := &fileStore{path: filepath.Join(configDir, credentialsFile)}
	native, _ := OpenNativeCredentialStore(goos, env)
	return &chainStore{native: native, file: file}
}

// OpenNativeCredentialStore returns the OS store alone, with no file fallback,
// and false when this machine has none. It is for a secret that must not land
// in a plain file by accident (an MCP client's one-time token, ADR-0032).
func OpenNativeCredentialStore(goos string, env []string) (CredentialStore, bool) {
	switch goos {
	case "darwin":
		if tool, ok := LookPath(env, "security"); ok {
			return &keychainStore{tool: tool, run: execRunner(env)}, true
		}
	case "linux":
		if tool, ok := LookPath(env, "secret-tool"); ok {
			return &secretToolStore{tool: tool, run: execRunner(env)}, true
		}
	}
	return nil, false
}

// LookPath finds an executable on the PATH given in env (not the process's).
func LookPath(env []string, name string) (string, bool) {
	for _, kv := range env {
		path, ok := strings.CutPrefix(kv, "PATH=")
		if !ok {
			continue
		}
		for _, dir := range filepath.SplitList(path) {
			if dir == "" || !filepath.IsAbs(dir) {
				continue
			}
			candidate := filepath.Join(dir, name)
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				return candidate, true
			}
		}
	}
	return "", false
}

func execRunner(env []string) runner {
	return func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, storeCommandWait)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // a fixed credential tool found on PATH, fixed arguments
		cmd.Env = env
		cmd.Stdin = bytes.NewReader(stdin)
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(name), err) // never the output: it may echo the secret
		}
		return stdout.Bytes(), nil
	}
}

// ---- macOS keychain -----------------------------------------------------------

type keychainStore struct {
	tool string
	run  runner
}

// Set feeds `security -i` the add command on stdin, so the token is not in
// any argument list. Interactive mode reports a failure on its output but
// not always in its exit status, so the stored value is read back.
func (k *keychainStore) Set(ctx context.Context, profile, token string) (string, error) {
	if !safeToken.MatchString(token) {
		return "", errors.New("the token has an unexpected shape")
	}
	command := fmt.Sprintf("add-generic-password -U -s %q -a %q -w %q\n", credentialService, profile, token)
	if _, err := k.run(ctx, []byte(command), k.tool, "-i"); err != nil {
		return "", err
	}
	stored, err := k.Get(ctx, profile)
	if err != nil || stored != token {
		return "", errors.New("the keychain did not keep the token")
	}
	return locationKeychain, nil
}

func (k *keychainStore) Get(ctx context.Context, profile string) (string, error) {
	out, err := k.run(ctx, nil, k.tool, "find-generic-password", "-s", credentialService, "-a", profile, "-w")
	if err != nil {
		return "", ErrNoCredential
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", ErrNoCredential
	}
	return token, nil
}

func (k *keychainStore) Delete(ctx context.Context, profile string) error {
	_, _ = k.run(ctx, nil, k.tool, "delete-generic-password", "-s", credentialService, "-a", profile)
	return nil // absent is the goal
}

// ---- Secret Service -----------------------------------------------------------

type secretToolStore struct {
	tool string
	run  runner
}

func (s *secretToolStore) Set(ctx context.Context, profile, token string) (string, error) {
	if !safeToken.MatchString(token) {
		return "", errors.New("the token has an unexpected shape")
	}
	args := []string{"store", "--label", "SuperMgmt " + profile, "service", credentialService, "account", profile}
	if _, err := s.run(ctx, []byte(token), s.tool, args...); err != nil {
		return "", err
	}
	return locationSecretTool, nil
}

func (s *secretToolStore) Get(ctx context.Context, profile string) (string, error) {
	out, err := s.run(ctx, nil, s.tool, "lookup", "service", credentialService, "account", profile)
	if err != nil {
		return "", ErrNoCredential
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", ErrNoCredential
	}
	return token, nil
}

func (s *secretToolStore) Delete(ctx context.Context, profile string) error {
	_, _ = s.run(ctx, nil, s.tool, "clear", "service", credentialService, "account", profile)
	return nil
}

// ---- file fallback ------------------------------------------------------------

type fileStore struct{ path string }

type credentialsDoc struct {
	Version int               `json:"version"`
	Tokens  map[string]string `json:"tokens"`
}

func (f *fileStore) load() (credentialsDoc, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return credentialsDoc{Version: credentialsVersion, Tokens: map[string]string{}}, nil
	}
	if err != nil {
		return credentialsDoc{}, fmt.Errorf("read credentials: %w", err)
	}
	var doc credentialsDoc
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != credentialsVersion {
		return credentialsDoc{}, fmt.Errorf("credentials file %s is not valid", f.path)
	}
	if doc.Tokens == nil {
		doc.Tokens = map[string]string{}
	}
	return doc, nil
}

func (f *fileStore) save(doc credentialsDoc) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	return writeFileAtomic(f.path, data)
}

func (f *fileStore) Get(_ context.Context, profile string) (string, error) {
	doc, err := f.load()
	if err != nil {
		return "", err
	}
	token, ok := doc.Tokens[profile]
	if !ok || token == "" {
		return "", ErrNoCredential
	}
	return token, nil
}

func (f *fileStore) Set(_ context.Context, profile, token string) (string, error) {
	doc, err := f.load()
	if err != nil {
		return "", err
	}
	doc.Tokens[profile] = token
	if err := f.save(doc); err != nil {
		return "", err
	}
	return fmt.Sprintf(locationFileTemplate, f.path), nil
}

func (f *fileStore) Delete(_ context.Context, profile string) error {
	doc, err := f.load()
	if err != nil {
		return err
	}
	if _, ok := doc.Tokens[profile]; !ok {
		return nil
	}
	delete(doc.Tokens, profile)
	return f.save(doc)
}

// ---- chain --------------------------------------------------------------------

// chainStore prefers the OS store and falls back to the file when the OS store
// is absent or fails. Reads look in both, since a token written while the OS
// store was unusable stays in the file.
type chainStore struct {
	native CredentialStore // nil when the machine has no tool
	file   *fileStore
}

func (c *chainStore) Get(ctx context.Context, profile string) (string, error) {
	if c.native != nil {
		if token, err := c.native.Get(ctx, profile); err == nil {
			return token, nil
		}
	}
	return c.file.Get(ctx, profile)
}

func (c *chainStore) Set(ctx context.Context, profile, token string) (string, error) {
	if c.native != nil {
		if location, err := c.native.Set(ctx, profile, token); err == nil {
			_ = c.file.Delete(ctx, profile) // no stale copy next to the good one
			return location, nil
		}
	}
	return c.file.Set(ctx, profile, token)
}

func (c *chainStore) Delete(ctx context.Context, profile string) error {
	if c.native != nil {
		_ = c.native.Delete(ctx, profile)
	}
	return c.file.Delete(ctx, profile)
}
