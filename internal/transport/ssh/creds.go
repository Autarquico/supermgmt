package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
)

const (
	agentRef       = "ssh-agent://default"
	secretPrefix   = "secret://"
	filePrefix     = "file://"
	identitySecret = secrets.SSHIdentityName
	maxKeyFileSize = 64 << 10
)

// Credential is a ready authentication method. Release frees what the method
// holds open (an agent connection) and is safe to call more than once.
type Credential struct {
	Auth    cryptossh.AuthMethod
	release func()
}

// Release frees the credential's resources after the handshake.
func (c Credential) Release() {
	if c.release != nil {
		c.release()
	}
}

// CredentialResolver turns a credential_ref (spec §8.4) into an auth method.
type CredentialResolver interface {
	Resolve(ctx context.Context, ref string) (Credential, error)
}

// SignerSource provides signers for stored secrets (*secrets.Store).
type SignerSource interface {
	Signer(ctx context.Context, ref secrets.Ref) (cryptossh.Signer, error)
}

// Credentials is the M1 resolver (ADR-0015): secret://ssh/default[@version]
// for automation; ssh-agent://default and file://<abs-path> for the human
// admin. Any other secret:// name is CAPABILITY_UNAVAILABLE in M1.
type Credentials struct {
	signers SignerSource
	agent   func() string // path of the agent socket
	uid     int
}

// NewCredentials builds the resolver. The agent socket is read from
// $SSH_AUTH_SOCK each time an agent credential is resolved.
func NewCredentials(signers SignerSource) *Credentials {
	return &Credentials{signers: signers, agent: func() string { return os.Getenv("SSH_AUTH_SOCK") }, uid: os.Getuid()}
}

var _ CredentialResolver = (*Credentials)(nil)

func (c *Credentials) Resolve(ctx context.Context, ref string) (Credential, error) {
	switch {
	case ref == agentRef:
		return c.fromAgent(ctx)
	case strings.HasPrefix(ref, secretPrefix):
		return c.fromSecret(ctx, strings.TrimPrefix(ref, secretPrefix))
	case strings.HasPrefix(ref, filePrefix):
		return c.fromFile(strings.TrimPrefix(ref, filePrefix))
	}
	return Credential{}, smerr.New(smerr.CodeInvalidArgument, "", "unsupported credential_ref scheme")
}

func (c *Credentials) fromSecret(ctx context.Context, rest string) (Credential, error) {
	name, version, err := parseSecretRef(rest)
	if err != nil {
		return Credential{}, err
	}
	if name != identitySecret {
		return Credential{}, smerr.New(smerr.CodeCapabilityUnavailable, "",
			"only secret://"+identitySecret+" can authenticate SSH sessions in this version")
	}
	signer, err := c.signers.Signer(ctx, secrets.Ref{Name: name, Version: version})
	if err != nil {
		return Credential{}, fmt.Errorf("load ssh identity: %w", err)
	}
	return Credential{Auth: cryptossh.PublicKeys(signer)}, nil
}

// parseSecretRef splits "<name>[@<version>]"; no version means the latest.
func parseSecretRef(rest string) (string, int, error) {
	name, versionText, hasVersion := strings.Cut(rest, "@")
	if !hasVersion {
		return name, 0, nil
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version < 1 || strconv.Itoa(version) != versionText {
		return "", 0, smerr.New(smerr.CodeInvalidArgument, "", "invalid secret version in credential_ref")
	}
	return name, version, nil
}

func (c *Credentials) fromAgent(ctx context.Context) (Credential, error) {
	socket := c.agent()
	if socket == "" {
		return Credential{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "SSH_AUTH_SOCK is not set: no ssh-agent available")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return Credential{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "cannot reach the ssh-agent")
	}
	client := agent.NewClient(conn)
	return Credential{Auth: cryptossh.PublicKeysCallback(client.Signers), release: func() { _ = conn.Close() }}, nil
}

func (c *Credentials) fromFile(path string) (Credential, error) {
	if !filepath.IsAbs(path) {
		return Credential{}, smerr.New(smerr.CodeInvalidArgument, "", "file:// credential_ref needs an absolute path")
	}
	raw, err := readPrivateKeyFile(path, c.uid)
	if err != nil {
		return Credential{}, err
	}
	defer clear(raw)
	signer, err := cryptossh.ParsePrivateKey(raw)
	var missing *cryptossh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return Credential{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "passphrase-protected key files are not supported; use ssh-agent://default")
	case err != nil:
		return Credential{}, smerr.New(smerr.CodeCapabilityUnavailable, "", "key file "+path+" is not a usable SSH private key")
	}
	return Credential{Auth: cryptossh.PublicKeys(signer)}, nil
}

// readPrivateKeyFile applies the §8.4 checks: O_NOFOLLOW, a regular file owned
// by the daemon user with no group/other bits, in a directory that is not
// group/other-writable.
func readPrivateKeyFile(path string, uid int) ([]byte, error) {
	if problem := parentProblem(filepath.Dir(path)); problem != "" {
		return nil, unusableKeyFile(path, problem)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // path is the operator's configured key file; every §8.4 check follows
	switch {
	case errors.Is(err, syscall.ELOOP):
		return nil, unusableKeyFile(path, "is a symlink")
	case err != nil:
		return nil, unusableKeyFile(path, "cannot be opened")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, unusableKeyFile(path, "cannot be inspected")
	}
	if problem := keyFileProblem(info, uid); problem != "" {
		return nil, unusableKeyFile(path, problem)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize))
	if err != nil {
		return nil, unusableKeyFile(path, "cannot be read")
	}
	return raw, nil
}

func keyFileProblem(info fs.FileInfo, uid int) string {
	st, _ := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return "is not a regular file"
	case info.Mode().Perm()&0o077 != 0:
		return fmt.Sprintf("has mode %04o; group/other access is not allowed", info.Mode().Perm())
	case st == nil || int(st.Uid) != uid:
		return "is not owned by the daemon user"
	}
	return ""
}

func parentProblem(dir string) string {
	info, err := os.Stat(dir)
	switch {
	case err != nil:
		return "has an unreadable parent directory"
	case info.Mode().Perm()&0o022 != 0:
		return "sits in a group/other-writable directory"
	}
	return ""
}

func unusableKeyFile(path, problem string) error {
	return smerr.New(smerr.CodeCapabilityUnavailable, "", "key file "+path+" "+problem)
}
