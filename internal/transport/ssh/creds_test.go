package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/autarquico/supermgmt/internal/domain/domaintest"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/secrets"
	"github.com/autarquico/supermgmt/internal/secrets/secretstest"
)

type fakeSigners struct {
	signer cryptossh.Signer
	asked  []secrets.Ref
}

func (f *fakeSigners) Signer(_ context.Context, ref secrets.Ref) (cryptossh.Signer, error) {
	f.asked = append(f.asked, ref)
	return f.signer, nil
}

func resolver(t *testing.T) (*Credentials, *fakeSigners) {
	t.Helper()
	signers := &fakeSigners{signer: newSigner(t)}
	return NewCredentials(signers), signers
}

func TestSecretRefsResolveOnlyTheInstanceIdentity(t *testing.T) {
	c, signers := resolver(t)
	tests := []struct {
		ref  string
		want secrets.Ref
	}{
		{"secret://ssh/default", secrets.Ref{Name: "ssh/default"}},
		{"secret://ssh/default@3", secrets.Ref{Name: "ssh/default", Version: 3}},
	}
	for _, tt := range tests {
		cred, err := c.Resolve(context.Background(), tt.ref)
		if err != nil || cred.Auth == nil {
			t.Fatalf("%s: %v", tt.ref, err)
		}
		if got := signers.asked[len(signers.asked)-1]; got != tt.want {
			t.Errorf("%s asked for %+v, want %+v", tt.ref, got, tt.want)
		}
	}
}

func TestCredentialRefErrors(t *testing.T) {
	c, _ := resolver(t)
	tests := map[string]smerr.Code{
		"secret://ssh/other":       smerr.CodeCapabilityUnavailable,
		"secret://proxmox/token":   smerr.CodeCapabilityUnavailable,
		"secret://ssh/default@0":   smerr.CodeInvalidArgument,
		"secret://ssh/default@-1":  smerr.CodeInvalidArgument,
		"secret://ssh/default@01":  smerr.CodeInvalidArgument,
		"secret://ssh/default@abc": smerr.CodeInvalidArgument,
		"secret://ssh/default@":    smerr.CodeInvalidArgument,
		"vault://x":                smerr.CodeInvalidArgument,
		"":                         smerr.CodeInvalidArgument,
		"ssh-agent://other":        smerr.CodeInvalidArgument,
		"file://relative/key":      smerr.CodeInvalidArgument,
		"/abs/without/scheme":      smerr.CodeInvalidArgument,
		"secret://ssh/default@1@2": smerr.CodeInvalidArgument,
	}
	for ref, want := range tests {
		_, err := c.Resolve(context.Background(), ref)
		requireCode(t, err, want)
	}
}

// shortTempDir avoids the 104-byte unix socket path limit on macOS.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func serveAgent(t *testing.T, keys ...any) string {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(shortTempDir(t), "a.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()
	return socket
}

func TestAgentCredentialAuthenticatesAgainstARealServer(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	server := startServer(t, signer, nil)
	t.Setenv("SSH_AUTH_SOCK", serveAgent(t, private))

	pool := NewPool(defaultConfig(), NewCredentials(&fakeSigners{}), domaintest.NewFakeClock(epoch))
	t.Cleanup(pool.Close)
	target := Target{NodeID: "n1", Host: "127.0.0.1", Port: server.port(), User: "admin", HostKey: server.pinned(), CredentialRef: "ssh-agent://default"}
	res, err := pool.For(target).Run(context.Background(), templatesRead("who"))
	if err != nil || string(res.Stdout) != "ran: who" {
		t.Fatalf("%q, %v", res.Stdout, err)
	}
}

func TestAgentUnavailableIsCapabilityUnavailable(t *testing.T) {
	c, _ := resolver(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err := c.Resolve(context.Background(), "ssh-agent://default")
	requireCode(t, err, smerr.CodeCapabilityUnavailable)

	t.Setenv("SSH_AUTH_SOCK", filepath.Join(shortTempDir(t), "gone.sock"))
	_, err = c.Resolve(context.Background(), "ssh-agent://default")
	requireCode(t, err, smerr.CodeCapabilityUnavailable)
}

func TestAnEmptyAgentIsReportedAsSuch(t *testing.T) {
	c, _ := resolver(t)
	t.Setenv("SSH_AUTH_SOCK", serveAgent(t))

	_, err := c.Resolve(context.Background(), "ssh-agent://default")

	requireCode(t, err, smerr.CodeCapabilityUnavailable)
	if !strings.Contains(err.Error(), "ssh-add") {
		t.Errorf("the message must say how to load a key: %v", err)
	}
}

func writeKeyFile(t *testing.T, dir string, mode os.FileMode) (string, []byte) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(block)
	path := filepath.Join(dir, "id")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path, body
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(shortTempDir(t), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFileCredentialLoadsAnOwnerOnlyKey(t *testing.T) {
	c, _ := resolver(t)
	path, _ := writeKeyFile(t, privateDir(t), 0o600)
	cred, err := c.Resolve(context.Background(), "file://"+path)
	if err != nil || cred.Auth == nil {
		t.Fatal(err)
	}
}

func TestFileCredentialChecks(t *testing.T) {
	c, _ := resolver(t)
	t.Run("group/other bits", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666} {
			path, body := writeKeyFile(t, privateDir(t), mode)
			_, err := c.Resolve(context.Background(), "file://"+path)
			requireCode(t, err, smerr.CodeCapabilityUnavailable)
			assertNoKeyMaterial(t, err, body)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := privateDir(t)
		real, body := writeKeyFile(t, privateDir(t), 0o600)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		_, err := c.Resolve(context.Background(), "file://"+link)
		requireCode(t, err, smerr.CodeCapabilityUnavailable)
		assertNoKeyMaterial(t, err, body)
	})
	t.Run("not a regular file", func(t *testing.T) {
		_, err := c.Resolve(context.Background(), "file://"+privateDir(t))
		requireCode(t, err, smerr.CodeCapabilityUnavailable)
	})
	t.Run("parent directory writable by others", func(t *testing.T) {
		dir := privateDir(t)
		path, _ := writeKeyFile(t, dir, 0o600)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err := c.Resolve(context.Background(), "file://"+path)
		requireCode(t, err, smerr.CodeCapabilityUnavailable)
	})
	t.Run("missing", func(t *testing.T) {
		_, err := c.Resolve(context.Background(), "file://"+filepath.Join(privateDir(t), "nope"))
		requireCode(t, err, smerr.CodeCapabilityUnavailable)
	})
	t.Run("garbage content", func(t *testing.T) {
		dir := privateDir(t)
		path := filepath.Join(dir, "id")
		if err := os.WriteFile(path, []byte("SECRET-GARBAGE-MARKER"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := c.Resolve(context.Background(), "file://"+path)
		requireCode(t, err, smerr.CodeCapabilityUnavailable)
		assertNoKeyMaterial(t, err, []byte("SECRET-GARBAGE-MARKER"))
	})
}

func TestOwnershipIsPartOfTheFileKeyCheck(t *testing.T) {
	path, _ := writeKeyFile(t, privateDir(t), 0o600)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyFileProblem(info, os.Getuid()); got != "" {
		t.Errorf("own file refused: %s", got)
	}
	if got := keyFileProblem(info, os.Getuid()+1); !strings.Contains(got, "not owned") {
		t.Errorf("foreign owner accepted: %q", got)
	}
}

func TestPassphraseProtectedKeyFilesAreRefusedWithAnExplanation(t *testing.T) {
	c, _ := resolver(t)
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	block, err := cryptossh.MarshalPrivateKeyWithPassphrase(private, "", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateDir(t), "id")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = c.Resolve(context.Background(), "file://"+path)
	requireCode(t, err, smerr.CodeCapabilityUnavailable)
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("err = %v", err)
	}
}

func assertNoKeyMaterial(t *testing.T, err error, material []byte) {
	t.Helper()
	if strings.Contains(err.Error(), string(material)) {
		t.Errorf("error leaks key file content: %v", err)
	}
}

// TestSecretBackedSessionNeverLeaksTheKey runs the real path end to end: the
// identity is generated in the secret store, a pool connects with it, and
// every error and state string produced along the way is scanned.
func TestSecretBackedSessionNeverLeaksTheKey(t *testing.T) {
	ctx := context.Background()
	repo := secretstest.NewMemRepo()
	ids := domaintest.NewSequentialIDs()
	keys, err := secrets.OpenFileKeys(ctx, filepath.Join(shortTempDir(t), "keys"), repo, ids)
	if err != nil {
		t.Fatal(err)
	}
	store := secrets.NewStore(keys, repo, ids, domaintest.NewFakeClock(epoch))
	identity, err := secrets.EnsureSSHIdentity(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := store.Signer(ctx, identity.Ref)
	if err != nil {
		t.Fatal(err)
	}
	pemText, _ := store.Get(ctx, identity.Ref)
	body := strings.Split(strings.TrimSpace(pemText.Reveal()), "\n")[1]

	server := startServer(t, signer, nil)
	pool := NewPool(defaultConfig(), NewCredentials(store), domaintest.NewFakeClock(epoch))
	t.Cleanup(pool.Close)
	target := Target{NodeID: "n1", Host: "127.0.0.1", Port: server.port(), User: "supermgmt", HostKey: server.pinned(), CredentialRef: "secret://ssh/default@1"}
	if _, err := pool.For(target).Run(ctx, templatesRead("id -un")); err != nil {
		t.Fatalf("connect with the stored identity: %v", err)
	}

	var surfaces []string
	bad := target
	bad.HostKey = rsaAuthorizedKey(t)
	_, mismatch := pool.For(bad).Run(ctx, templatesRead("x"))
	surfaces = append(surfaces, mismatch.Error())
	missing := target
	missing.NodeID, missing.CredentialRef = "n2", "secret://ssh/default@9"
	_, notFound := pool.For(missing).Run(ctx, templatesRead("x"))
	surfaces = append(surfaces, notFound.Error(), string(pool.State("n1").Status), pool.State("n2").LastError.Error())

	for _, s := range surfaces {
		if strings.Contains(s, body) || strings.Contains(s, "PRIVATE KEY") {
			t.Errorf("key material in %q", s)
		}
	}
}
