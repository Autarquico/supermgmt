package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

// serveTestAgent serves an ssh-agent holding keys and returns its socket.
func serveTestAgent(t *testing.T, keys ...any) string {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := os.MkdirTemp("", "sm") // a unix socket path must stay short
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "a.sock")
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

func TestNodesAddWarnsWhenTheAgentCannotSignIn(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		env  []string
		want string
	}{
		"no agent":         {nil, "SSH_AUTH_SOCK is not set"},
		"empty agent":      {[]string{"SSH_AUTH_SOCK=" + serveTestAgent(t)}, "holds no keys"},
		"agent is gone":    {[]string{"SSH_AUTH_SOCK=" + filepath.Join(t.TempDir(), "gone.sock")}, "does not answer"},
		"agent with a key": {[]string{"SSH_AUTH_SOCK=" + serveTestAgent(t, key)}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			k := scannedKey(t)
			f := addNodeAPI(t, k)
			f.Env = append(f.Env, tc.env...)

			r := f.run(append(addArgs, "--fingerprint", k.FingerprintSHA256)...)

			if r.code != 0 {
				t.Fatalf("a warning must not fail the add: code=%d err=%q", r.code, r.stderr)
			}
			warned := strings.Contains(r.stderr, "warning:")
			if tc.want == "" && warned || tc.want != "" && !strings.Contains(r.stderr, tc.want) {
				t.Errorf("stderr = %q, want warning %q", r.stderr, tc.want)
			}
		})
	}
}

func TestNodesAddDoesNotCheckTheAgentForAnotherCredential(t *testing.T) {
	k := scannedKey(t)
	f := addNodeAPI(t, k)

	r := f.run(append(addArgs, "--fingerprint", k.FingerprintSHA256, "--admin-credential-ref", "file:///home/alex/.ssh/id_ed25519")...)

	if strings.Contains(r.stderr, "warning:") {
		t.Errorf("a file credential needs no agent: %q", r.stderr)
	}
}

func TestNodesAddDoesNotCheckTheShellsAgentForAServer(t *testing.T) {
	k := scannedKey(t)
	f := addNodeAPI(t, k)
	configFile := f.Args[len(f.Args)-1]
	writeFile(t, configFile, "version: 1\ninstance:\n  mode: server\n  data_dir: "+filepath.Join(filepath.Dir(configFile), "data")+"\n"+
		"server:\n  admin_socket: "+filepath.Join(filepath.Dir(configFile), "s")+"\n")

	r := f.run(append(addArgs, "--fingerprint", k.FingerprintSHA256)...)

	if r.code != 0 || strings.Contains(r.stderr, "warning:") {
		t.Errorf("a server signs with its own agent, not this shell's: code=%d %q", r.code, r.stderr)
	}
}
