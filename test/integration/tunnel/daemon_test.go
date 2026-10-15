package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/client"
	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/daemon"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// liveDaemon is `sm daemon` running in this process, reached over its Unix
// socket with the typed client, the way the CLI and the TUI reach it.
type liveDaemon struct {
	t      *testing.T
	api    *client.Client
	socket string
}

const cloudflareBlock = `cloudflare:
  account_id: 0123456789abcdef0123456789abcdef
  zone: example.test
  owner_emails: [owner@example.test]
`

// loadConfig writes and loads a local-mode configuration with extra appended.
func loadConfig(t *testing.T, root, extra string) (*config.Config, error) {
	t.Helper()
	file := filepath.Join(root, "config.yaml")
	yaml := "version: 1\ninstance:\n  mode: local\n  data_dir: " + filepath.Join(root, "data") + "\n" +
		"environments:\n  - name: staging\n    risk_level: staging\n" + extra
	must(t, os.WriteFile(file, []byte(yaml), 0o600))
	res, err := config.Load(file, []string{"HOME=" + root})
	if err != nil {
		return nil, err
	}
	return res.Config, nil
}

func startDaemon(t *testing.T, extra string) *liveDaemon {
	t.Helper()
	root, err := os.MkdirTemp("", "smd") // short: sun_path is limited on macOS
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cfg, err := loadConfig(t, root, extra)
	must(t, err)
	socket := filepath.Join(root, "run", "s")

	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{Config: cfg, Socket: socket, OnListening: func(string) { close(listening) }, IdleCheck: 10 * time.Millisecond})
	}()
	select {
	case <-listening:
	case err := <-done:
		cancel()
		t.Fatalf("the daemon did not start: %v", err)
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("the daemon did not start within 30s")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the daemon did not stop within 30s")
		}
	})
	return &liveDaemon{t: t, api: client.New(client.Options{Socket: socket}), socket: socket}
}

// hostKey is a valid OpenSSH host key line the node can be pinned to without
// scanning anything.
func hostKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	key, err := cryptossh.NewPublicKey(pub)
	must(t, err)
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key)))
}

func (d *liveDaemon) addNode(name, host string) (wire.Direct[wire.Node], error) {
	d.t.Helper()
	return d.api.AddSSHNode(context.Background(), wire.AddSSHNodeRequest{
		Name: name, Host: host, Port: 22, AdminUser: "admin", HostPublicKey: hostKey(d.t), Environment: "staging",
	})
}

func (d *liveDaemon) nodes() []wire.Node {
	d.t.Helper()
	page, err := d.api.ListNodes(context.Background(), wire.NodeQuery{})
	must(d.t, err)
	return page.Items
}

func codeOf(err error) smerr.Code { return smerr.CodeOf(err) }
