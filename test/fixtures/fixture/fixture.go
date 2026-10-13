//go:build fixtures

// Package fixture builds and drives the M1 node fixture image
// (test/fixtures/node): a Debian node with systemd as PID 1, sshd, sudo and
// docker, a bootstrap account `admin` with passwordless sudo, and no
// `supermgmt` user (ADR-0009). It shells out to the docker CLI and is only
// compiled with `-tags fixtures`, so the regular suite stays hermetic.
package fixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

const (
	// ImageTag is the local tag of the default (Debian 13) image.
	ImageTag = "sm-fixture-node:local"
	// DistroEnv selects the node distro: debian13 (default) or ubuntu2404.
	DistroEnv = "SM_FIXTURE_DISTRO"
	// AdminUser is the bootstrap account baked into the image.
	AdminUser = "admin"

	readyTimeout = 3 * time.Minute
	readyPoll    = time.Second
)

// Options tune one fixture node.
type Options struct {
	// Name is the container name; empty picks a unique one.
	Name string
	// DemoContainer starts the `sm-demo-web` container inside the node's
	// docker (pulls busybox, needs network).
	DemoContainer bool
}

// Node is a running fixture container.
type Node struct {
	Name string
	// Host and Port are the published sshd endpoint on the docker host.
	Host string
	Port int
	// HostKey is the sshd host key this run injected; pin it before dialing.
	HostKey cryptossh.PublicKey
	// ClientSigner authenticates as AdminUser.
	ClientSigner cryptossh.Signer
}

// image is the build recipe of one supported distro.
type image struct{ tag, dockerfile string }

// imageFor resolves a SM_FIXTURE_DISTRO value; empty means debian13.
func imageFor(distro string) (image, error) {
	switch distro {
	case "", "debian13":
		return image{tag: ImageTag, dockerfile: "Dockerfile"}, nil
	case "ubuntu2404":
		return image{tag: "sm-fixture-node:ubuntu2404", dockerfile: "Dockerfile.ubuntu2404"}, nil
	default:
		return image{}, fmt.Errorf("unknown %s %q (want debian13 or ubuntu2404)", DistroEnv, distro)
	}
}

func selectedImage() (image, error) { return imageFor(os.Getenv(DistroEnv)) }

// Build builds the image of the distro selected by SM_FIXTURE_DISTRO
// (cached by docker when unchanged).
func Build(ctx context.Context) error {
	img, err := selectedImage()
	if err != nil {
		return err
	}
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "node")
	if out, err := docker(ctx, nil, "build", "--quiet", "--tag", img.tag,
		"--file", filepath.Join(dir, img.dockerfile), dir); err != nil {
		return fmt.Errorf("build fixture image: %w: %s", err, out)
	}
	return nil
}

// Start runs a node, injects fresh host and client keys, starts sshd and
// waits until systemd reports `running`. On error nothing is left behind.
func Start(ctx context.Context, o Options) (_ *Node, err error) {
	hostKey, hostPEM, err := newKey("fixture host key")
	if err != nil {
		return nil, err
	}
	clientSigner, clientPub, err := newClientKey()
	if err != nil {
		return nil, err
	}
	img, err := selectedImage()
	if err != nil {
		return nil, err
	}
	name := o.Name
	if name == "" {
		name = "sm-fixture-" + rand.Text()
	}
	if out, runErr := docker(ctx, nil, "run", "--detach", "--privileged", "--cgroupns=host",
		"--tmpfs", "/run", "--tmpfs", "/run/lock", "--publish", "127.0.0.1::22",
		"--name", name, img.tag); runErr != nil {
		return nil, fmt.Errorf("run fixture: %w: %s", runErr, out)
	}
	n := &Node{Name: name, HostKey: hostKey.PublicKey(), ClientSigner: clientSigner}
	defer func() {
		if err != nil {
			_ = n.Stop(context.WithoutCancel(ctx))
		}
	}()
	if err = n.waitSystemdRunning(ctx); err != nil {
		return nil, err
	}
	if err = n.injectKeys(ctx, hostKey, hostPEM, clientPub); err != nil {
		return nil, err
	}
	if _, err = n.Exec(ctx, "systemctl", "start", "ssh.service"); err != nil {
		return nil, fmt.Errorf("start sshd: %w", err)
	}
	if err = n.resolveEndpoint(ctx); err != nil {
		return nil, err
	}
	if o.DemoContainer {
		if _, err = n.Exec(ctx, "systemctl", "start", "sm-demo-web-container.service"); err != nil {
			return nil, fmt.Errorf("start demo container: %w", err)
		}
	}
	return n, nil
}

// Addr is "host:port" for dialing.
func (n *Node) Addr() string { return net.JoinHostPort(n.Host, strconv.Itoa(n.Port)) }

// Exec runs a command as root inside the container and returns its output.
func (n *Node) Exec(ctx context.Context, argv ...string) (string, error) {
	return docker(ctx, nil, append([]string{"exec", n.Name}, argv...)...)
}

// Pause freezes the node (every connection hangs); Unpause thaws it.
func (n *Node) Pause(ctx context.Context) error {
	_, err := docker(ctx, nil, "pause", n.Name)
	return err
}

func (n *Node) Unpause(ctx context.Context) error {
	_, err := docker(ctx, nil, "unpause", n.Name)
	return err
}

// Logs returns the container's console output, for CI artifacts.
func (n *Node) Logs(ctx context.Context) string {
	out, _ := docker(ctx, nil, "logs", n.Name)
	return out
}

// Stop removes the container and its anonymous volumes. It is idempotent.
func (n *Node) Stop(ctx context.Context) error {
	if out, err := docker(ctx, nil, "rm", "--force", "--volumes", n.Name); err != nil &&
		!strings.Contains(out, "No such container") {
		return fmt.Errorf("remove fixture %s: %w: %s", n.Name, err, out)
	}
	return nil
}

func (n *Node) waitSystemdRunning(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	last := ""
	for {
		out, err := n.Exec(ctx, "systemctl", "is-system-running", "--wait")
		last = strings.TrimSpace(out)
		if err == nil && last == "running" {
			return nil
		}
		select {
		case <-ctx.Done():
			failed, _ := n.Exec(context.WithoutCancel(ctx), "systemctl", "--failed", "--no-legend", "--plain")
			return fmt.Errorf("systemd not running after %s (last state %q, failed units: %q): %w",
				readyTimeout, last, strings.TrimSpace(failed), ctx.Err())
		case <-time.After(readyPoll):
		}
	}
}

func (n *Node) injectKeys(ctx context.Context, host cryptossh.Signer, hostPEM, clientPub []byte) error {
	files := []struct {
		path, owner, mode string
		content           []byte
	}{
		{"/etc/ssh/ssh_host_ed25519_key", "root:root", "0600", hostPEM},
		{"/etc/ssh/ssh_host_ed25519_key.pub", "root:root", "0644", cryptossh.MarshalAuthorizedKey(host.PublicKey())},
		{"/home/admin/.ssh/authorized_keys", "admin:admin", "0600", clientPub},
	}
	for _, f := range files {
		script := fmt.Sprintf("umask 077 && cat > %[1]s && chown %[2]s %[1]s && chmod %[3]s %[1]s", f.path, f.owner, f.mode)
		if out, err := docker(ctx, f.content, "exec", "-i", n.Name, "sh", "-c", script); err != nil {
			return fmt.Errorf("inject %s: %w: %s", f.path, err, out)
		}
	}
	return nil
}

func (n *Node) resolveEndpoint(ctx context.Context) error {
	out, err := docker(ctx, nil, "port", n.Name, "22/tcp")
	if err != nil {
		return fmt.Errorf("resolve ssh port: %w: %s", err, out)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	host, port, err := net.SplitHostPort(line)
	if err != nil {
		return fmt.Errorf("parse published port %q: %w", line, err)
	}
	if n.Port, err = strconv.Atoi(port); err != nil {
		return fmt.Errorf("parse port %q: %w", port, err)
	}
	n.Host = host
	return nil
}

func newKey(comment string) (cryptossh.Signer, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("signer: %w", err)
	}
	return signer, pem.EncodeToMemory(block), nil
}

func newClientKey() (cryptossh.Signer, []byte, error) {
	signer, _, err := newKey("fixture client key")
	if err != nil {
		return nil, nil, err
	}
	return signer, cryptossh.MarshalAuthorizedKey(signer.PublicKey()), nil
}

func docker(ctx context.Context, stdin []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}
