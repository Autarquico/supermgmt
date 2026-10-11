//go:build e2e

package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// HostImage is the clean Debian systemd image every server, mirror and node host runs.
const HostImage = "sm-e2e-host:local"

var (
	workDir  string
	built    = map[string]*buildOnce{}
	builtMu  sync.Mutex
	dockerGo string
)

type buildOnce struct {
	once sync.Once
	path string
	err  error
}

// Init creates the process-wide work directory; call it from TestMain and defer Close.
func Init() error {
	dir, err := os.MkdirTemp("", "sm-e2e-")
	if err != nil {
		return err
	}
	workDir = dir
	return nil
}

// Close removes the work directory.
func Close() { _ = os.RemoveAll(workDir) }

// WorkDir is the process-wide work directory.
func WorkDir() string { return workDir }

func once(key string, build func() (string, error)) (string, error) {
	builtMu.Lock()
	b, ok := built[key]
	if !ok {
		b = &buildOnce{}
		built[key] = b
	}
	builtMu.Unlock()
	b.once.Do(func() { b.path, b.err = build() })
	return b.path, b.err
}

// DockerArch is the GOARCH of the docker daemon's containers.
func DockerArch(t testing.TB) string {
	t.Helper()
	builtMu.Lock()
	defer builtMu.Unlock()
	if dockerGo != "" {
		return dockerGo
	}
	switch arch := MustDocker(t, "info", "--format", "{{.Architecture}}"); arch {
	case "x86_64", "amd64":
		dockerGo = "amd64"
	case "aarch64", "arm64":
		dockerGo = "arm64"
	default:
		t.Fatalf("unsupported docker architecture %q", arch)
	}
	return dockerGo
}

func goBuild(goos, goarch, pkg, out string) (string, error) {
	env := append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	res, err := Run(context.Background(), RepoRoot(), env, "", "go", "build", "-trimpath", "-o", out, pkg)
	if err := commandError(fmt.Sprintf("go build %s for %s/%s", pkg, goos, goarch), res, err); err != nil {
		return "", err
	}
	return out, nil
}

// HostSM builds `sm` for the machine running the tests: the laptop client.
func HostSM(t testing.TB) string {
	t.Helper()
	path, err := once("host-sm", func() (string, error) {
		return goBuild(runtime.GOOS, runtime.GOARCH, "./cmd/sm", filepath.Join(workDir, "sm-host"))
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// LinuxSM builds `sm` for the containers.
func LinuxSM(t testing.TB) string {
	t.Helper()
	arch := DockerArch(t)
	path, err := once("linux-sm", func() (string, error) {
		return goBuild("linux", arch, "./cmd/sm", filepath.Join(workDir, "sm-linux-"+arch))
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// Tool builds e2etool (TLS proxy and file server) for the containers.
func Tool(t testing.TB) string {
	t.Helper()
	arch := DockerArch(t)
	path, err := once("tool", func() (string, error) {
		return goBuild("linux", arch, "./test/e2e/e2etool", filepath.Join(workDir, "e2etool-"+arch))
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// Image builds the Debian systemd host image (cached by docker).
func Image(t testing.TB) string {
	t.Helper()
	if _, err := once("image", func() (string, error) {
		res, err := Docker(context.Background(), "", "build", "--quiet", "--tag", HostImage, filepath.Join(RepoRoot(), "test", "e2e", "image"))
		if err := commandError("build "+HostImage, res, err); err != nil {
			return "", err
		}
		return HostImage, nil
	}); err != nil {
		t.Fatal(err)
	}
	return HostImage
}

// Host starts a clean Debian systemd container on the network and waits for it to settle.
// aliases are extra DNS names on that network.
func Host(t testing.TB, net *Network, publish []string, aliases ...string) *Container {
	t.Helper()
	c := Start(t, RunOptions{Image: Image(t), Network: net.Name, Aliases: aliases, Publish: publish, Privileged: true})
	c.WaitSystemd(context.Background())
	return c
}

// TrustCA installs a CA certificate in the container's system trust store.
func (c *Container) TrustCA(ctx context.Context, caPEM []byte) {
	c.t.Helper()
	c.WriteFile(ctx, "/usr/local/share/ca-certificates/e2e-"+Suffix()+".crt", caPEM, "0644")
	c.MustExec(ctx, "update-ca-certificates")
}

// InstallSM puts the Linux `sm` at path (for scenarios that do not go through install.sh).
func (c *Container) InstallSM(ctx context.Context, t testing.TB, path string) {
	c.CopyRoot(ctx, LinuxSM(t), path)
	c.MustExec(ctx, "chmod", "0755", path)
}
