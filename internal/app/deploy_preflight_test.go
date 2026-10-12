package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/autarquico/supermgmt/internal/deployments"
	"github.com/autarquico/supermgmt/internal/deployments/compose"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	preflightImage  = "registry.example.com/web@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	preflightRoot   = "/srv/supermgmt"
	preflightDocker = "/var/lib/docker"
	preflightSize   = int64(500 << 20)
)

var preflightOwner = domain.ID("11111111-1111-4111-8111-111111111111")

func preflightDF(free int64) string {
	return fmt.Sprintf("Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/vda1 99999999999 1 %d 1%% /\n", free)
}

// preflightFixture is a healthy node that holds no image yet and has room.
type preflightFixture struct {
	node  *fakeNode
	input preflightInput
}

func newPreflightFixture(t *testing.T) *preflightFixture {
	t.Helper()
	node := newFakeNode(t)
	node.reply("compose.docker_root", preflightDocker+"\n")
	node.reply("compose.project_containers", "")
	node.reply("compose.project_resources", "")
	node.reply("compose.listeners", "")
	node.exit("compose.image_inspect", 1)
	node.reply("compose.image_size", fmt.Sprintf("%d\n", preflightSize))
	node.reply("compose.disk_free", preflightDF(1<<40))
	return &preflightFixture{node: node, input: preflightInput{
		Project: "shop", Owner: preflightOwner, DeployRoot: preflightRoot,
		Images:       []string{preflightImage},
		Capabilities: map[string]bool{"docker.compose.deploy": true, "health.http": true, "health.tcp": true, "docker.read": true},
	}}
}

func (f *preflightFixture) run() error {
	return runPreflight(context.Background(), f.node, f.input)
}

func wantPreflightCause(t *testing.T, err error, cause string) {
	t.Helper()
	wantError(t, err, smerr.CodeDeploymentFailed, smerr.ReasonPreflightFailed)
	var typed *smerr.Error
	if !errors.As(err, &typed) || typed.Details["cause"] != cause {
		t.Fatalf("details = %v, want cause %s", typed.Details, cause)
	}
}

func TestPreflight_HealthyNodePasses(t *testing.T) {
	f := newPreflightFixture(t)
	if err := f.run(); err != nil {
		t.Fatalf("runPreflight: %v", err)
	}
}

func TestPreflight_DiskThreshold(t *testing.T) {
	need := preflightSize + 1<<30
	tests := []struct {
		name        string
		dockerFree  int64
		deployFree  int64
		wantDiskLow bool
	}{
		{"below on both", need - 1, need - 1, true},
		{"below on the docker root only", need - 1, need + 1, true},
		{"below on the deploy root only", need + 1, need - 1, true},
		{"equal passes", need, need, false},
		{"above passes", need + 1, need + 1, false},
	}
	dockerRootLine := mustRender(t, "compose.disk_free", map[string]string{"path": preflightDocker}).Line
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPreflightFixture(t)
			f.node.on("compose.disk_free", func(c templates.Command) (transport.Result, error) {
				free := tt.deployFree
				if c.Line == dockerRootLine {
					free = tt.dockerFree
				}
				return transport.Result{Stdout: []byte(preflightDF(free))}, nil
			})
			err := f.run()
			if tt.wantDiskLow {
				wantPreflightCause(t, err, causePreflightDiskLow)
			} else if err != nil {
				t.Fatalf("runPreflight: %v", err)
			}
		})
	}
}

func TestPreflight_PresentImageCountsZero(t *testing.T) {
	f := newPreflightFixture(t)
	f.node.exit("compose.image_inspect", 0)
	f.node.reply("compose.disk_free", preflightDF(1<<30)) // exactly the headroom
	if err := f.run(); err != nil {
		t.Fatalf("runPreflight: %v", err)
	}
	if n := f.node.count("compose.image_size"); n != 0 {
		t.Errorf("image_size ran %d times for a present image", n)
	}
}

func TestPreflight_DiskThresholdSumsEveryMissingImage(t *testing.T) {
	f := newPreflightFixture(t)
	other := "registry.example.com/db@sha256:" + "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	f.input.Images = []string{preflightImage, other, preflightImage}
	f.node.reply("compose.disk_free", preflightDF(2*preflightSize+1<<30-1))
	wantPreflightCause(t, f.run(), causePreflightDiskLow)
	f.node.reply("compose.disk_free", preflightDF(2*preflightSize+1<<30))
	if err := f.run(); err != nil {
		t.Fatalf("runPreflight: %v", err)
	}
}

func TestPreflight_UnknownImageSizeFailsClosed(t *testing.T) {
	tests := map[string]func(*fakeNode){
		"command fails":        func(n *fakeNode) { n.exit("compose.image_size", 1) },
		"output is not a size": func(n *fakeNode) { n.reply("compose.image_size", "lots\n") },
		"negative size":        func(n *fakeNode) { n.reply("compose.image_size", "-5\n") },
		"empty output":         func(n *fakeNode) { n.reply("compose.image_size", "") },
		"output truncated": func(n *fakeNode) {
			n.on("compose.image_size", func(templates.Command) (transport.Result, error) {
				return transport.Result{Stdout: []byte("12\n"), Truncated: true}, nil
			})
		},
	}
	for name, breakSize := range tests {
		t.Run(name, func(t *testing.T) {
			f := newPreflightFixture(t)
			breakSize(f.node)
			wantPreflightCause(t, f.run(), deployments.CauseImageSizeUnknown)
		})
	}
}

func TestPreflight_UnreadableDiskFailsClosed(t *testing.T) {
	for name, out := range map[string]string{
		"header only":  "Filesystem 1-blocks Used Available Capacity Mounted on\n",
		"not a number": "Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/vda1 1 1 many 1% /\n",
		"empty":        "",
	} {
		t.Run(name, func(t *testing.T) {
			f := newPreflightFixture(t)
			f.node.reply("compose.disk_free", out)
			wantPreflightCause(t, f.run(), causePreflightDiskUnknown)
		})
	}
	t.Run("docker root is not a path", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.node.reply("compose.docker_root", "relative/dir\n")
		wantPreflightCause(t, f.run(), causePreflightDiskUnknown)
	})
}

func preflightContainerJSON(owner string, hostPorts ...string) string {
	labels := `{"com.docker.compose.project":"shop"`
	if owner != "" {
		labels += fmt.Sprintf(`,"dev.supermgmt.owner":%q`, owner)
	}
	labels += "}"
	bindings := ""
	for i, p := range hostPorts {
		if i > 0 {
			bindings += ","
		}
		bindings += fmt.Sprintf(`"80/tcp":[{"HostIp":"127.0.0.1","HostPort":%q}]`, p)
	}
	return fmt.Sprintf(`[{"Config":{"Labels":%s},"HostConfig":{"PortBindings":{%s}}}]`, labels, bindings)
}

func TestPreflight_ProjectNotOwned(t *testing.T) {
	tests := map[string]string{
		"no owner label":     preflightContainerJSON(""),
		"another app target": preflightContainerJSON("22222222-2222-4222-8222-222222222222"),
	}
	for name, containers := range tests {
		t.Run(name, func(t *testing.T) {
			f := newPreflightFixture(t)
			f.node.reply("compose.project_containers", containers)
			wantError(t, f.run(), smerr.CodeConflict, smerr.ReasonProjectNotOwned)
			if n := f.node.count("compose.image_size"); n != 0 {
				t.Errorf("preflight went on after the ownership refusal")
			}
		})
	}
	t.Run("own containers pass", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.node.reply("compose.project_containers", preflightContainerJSON(preflightOwner.String()))
		if err := f.run(); err != nil {
			t.Fatalf("runPreflight: %v", err)
		}
	})
	t.Run("unreadable inspect output fails", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.node.reply("compose.project_containers", "{not json")
		wantPreflightCause(t, f.run(), causePreflightUnreadable)
	})
}

func TestPreflight_ForeignPort(t *testing.T) {
	published := []compose.HostPort{{Service: "web", Addr: netip.MustParseAddr("127.0.0.1"), Port: 8080, Proto: "tcp"}}
	own := preflightOwner.String()
	tests := []struct {
		name      string
		listeners string
		owned     string
		wantBusy  bool
	}{
		{"free", "LISTEN 0 4096 127.0.0.1:9090 0.0.0.0:*\n", "", false},
		{"same address", "LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\n", "", true},
		{"wildcard ipv4", "LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*\n", "", true},
		{"wildcard star", "LISTEN 0 4096 *:8080 *:*\n", "", true},
		{"wildcard ipv6", "LISTEN 0 4096 [::]:8080 [::]:*\n", "", true},
		{"other address only", "LISTEN 0 4096 10.0.0.5:8080 0.0.0.0:*\n", "", false},
		{"owned by the project", "LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\n", preflightContainerJSON(own, "8080"), false},
		{"project owns another port", "LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\n", preflightContainerJSON(own, "9999"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPreflightFixture(t)
			f.input.HostPorts = published
			f.node.reply("compose.listeners", tt.listeners)
			f.node.reply("compose.project_containers", tt.owned)
			err := f.run()
			if tt.wantBusy {
				wantPreflightCause(t, err, causePreflightPortInUse)
			} else if err != nil {
				t.Fatalf("runPreflight: %v", err)
			}
		})
	}
}

func TestPreflight_UDPPorts(t *testing.T) {
	published := []compose.HostPort{{Service: "dns", Addr: netip.MustParseAddr("127.0.0.1"), Port: 5353, Proto: "udp"}}
	own := preflightOwner.String()
	tests := []struct {
		name      string
		listeners string
		owned     string
		wantBusy  bool
	}{
		{"a tcp listener does not hold the udp port", "LISTEN 0 4096 0.0.0.0:5353 0.0.0.0:*\n", "", false},
		{"a udp socket on the address holds it", "UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*\n", "", true},
		{"a udp wildcard holds it", "UNCONN 0 0 *:5353 *:*\n", "", true},
		{"a udp socket elsewhere does not", "UNCONN 0 0 10.0.0.5:5353 0.0.0.0:*\n", "", false},
		{"the project's own udp binding passes", "UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*\n", preflightUDPContainerJSON(own, "5353"), false},
		{"a tcp binding of the project does not own the udp port", "UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*\n", preflightContainerJSON(own, "5353"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPreflightFixture(t)
			f.input.HostPorts = published
			f.node.reply("compose.listeners", tt.listeners)
			f.node.reply("compose.project_containers", tt.owned)
			err := f.run()
			if tt.wantBusy {
				wantPreflightCause(t, err, causePreflightPortInUse)
			} else if err != nil {
				t.Fatalf("runPreflight: %v", err)
			}
		})
	}
}

func preflightUDPContainerJSON(owner, hostPort string) string {
	return fmt.Sprintf(`[{"Config":{"Labels":{"dev.supermgmt.owner":%q}},"HostConfig":{"PortBindings":{"53/udp":[{"HostPort":%q}]}}}]`, owner, hostPort)
}

func preflightResourceLine(kind, name, owner string) string {
	labels := `{"com.docker.compose.project":"shop"`
	if owner != "" {
		labels += fmt.Sprintf(`,"dev.supermgmt.owner":%q`, owner)
	}
	return fmt.Sprintf("%s {\"Name\":%q,\"Labels\":%s}}\n", kind, name, labels)
}

func TestPreflight_VolumesAndNetworksMustBeOwned(t *testing.T) {
	own := preflightOwner.String()
	other := "22222222-2222-4222-8222-222222222222"
	tests := []struct {
		name      string
		resources string
		wantRefus bool
	}{
		{"own volume and network pass", preflightResourceLine("volume", "shop_data", own) + preflightResourceLine("network", "shop_default", own), false},
		{"foreign volume", preflightResourceLine("volume", "shop_data", other), true},
		{"unlabelled volume", preflightResourceLine("volume", "shop_data", ""), true},
		{"foreign network", preflightResourceLine("volume", "shop_data", own) + preflightResourceLine("network", "shop_default", other), true},
		{"unlabelled network", preflightResourceLine("network", "shop_default", ""), true},
		{"project-prefixed name without any labels", `volume {"Name":"shop_cache","Labels":null}` + "\n", true},
		{"unrelated name matched by the substring filter", `volume {"Name":"myshop_x","Labels":null}` + "\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPreflightFixture(t)
			f.node.reply("compose.project_resources", tt.resources)
			err := f.run()
			if tt.wantRefus {
				wantError(t, err, smerr.CodeConflict, smerr.ReasonProjectNotOwned)
				if n := f.node.count("compose.image_size"); n != 0 {
					t.Errorf("preflight went on after the ownership refusal")
				}
			} else if err != nil {
				t.Fatalf("runPreflight: %v", err)
			}
		})
	}
	t.Run("unreadable output fails closed", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.node.reply("compose.project_resources", "volume {not json\n")
		wantPreflightCause(t, f.run(), causePreflightUnreadable)
	})
}

func TestPreflight_HealthCapabilityMissing(t *testing.T) {
	nodeCheck := func(typ string) health.Check { return health.Check{Scope: health.ScopeNode, Type: typ} }
	tests := []struct {
		name    string
		check   health.Check
		missing string
		wantErr bool
	}{
		{"http without curl", nodeCheck(health.TypeHTTP), "health.http", true},
		{"tcp without bash and timeout", nodeCheck(health.TypeTCP), "health.tcp", true},
		{"docker-health without docker", nodeCheck(health.TypeDockerHealth), "docker.read", true},
		{"unknown type", nodeCheck("systemd-active"), "", true},
		{"control plane checks need nothing on the node", health.Check{Scope: health.ScopeControlPlane, Type: health.TypeHTTP}, "health.http", false},
		{"capability present", nodeCheck(health.TypeHTTP), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPreflightFixture(t)
			f.input.Health = []health.Check{tt.check}
			delete(f.input.Capabilities, tt.missing)
			err := f.run()
			if tt.wantErr {
				wantPreflightCause(t, err, causePreflightHealthCapability)
			} else if err != nil {
				t.Fatalf("runPreflight: %v", err)
			}
		})
	}
}

func TestPreflight_ComposeDeployCapabilityMissing(t *testing.T) {
	f := newPreflightFixture(t)
	f.input.Capabilities["docker.compose.deploy"] = false
	wantPreflightCause(t, f.run(), deployments.CauseComposeUnsupported)
	if got := f.node.ran(); len(got) != 0 {
		t.Errorf("the node was read despite the missing capability: %v", got)
	}
}

func TestPreflight_NodeErrorsAreNotPasses(t *testing.T) {
	down := errors.New("connection reset")
	for _, name := range []string{"compose.project_containers", "compose.project_resources", "compose.docker_root", "compose.image_inspect", "compose.image_size", "compose.disk_free"} {
		t.Run(name, func(t *testing.T) {
			f := newPreflightFixture(t)
			f.node.down(name, down)
			if err := f.run(); !errors.Is(err, down) {
				t.Fatalf("runPreflight = %v, want the transport error", err)
			}
		})
	}
	t.Run("a read that exits non-zero", func(t *testing.T) {
		f := newPreflightFixture(t)
		f.node.exit("compose.docker_root", 1)
		wantPreflightCause(t, f.run(), causePreflightUnreadable)
	})
}

func mustRender(t *testing.T, name string, args map[string]string) templates.Command {
	t.Helper()
	c, err := templates.Render(name, args)
	if err != nil {
		t.Fatalf("Render %s: %v", name, err)
	}
	return c
}
