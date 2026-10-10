//go:build fixtures

package integration

import (
	"slices"
	"testing"

	"github.com/autarquico/supermgmt/internal/database"
	"github.com/autarquico/supermgmt/internal/discovery"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

func TestFixturesDiscovery_ProbeOfANodeBeforeSetupIsReadOnly(t *testing.T) {
	n := startNode(t, fixture.Options{})
	useAgent(t, n.ClientSigner)
	h := newHarness(t, defaultPoolConfig(), newIdentity(t))

	snap, err := discovery.Probe(t.Context(), h.pool.For(n.target(fixture.AdminUser)))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	snap.TakenAt = fixtureEpoch

	t.Run("the snapshot describes the Debian node", func(t *testing.T) {
		if snap.OS.ID != "debian" || snap.Kernel == "" || snap.Hostname == "" {
			t.Errorf("os/kernel/hostname = %+v %q %q; want a Debian host", snap.OS, snap.Kernel, snap.Hostname)
		}
		if !snap.Systemd.Active || snap.Systemd.SystemctlPath == "" || snap.Systemd.Version == "" {
			t.Errorf("systemd = %+v; want active with a path and version", snap.Systemd)
		}
		if snap.CPU.Cores < 1 || !snap.CPU.UsageKnown {
			t.Errorf("cpu = %+v; want cores and a usage from two samples", snap.CPU)
		}
		if snap.Memory.TotalKB == 0 || snap.Disk.TotalKB == 0 || snap.Uptime == 0 {
			t.Errorf("memory/disk/uptime = %+v %+v %v; want all known", snap.Memory, snap.Disk, snap.Uptime)
		}
		if !slices.Contains(snap.PackageManagers, "apt-get") {
			t.Errorf("package managers = %v; want apt-get", snap.PackageManagers)
		}
		if !snap.PasswordlessSudo {
			t.Error("the bootstrap admin has passwordless sudo")
		}
		if !slices.ContainsFunc(snap.Addresses, func(a discovery.Address) bool { return a.Scope == "loopback" }) {
			t.Errorf("addresses = %v; want a loopback address", snap.Addresses)
		}
	})

	t.Run("the probing user is admin and no setup exists yet", func(t *testing.T) {
		if snap.Probed.User != fixture.AdminUser || snap.Probed.HomeExists || snap.Probed.MarkersWritable {
			t.Errorf("probed = %+v; want admin, no supermgmt home, no markers", snap.Probed)
		}
	})

	t.Run("docker is installed but not reachable for a user outside the docker group", func(t *testing.T) {
		if snap.Docker.Path == "" || snap.Docker.Reachable() {
			t.Errorf("docker = %+v; want the binary found and the daemon not reachable", snap.Docker)
		}
	})

	t.Run("read capabilities are advertised and mutating ones are not", func(t *testing.T) {
		caps := discovery.Capabilities(snap, false)
		for name, want := range map[string]bool{
			"node.read": true, "node.metrics": true, "node.ssh": true, "service.read": true, "service.logs": true,
			"docker.read": false, "service.start": false, "service.stop": false, "service.restart": false,
		} {
			if got := capability(t, caps, name); got.Available != want {
				t.Errorf("%s available = %v; want %v", name, got.Available, want)
			}
		}
	})

	t.Run("the local provider never advertises ssh", func(t *testing.T) {
		caps := discovery.Capabilities(snap, true)
		if capability(t, caps, "node.ssh").Available || capability(t, caps, "node.exec.template").Available {
			t.Error("a local node must not report ssh capabilities")
		}
	})
}

func TestFixturesDiscovery_SetupSwitchesTheNodeToTheDedicatedUser(t *testing.T) {
	p := provision(t, fixture.Options{DemoContainer: true}, nil)
	before, err := discovery.Probe(t.Context(), p.admin)
	if err != nil {
		t.Fatalf("probe as admin: %v", err)
	}
	after, err := discovery.Probe(t.Context(), p.super)
	if err != nil {
		t.Fatalf("probe as supermgmt: %v", err)
	}

	if before.Probed.User != "admin" || after.Probed.User != dedicatedUser {
		t.Errorf("probed users = %q then %q; want admin then supermgmt", before.Probed.User, after.Probed.User)
	}
	if after.PasswordlessSudo {
		t.Error("supermgmt must not have general passwordless sudo")
	}

	t.Run("mutating capabilities appear only once the setup metadata is attached", func(t *testing.T) {
		after.TakenAt = fixtureEpoch
		without := discovery.Capabilities(after, false)
		for _, name := range []string{"service.start", "service.stop", "service.restart"} {
			if capability(t, without, name).Available {
				t.Errorf("%s available without node.setup", name)
			}
		}
		after.Setup = &p.meta
		with := discovery.Capabilities(after, false)
		for _, name := range []string{"service.start", "service.stop", "service.restart"} {
			c := capability(t, with, name)
			if !c.Available || !metadataUnits(c).contains(demoUnit) {
				t.Errorf("%s = %+v; want available for %s", name, c, demoUnit)
			}
			if c.Metadata["containers"] != false {
				t.Errorf("%s containers = %v; docker_access was not requested", name, c.Metadata["containers"])
			}
		}
	})
}

type units []string

func (u units) contains(unit string) bool { return slices.Contains(u, unit) }

func metadataUnits(c database.NodeCapability) units {
	got, _ := c.Metadata["units"].([]string)
	return got
}
