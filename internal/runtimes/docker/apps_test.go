package docker

import (
	"context"
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const statsOut = `{"ID":"aaaa","Name":"shop-web-1","CPUPerc":"0.50%","MemUsage":"1.5MiB / 2GiB","MemPerc":"0.07%"}
{"ID":"bbbb","Name":"shop-db-1","CPUPerc":"12.25%","MemUsage":"512kB / 1GB"}
{"ID":"cccc","Name":"starting","CPUPerc":"--","MemUsage":"0B / 0B"}
`

func TestStatsReadsCPUAndMemoryPerContainer(t *testing.T) {
	stats, err := New().Stats(context.Background(), newFakeNode(t).reply("docker.stats", statsOut))
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	if w := stats[0]; w.Name != "shop-web-1" || w.CPUPercent != 0.5 || w.MemUsedBytes != 1572864 || w.MemLimitBytes != 2<<30 {
		t.Errorf("web = %+v", w)
	}
	if d := stats[1]; d.CPUPercent != 12.25 || d.MemUsedBytes != 512000 || d.MemLimitBytes != 1e9 {
		t.Errorf("db = %+v", d)
	}
}

func TestStatsWithoutJSONSupportIsCapabilityUnavailable(t *testing.T) {
	for name, node := range map[string]*fakeNode{
		"old docker prints the word json": newFakeNode(t).reply("docker.stats", "json\njson\n"),
		"docker rejects the flag":         newFakeNode(t).fail("docker.stats", 125),
	} {
		_, err := New().Stats(context.Background(), node)
		if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestStatsOfNoContainersIsEmpty(t *testing.T) {
	stats, err := New().Stats(context.Background(), newFakeNode(t).reply("docker.stats", ""))
	if err != nil || len(stats) != 0 {
		t.Errorf("stats = %+v, %v", stats, err)
	}
}

func TestLogsSinceAsksForTheCursorInUTC(t *testing.T) {
	node := newFakeNode(t).reply("docker.logs_since", "2026-11-09T10:00:00.5Z hello\n")
	since := time.Date(2026, 11, 9, 11, 0, 0, 500_000_000, time.FixedZone("CET", 3600))
	chunk, err := New().LogsSince(context.Background(), node, ref("web"), since, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunk.Lines) != 1 || node.calls[0].Line != "docker logs --timestamps --since '2026-11-09T10:00:00.5Z' --tail '100' -- 'web' 2>&1" {
		t.Errorf("lines = %v, call = %s", chunk.Lines, node.calls[0].Line)
	}
	if _, err := New().LogsSince(context.Background(), node, ref("web"), since, 0); smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Errorf("zero lines: %v", err)
	}
}

const inspectDetail = `[{"Id":"aaaa","Name":"/shop-web-1","Image":"sha256:1","RestartCount":3,
 "Config":{"Image":"nginx","Labels":{"com.docker.compose.project":"shop"},"Env":["A=1","B=x\u001b[31m"],"Cmd":["nginx","-g","daemon off;"],"Entrypoint":null},
 "HostConfig":{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":5}},
 "Mounts":[{"Type":"volume","Name":"data","Source":"/var/lib/docker/volumes/data/_data","Destination":"/data","RW":true},
           {"Type":"bind","Source":"/srv/conf","Destination":"/etc/conf","RW":false}],
 "State":{"Status":"running","Running":true,"StartedAt":"2026-11-09T10:00:00Z","Health":{"Status":"unhealthy"}},
 "NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}}}]`

func TestDetailsReadRestartsMountsAndConfiguration(t *testing.T) {
	all, err := New().Details(context.Background(), newFakeNode(t).reply("docker.inspect_all", inspectDetail))
	if err != nil || len(all) != 1 {
		t.Fatalf("all = %+v, %v", all, err)
	}
	d := all[0]
	if d.Project != "shop" || d.Name != "shop-web-1" || d.Health != "unhealthy" || d.RestartCount != 3 {
		t.Errorf("detail = %+v", d)
	}
	if d.RestartPolicy != "on-failure" || d.RestartMaxRetries != 5 {
		t.Errorf("policy = %q/%d", d.RestartPolicy, d.RestartMaxRetries)
	}
	if len(d.Mounts) != 2 || d.Mounts[0].Name != "data" || !d.Mounts[0].ReadWrite || d.Mounts[1].ReadWrite || d.Mounts[1].Source != "/srv/conf" {
		t.Errorf("mounts = %+v", d.Mounts)
	}
	if len(d.Env) != 2 || d.Env[0] != "A=1" || strings.ContainsRune(d.Env[1], 0x1b) {
		t.Errorf("env = %q", d.Env)
	}
	if len(d.Cmd) != 3 || d.Entrypoint != nil || len(d.Ports) != 1 {
		t.Errorf("cmd = %q entrypoint = %q ports = %q", d.Cmd, d.Entrypoint, d.Ports)
	}
}
