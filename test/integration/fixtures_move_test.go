//go:build fixtures

package integration

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// The gate of app-move: docker cp between the created, never-started
// containers of two nodes carries a named volume with everything a manifest
// checks. Both nodes get the same project; A also ran and was stopped, as a
// moved app would have.

const (
	moveProject    = "mvgate"
	moveDeployment = "018f0000-0000-7000-8000-0000000000c1"
	moveContainer  = moveProject + "-web-1"
	moveImage      = "sm-move-seed:1"
	// moveDataMount is directly under the root; moveStateMount is nested.
	moveDataMount  = "/data"
	moveStateMount = "/srv/app/state"
	moveSeedScript = `set -e
mkdir -p /seed && cd /seed
cat > Dockerfile <<'EOF'
FROM ` + busyboxImage + `
RUN mkdir -p /data/imgdir /srv/app/state/deep \
 && echo image-seed > /data/seed.txt \
 && echo inner > /data/imgdir/inner && chown 1234:5678 /data/imgdir/inner && chmod 640 /data/imgdir/inner \
 && echo state-seed > /srv/app/state/deep/seed && chown 33:33 /srv/app/state/deep && chmod 0750 /srv/app/state/deep
EOF
docker pull -q ` + busyboxImage + ` >/dev/null
docker build -q -t ` + moveImage + ` . >/dev/null`
	moveCompose = `services:
  web:
    image: ` + moveImage + `
    command: ["sleep", "infinity"]
    volumes:
      - data:` + moveDataMount + `
      - state:` + moveStateMount + `
volumes:
  data: {}
  state: {}
`
	// moveWriteScript fills A's volumes with what a real app leaves behind.
	moveWriteScript = `set -e
cd /data
mkdir -p tree/a/b empty "dir with space"
echo hi > tree/a/b/f
printf secret > secret.env && chown 1000:1000 secret.env && chmod 600 secret.env
ln -s tree/a/b/f rel-link; ln -s /etc/passwd abs-link; ln -s missing dangling
ln tree/a/b/f tree/hard
chmod 2775 empty && chown 1000:2000 empty
head -c 3000000 /dev/urandom > big.bin
echo u > "dir with space/ünï ¢.txt"
touch -d 2001-02-03 old.txt
mkfifo pipe
echo changed-on-a > seed.txt && chmod 600 seed.txt
chown 4321:8765 imgdir/inner
cd /srv/app/state
mkdir -p a/b/c && echo nested > a/b/c/n.txt && chown -R 1000:1000 a && chmod 600 a/b/c/n.txt
echo top > top.txt && chmod 0400 top.txt && chown 65534:65534 top.txt`
)

type moveNodes struct{ a, b *deployNode }

// startMoveNodes starts two provisioned nodes, each with the seed image, the
// project's compose.yaml materialized and its containers created.
func startMoveNodes(t *testing.T) moveNodes {
	t.Helper()
	m := moveNodes{a: startDeployNode(t), b: startDeployNode(t)}
	for _, n := range []*deployNode{m.a, m.b} {
		n.shell(t, moveSeedScript)
		n.adoptProject(t, moveProject)
		if res := n.materialize(t, deployDirArgs(moveProject, moveDeployment), composeOnly(moveCompose)); res.ExitStatus != 0 {
			t.Fatalf("materialize: %s", stderrOf(res))
		}
		n.composeCreate(t)
	}
	return m
}

func (n *deployNode) composeCreate(t *testing.T) {
	t.Helper()
	if res, _ := n.mutate(t, "compose.create", deployDirArgs(moveProject, moveDeployment), nil, moveProject); res.ExitStatus != 0 {
		t.Fatalf("compose.create: %s %s", res.Stdout, stderrOf(res))
	}
}

func (n *deployNode) compose(t *testing.T, verb string) {
	t.Helper()
	if res, _ := n.mutate(t, "compose."+verb, deployDirArgs(moveProject, moveDeployment), nil, moveProject); res.ExitStatus != 0 {
		t.Fatalf("compose.%s: %s %s", verb, res.Stdout, stderrOf(res))
	}
}

func (n *deployNode) volumeShell(t *testing.T, script string) string {
	t.Helper()
	return n.shell(t, fmt.Sprintf("docker run --rm -v %[1]s_data:%[2]s -v %[1]s_state:%[3]s %[4]s sh -c '%[5]s'",
		moveProject, moveDataMount, moveStateMount, busyboxImage, strings.ReplaceAll(script, "'", `'\''`)))
}

var moveOptions = transport.StreamOptions{Total: 5 * time.Minute, Idle: time.Minute, Ceiling: 1 << 30}

func (n *deployNode) openVolume(t *testing.T, ctx context.Context, template, mount string) transport.Stream {
	t.Helper()
	cmd, err := templates.RenderStream(template, map[string]string{
		"container": moveContainer, "mount": mount, "deadline": templates.DeadlineArg(4 * time.Minute),
	})
	if err != nil {
		t.Fatalf("render %s: %v", template, err)
	}
	st, err := n.h.pool.OpenStream(ctx, n.superTarget(), cmd, moveOptions)
	if err != nil {
		t.Fatalf("open %s: %v", template, err)
	}
	return st
}

// manifestOfExport exports the mount and reads its manifest.
func (n *deployNode) manifestOfExport(t *testing.T, mount string) transport.Manifest {
	t.Helper()
	st := n.openVolume(t, t.Context(), "docker.volume_export", mount)
	m, err := transport.TarManifest(st)
	if err != nil {
		st.Abort()
		_, _, _ = st.Wait()
		t.Fatalf("manifest of %s: %v", mount, err)
	}
	if exit, tail, err := st.Wait(); exit != 0 || err != nil {
		t.Fatalf("export of %s: exit %d %q %v", mount, exit, tail, err)
	}
	return m
}

// rawExport reads the whole tar of the mount.
func (n *deployNode) rawExport(t *testing.T, mount string) []byte {
	t.Helper()
	st := n.openVolume(t, t.Context(), "docker.volume_export", mount)
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(st); err != nil {
		t.Fatal(err)
	}
	if exit, tail, err := st.Wait(); exit != 0 || err != nil {
		t.Fatalf("export of %s: exit %d %q %v", mount, exit, tail, err)
	}
	return buf.Bytes()
}

func copyVolume(t *testing.T, from, to *deployNode, mount string) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	exp := from.openVolume(t, ctx, "docker.volume_export", mount)
	imp := to.openVolume(t, ctx, "docker.volume_import", mount)
	n, err := transport.CopyVolume(ctx, exp, imp, moveOptions.Ceiling)
	if err != nil {
		t.Fatalf("copy %s: %v", mount, err)
	}
	return n
}

func entryOf(t *testing.T, m transport.Manifest, path string) transport.ManifestEntry {
	t.Helper()
	for _, e := range m.Entries {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("manifest lacks %q; has %d entries", path, m.Count)
	return transport.ManifestEntry{}
}

func sameManifest(t *testing.T, what string, a, b transport.Manifest) {
	t.Helper()
	if a.Digest == b.Digest {
		return
	}
	for _, ea := range a.Entries {
		found := false
		for _, eb := range b.Entries {
			if ea == eb {
				found = true
			}
		}
		if !found {
			t.Logf("%s: only on A (or different): %+v", what, ea)
		}
	}
	for _, eb := range b.Entries {
		if !slices.Contains(a.Entries, eb) {
			t.Logf("%s: only on B (or different): %+v", what, eb)
		}
	}
	t.Fatalf("%s: manifests differ (A %d entries %s, B %d entries %s)", what, a.Count, a.Digest, b.Count, b.Digest)
}

func TestFixtures_MoveCopiesNamedVolumesBetweenCreatedContainers(t *testing.T) {
	m := startMoveNodes(t)

	// A runs, its app writes, and it is stopped: the state a move starts from.
	m.a.compose(t, "start")
	m.a.volumeShell(t, moveWriteScript)
	m.a.compose(t, "stop")
	if got := m.a.shell(t, "docker inspect -f '{{.State.Status}}' "+moveContainer); got != "exited" {
		t.Fatalf("A's container is %q, want exited", got)
	}
	if got := m.b.shell(t, "docker inspect -f '{{.State.Status}}' "+moveContainer); got != "created" {
		t.Fatalf("B's container is %q, want created and never started", got)
	}

	wantA := map[string]transport.Manifest{}
	for _, mount := range []string{moveDataMount, moveStateMount} {
		wantA[mount] = m.a.manifestOfExport(t, mount)
	}
	t.Run("A's export holds what the app left, with numeric owners", func(t *testing.T) {
		data, state := wantA[moveDataMount], wantA[moveStateMount]
		for path, want := range map[string]transport.ManifestEntry{
			"seed.txt":                 {Type: "file", UID: 0, GID: 0, Mode: 0o600},
			"imgdir/inner":             {Type: "file", UID: 4321, GID: 8765, Mode: 0o640},
			"secret.env":               {Type: "file", UID: 1000, GID: 1000, Mode: 0o600},
			"rel-link":                 {Type: "symlink", Link: "tree/a/b/f"},
			"abs-link":                 {Type: "symlink", Link: "/etc/passwd"},
			"dangling":                 {Type: "symlink", Link: "missing"},
			"empty":                    {Type: "dir", UID: 1000, GID: 2000, Mode: 0o2775},
			"tree/hard":                {Type: "hardlink", Link: "tree/a/b/f"},
			"pipe":                     {Type: "fifo"},
			"dir with space/ünï ¢.txt": {Type: "file"},
		} {
			got := entryOf(t, data, path)
			if got.Type != want.Type || got.UID != want.UID || got.GID != want.GID || got.Link != want.Link || (want.Mode != 0 && got.Mode != want.Mode) {
				t.Errorf("%s = %+v, want %+v", path, got, want)
			}
		}
		for path, want := range map[string]transport.ManifestEntry{
			"deep/seed":   {Type: "file"},
			"deep":        {Type: "dir", UID: 33, GID: 33, Mode: 0o750},
			"a/b/c/n.txt": {Type: "file", UID: 1000, GID: 1000, Mode: 0o600},
			"top.txt":     {Type: "file", UID: 65534, GID: 65534, Mode: 0o400},
		} {
			got := entryOf(t, state, path)
			if got.Type != want.Type || got.UID != want.UID || got.GID != want.GID || (want.Mode != 0 && got.Mode != want.Mode) {
				t.Errorf("%s = %+v, want %+v", path, got, want)
			}
		}
		if data.Bytes < 3_000_000 {
			t.Errorf("A's data export holds %d bytes", data.Bytes)
		}
	})

	t.Run("archive shape of docker cp", func(t *testing.T) {
		for _, mount := range []string{moveDataMount, moveStateMount} {
			raw := m.a.rawExport(t, mount)
			first := strings.Join(firstNames(t, raw, 4), " | ")
			t.Logf("docker cp %s/. - starts with: %s", mount, first)
		}
	})

	for _, mount := range []string{moveDataMount, moveStateMount} {
		t.Run("first copy "+mount, func(t *testing.T) {
			n := copyVolume(t, m.a, m.b, mount)
			t.Logf("copied %d bytes of %s", n, mount)
			sameManifest(t, mount, wantA[mount], m.b.manifestOfExport(t, mount))
		})
	}
	if t.Failed() {
		return
	}

	t.Run("B's containers were never started", func(t *testing.T) {
		if got := m.b.shell(t, "docker inspect -f '{{.State.Status}}' "+moveContainer); got != "created" {
			t.Errorf("B's container is %q", got)
		}
		if got := m.a.shell(t, "docker volume ls -q"); !strings.Contains(got, moveProject+"_data") {
			t.Errorf("A lost its volume: %q", got)
		}
	})

	t.Run("a second import merges, which is why a retry replaces the volume", func(t *testing.T) {
		m.b.volumeShell(t, "echo stray > /data/stray.txt")
		stray := m.b.manifestOfExport(t, moveDataMount)
		if stray.Digest == wantA[moveDataMount].Digest {
			t.Fatal("a stray file did not change B's manifest")
		}
		copyVolume(t, m.a, m.b, moveDataMount)
		merged := m.b.manifestOfExport(t, moveDataMount)
		hasStray := slices.ContainsFunc(merged.Entries, func(e transport.ManifestEntry) bool { return e.Path == "stray.txt" })
		t.Logf("after importing over a volume with a stray file, the stray file survives: %v", hasStray)
		if merged.Digest == wantA[moveDataMount].Digest {
			t.Error("an import over a dirty volume replaced it; the design assumed it merges")
		}
	})

	t.Run("replacement: down, remove the volumes, create, copy again", func(t *testing.T) {
		m.b.compose(t, "down")
		for _, volume := range []string{moveProject + "_data", moveProject + "_state"} {
			res, _ := m.b.mutate(t, "docker.volume_rm", map[string]string{"volume": volume}, nil, "")
			if res.ExitStatus != 0 {
				t.Fatalf("volume_rm %s: %s", volume, stderrOf(res))
			}
		}
		if got := m.b.shell(t, "docker volume ls -q"); strings.Contains(got, moveProject) {
			t.Fatalf("B still has volumes: %q", got)
		}
		m.b.composeCreate(t)
		for _, mount := range []string{moveDataMount, moveStateMount} {
			if empty := m.b.manifestOfExport(t, mount); empty.Digest == wantA[mount].Digest {
				t.Fatalf("a fresh volume at %s already equals A's", mount)
			}
			copyVolume(t, m.a, m.b, mount)
			sameManifest(t, "replaced "+mount, wantA[mount], m.b.manifestOfExport(t, mount))
		}
	})

	t.Run("the new reads decode on a node with a project", func(t *testing.T) {
		read := func(name string, args map[string]string) []byte {
			res := m.b.readTemplate(t, name, args)
			if res.ExitStatus != 0 {
				t.Fatalf("%s exit %d: %s", name, res.ExitStatus, stderrOf(res))
			}
			return res.Stdout
		}
		info, err := templates.ParseInfoResources(read("docker.info_resources", nil))
		if err != nil || info.NCPU < 1 || info.MemTotal < 1<<28 {
			t.Errorf("info = %+v, %v", info, err)
		}
		sizes, err := templates.ParseVolumeSizes(read("docker.volume_sizes", nil))
		if err != nil || sizes[moveProject+"_data"] < 3_000_000 || sizes[moveProject+"_state"] == 0 {
			t.Errorf("sizes = %v, %v", sizes, err)
		}
		volumes, err := templates.ParseVolumeInspectMany(read("docker.volume_inspect_many",
			map[string]string{"volumes": moveProject + "_data,nope," + moveProject + "_state"}))
		if err != nil || len(volumes) != 2 || volumes[0].Labels["com.docker.compose.project"] != moveProject {
			t.Errorf("volumes = %+v, %v", volumes, err)
		}
		none, err := templates.ParseVolumeInspectMany(read("docker.volume_inspect_many", map[string]string{"volumes": "nope"}))
		if err != nil || len(none) != 0 {
			t.Errorf("absent volume = %+v, %v", none, err)
		}
		states, err := templates.ParsePsState(read("compose.ps_state", map[string]string{"project": moveProject}), moveProject)
		if err != nil || len(states) != 1 || states[0].State != "created" || states[0].Service != "web" || states[0].Name != moveContainer {
			t.Errorf("states = %+v, %v", states, err)
		}
		m.a.compose(t, "start")
		m.a.compose(t, "stop")
		states, err = templates.ParsePsState(m.a.readTemplate(t, "compose.ps_state", map[string]string{"project": moveProject}).Stdout, moveProject)
		if err != nil || len(states) != 1 || states[0].State != "exited" {
			t.Errorf("A after stop = %+v, %v", states, err)
		}
	})
}

// firstNames lists the first n member names of a tar.
func firstNames(t *testing.T, raw []byte, n int) []string {
	t.Helper()
	var names []string
	for off := 0; off+512 <= len(raw) && len(names) < n; {
		name := strings.TrimRight(string(raw[off:off+100]), "\x00")
		if name == "" {
			break
		}
		names = append(names, name)
		var size int
		if _, err := fmt.Sscanf(strings.TrimRight(string(raw[off+124:off+136]), "\x00 "), "%o", &size); err != nil {
			t.Fatalf("tar header of %s: %v", name, err)
		}
		off += 512 + (size+511)/512*512
	}
	return names
}
