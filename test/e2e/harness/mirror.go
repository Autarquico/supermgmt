//go:build e2e

package harness

import (
	"os"
	"path/filepath"
	"testing"
)

// MirrorHost is the DNS name of the release mirror on the docker network.
const MirrorHost = "releases.test"

// Mirror serves release trees over HTTPS from a container (the stand-in for GitHub Releases and
// raw.githubusercontent.com, selected with SUPERMGMT_RELEASE_BASE_URL).
type Mirror struct {
	C  *Container
	CA *CA
	t  testing.TB
}

// StartMirror runs the file server on the network under the name releases.test.
func StartMirror(t testing.TB, net *Network, ca *CA) *Mirror {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := ca.Issue(t, []string{MirrorHost}, nil).WriteTo(t, dir, "mirror")
	_ = os.Chmod(keyPath, 0o644)
	c := Start(t, RunOptions{
		Image: Image(t), Network: net.Name, Aliases: []string{MirrorHost},
		Cmd:   []string{"/e2etool", "files", "-listen", ":443", "-dir", "/srv", "-cert", "/mirror.crt", "-key", "/mirror.key"},
		Files: map[string]string{"/e2etool": Tool(t), "/mirror.crt": certPath, "/mirror.key": keyPath},
	})
	return &Mirror{C: c, CA: ca, t: t}
}

// Publish makes a host directory available at BaseURL(name).
func (m *Mirror) Publish(name, hostDir string) {
	m.t.Helper()
	MustDocker(m.t, "cp", hostDir+string(filepath.Separator)+".", m.C.Name+":/srv/"+name)
}

// PublishFile makes one file available at BaseURL(name)/<file name>.
func (m *Mirror) PublishFile(name, hostFile string) {
	m.t.Helper()
	MustDocker(m.t, "cp", hostFile, m.C.Name+":/srv/"+name+"/"+filepath.Base(hostFile))
}

// BaseURL is the SUPERMGMT_RELEASE_BASE_URL of a published tree.
func (m *Mirror) BaseURL(name string) string { return "https://" + MirrorHost + "/" + name }
