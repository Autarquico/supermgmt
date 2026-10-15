package templates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var tunnelPaths = []string{CloudflareKeyringPath, CloudflaredSourcePath, CloudflaredTokenPath, CloudflaredUnitPath}

func TestTunnelFilesAreStagedAndCommittedAsRootThroughBothVariants(t *testing.T) {
	for _, suffix := range []string{"", SudoVariantSuffix} {
		for _, path := range tunnelPaths {
			mode := "0644"
			if path == CloudflaredTokenPath {
				mode = "0600"
			}
			stage, err := RenderSetup("setup.file_stage"+suffix, map[string]string{"mode": mode, "owner": "root", "group": "root", "path": StagingPath(path)}, []byte("x"))
			if err != nil {
				t.Errorf("stage %s%s: %v", path, suffix, err)
				continue
			}
			if suffix != "" && !strings.HasPrefix(stage.Line, "sudo -n install ") {
				t.Errorf("sudo variant = %s", stage.Line)
			}
			if _, err := RenderSetup("setup.file_commit"+suffix, map[string]string{"from": StagingPath(path), "to": path}, nil); err != nil {
				t.Errorf("commit %s%s: %v", path, suffix, err)
			}
			if _, err := RenderSetup("setup.file_discard"+suffix, map[string]string{"path": StagingPath(path)}, nil); err != nil {
				t.Errorf("discard %s%s: %v", path, suffix, err)
			}
		}
	}
	for _, dir := range []string{CloudflaredDir, AptKeyringDir} {
		if _, err := RenderSetup("setup.dir", map[string]string{"mode": "0700", "owner": "root", "group": "root", "path": dir}, nil); err != nil {
			t.Errorf("dir %s: %v", dir, err)
		}
	}
	for _, bad := range []string{
		"/etc/apt/sources.list", "/etc/apt/sources.list.d/other.list", "/etc/apt/keyrings/other.gpg",
		"/etc/supermgmt/cloudflared/other", "/etc/systemd/system/ssh.service", "/etc/supermgmt/cloudflared/token/../../x",
	} {
		if _, err := RenderSetup("setup.file_stage", map[string]string{"mode": "0644", "owner": "root", "group": "root", "path": StagingPath(bad)}, nil); err == nil {
			t.Errorf("staging %s accepted", bad)
		}
		if _, err := RenderSetup("setup.file_commit", map[string]string{"from": StagingPath(bad), "to": bad}, nil); err == nil {
			t.Errorf("commit %s accepted", bad)
		}
	}
}

func TestTunnelRemovalAndHashStepsTouchOnlyTunnelPaths(t *testing.T) {
	notTunnel := []string{SudoersPath, TmpfilesPath, BrokerPath, "/etc/passwd", "/etc", CloudflaredDir, StagingPath(CloudflaredTokenPath), AuthorizedKeysPath}
	for _, name := range []string{"setup.file_remove", "setup.file_sha256"} {
		for _, suffix := range []string{"", SudoVariantSuffix} {
			for _, path := range tunnelPaths {
				if _, err := RenderSetup(name+suffix, map[string]string{"path": path}, nil); err != nil {
					t.Errorf("%s%s %s: %v", name, suffix, path, err)
				}
			}
			for _, bad := range notTunnel {
				if _, err := RenderSetup(name+suffix, map[string]string{"path": bad}, nil); err == nil {
					t.Errorf("%s%s accepted %s", name, suffix, bad)
				}
			}
		}
	}
	rm, err := RenderSetup("setup.dir_remove", map[string]string{"path": CloudflaredDir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rm.Line, "rm ") || !strings.Contains(rm.Line, "rmdir") {
		t.Errorf("directory removal must be rmdir only: %s", rm.Line)
	}
	for _, bad := range []string{BrokerConfigDir, AptKeyringDir, "/etc", HomeDir, CloudflaredTokenPath} {
		if _, err := RenderSetup("setup.dir_remove", map[string]string{"path": bad}, nil); err == nil {
			t.Errorf("dir_remove accepted %s", bad)
		}
	}
}

func TestTunnelUnitStepsAcceptOnlyTheSuperMgmtUnit(t *testing.T) {
	for _, name := range []string{"setup.tunnel_enable", "setup.tunnel_restart", "setup.tunnel_disable"} {
		if _, err := RenderSetup(name, map[string]string{"unit": CloudflaredUnitName}, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		for _, bad := range []string{"cloudflared.service", "ssh.service", "supermgmt-cloudflared", "x.service; id"} {
			if _, err := RenderSetup(name, map[string]string{"unit": bad}, nil); err == nil {
				t.Errorf("%s accepted %s", name, bad)
			}
		}
	}
}

func TestTunnelAptStepsRenderOneFixedCommandEach(t *testing.T) {
	want := map[string]string{
		"setup.apt_install_cloudflared": "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=60 cloudflared",
		"setup.apt_remove_cloudflared":  "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get remove -y -o DPkg::Lock::Timeout=60 cloudflared",
		"setup.daemon_reload":           "sudo -n systemctl daemon-reload",
	}
	for name, line := range want {
		c, err := RenderSetup(name+SudoVariantSuffix, nil, nil)
		if err != nil || c.Line != line {
			t.Errorf("%s = %q, %v", name, c.Line, err)
		}
		if _, err := RenderSetup(name, map[string]string{"extra": "x"}, nil); err == nil {
			t.Errorf("%s accepted an argument", name)
		}
	}
	update, err := RenderSetup("setup.apt_update_cloudflared", nil, nil)
	if err != nil || !strings.Contains(update.Line, "Dir::Etc::sourcelist=sources.list.d/cloudflared.list") || !strings.Contains(update.Line, "Dir::Etc::sourceparts=-") {
		t.Errorf("update = %q, %v", update.Line, err)
	}
}

func TestTunnelReadsAreUnprivilegedAndTakeNoArguments(t *testing.T) {
	for name, want := range map[string]string{
		"setup.os_release":          `sh -c '. /etc/os-release && printf "%s %s\n" "$ID" "$VERSION_CODENAME"'`,
		"setup.cloudflared_package": `dpkg-query -W -f='${db:Status-Abbrev} ${Version}\n' cloudflared`,
	} {
		c, err := Render(name, nil)
		if err != nil || c.Line != want {
			t.Errorf("%s = %q, %v", name, c.Line, err)
		}
	}
}

// TestFileHashStepReportsAbsenceAndNeverTheContent runs the rendered step with
// the path swapped for a temp file: exit 3 when absent, only the digest when present.
func TestFileHashStepReportsAbsenceAndNeverTheContent(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is not installed (the step runs on Debian and Ubuntu nodes)")
	}
	c, err := RenderSetup("setup.file_sha256", map[string]string{"path": CloudflaredTokenPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	script := strings.Replace(c.Line, Quote(CloudflaredTokenPath), `"$TARGET"`, 1)
	file := filepath.Join(t.TempDir(), "token")
	run := func() (string, int) {
		cmd := exec.CommandContext(t.Context(), "sh", "-c", script)
		cmd.Env = append(os.Environ(), "TARGET="+file)
		out, runErr := cmd.Output()
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			return string(out), exit.ExitCode()
		}
		return string(out), 0
	}
	if out, code := run(); code != 3 || out != "" {
		t.Errorf("absent file: exit %d, output %q", code, out)
	}
	if err := os.WriteFile(file, []byte("secret-content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run()
	if code != 0 || strings.Contains(out, "secret-content") || len(strings.Fields(out)[0]) != 64 {
		t.Errorf("present file: exit %d, output %q", code, out)
	}
}
