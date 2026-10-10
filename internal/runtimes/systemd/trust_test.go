package systemd

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func execLine(program string, argv ...string) string {
	return fmt.Sprintf("{ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }", program, strings.Join(argv, " "))
}

// trustNode serves a unit's trust_show output and a filesystem where every
// path is root:root 0755 except those in badModes (path -> "uid mode").
func trustNode(t *testing.T, show string, badModes map[string]string, shebang map[string]bool) *fakeNode {
	return newFakeNode(t).
		reply("systemd.trust_show", show).
		on("systemd.path_chain", func(c templates.Command) transport.Result {
			p := strings.Trim(strings.SplitN(c.Line, "'", 3)[1], "'")
			var out strings.Builder
			for ; ; p = path.Dir(p) {
				state := "0 755"
				if bad, ok := badModes[p]; ok {
					state = bad
				}
				fmt.Fprintf(&out, "%s %s\n", state, p)
				if p == "/" {
					break
				}
			}
			return transport.Result{Stdout: []byte(out.String())}
		}).
		on("systemd.file_magic", func(c templates.Command) transport.Result {
			p := strings.Trim(strings.SplitN(c.Line, "'", 3)[1], "'")
			if shebang[p] {
				return transport.Result{Stdout: []byte("#!")}
			}
			return transport.Result{Stdout: []byte("\x7fE")}
		})
}

func goodShow(extra ...string) string {
	lines := append([]string{
		"LoadState=loaded",
		"FragmentPath=/etc/systemd/system/app.service",
		"DropInPaths=/etc/systemd/system/app.service.d/override.conf",
		"ExecStart=" + execLine("/usr/local/bin/app", "/usr/local/bin/app", "--serve"),
		"User=app",
	}, extra...)
	return strings.Join(lines, "\n") + "\n"
}

func TestCheckTrustAcceptsARootOwnedUnit(t *testing.T) {
	node := trustNode(t, goodShow(
		"EnvironmentFiles=/etc/default/app (ignore_errors=no)",
		"WorkingDirectory=/srv/app",
		"ExecReload="+execLine("/bin/sh", "/bin/sh", "/opt/app/reload.sh", "now"),
	), nil, nil)
	if err := CheckTrust(context.Background(), node, "app.service"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/etc/systemd/system/app.service", "/usr/local/bin/app", "/etc/default/app", "/srv/app", "/opt/app/reload.sh"} {
		if !strings.Contains(node.lines(), "p='"+want+"'") {
			t.Errorf("%s was not inspected", want)
		}
	}
}

func TestCheckTrustRefusesWithTheFailingPath(t *testing.T) {
	tests := []struct {
		name    string
		show    string
		bad     map[string]string
		shebang map[string]bool
		wantIn  string
	}{
		{"unit file owned by a user", goodShow(), map[string]string{"/etc/systemd/system/app.service": "1000 644"}, nil, "/etc/systemd/system/app.service"},
		{"group-writable drop-in", goodShow(), map[string]string{"/etc/systemd/system/app.service.d/override.conf": "0 664"}, nil, "override.conf"},
		{"world-writable binary", goodShow(), map[string]string{"/usr/local/bin/app": "0 757"}, nil, "/usr/local/bin/app"},
		{"writable parent directory", goodShow(), map[string]string{"/usr/local/bin": "0 775"}, nil, "/usr/local/bin"},
		{"sticky world-writable parent", goodShow(), map[string]string{"/usr/local": "0 1777"}, nil, "/usr/local"},
		{"user-owned parent", goodShow(), map[string]string{"/usr": "1000 755"}, nil, "/usr"},
		{"environment file", goodShow("EnvironmentFiles=/etc/default/app (ignore_errors=no)"), map[string]string{"/etc/default/app": "1000 600"}, nil, "/etc/default/app"},
		{"working directory", goodShow("WorkingDirectory=/srv/app"), map[string]string{"/srv/app": "0 777"}, nil, "/srv/app"},
		{"interpreter script", goodShow("ExecStartPre=" + execLine("/usr/bin/python3", "/usr/bin/python3", "/srv/app/pre.py")), map[string]string{"/srv/app/pre.py": "1000 755"}, nil, "/srv/app/pre.py"},
		{
			"shebang script argument", goodShow(),
			map[string]string{"/srv/data/x.conf": "1000 644"},
			map[string]bool{"/usr/local/bin/app": true},
			"/srv/data/x.conf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			show := tt.show
			if tt.shebang != nil {
				show = goodShow("ExecStop=" + execLine("/usr/local/bin/app", "/usr/local/bin/app", "/srv/data/x.conf"))
			}
			err := CheckTrust(context.Background(), trustNode(t, show, tt.bad, tt.shebang), "app.service")
			assertNotEligible(t, err, tt.wantIn)
		})
	}
}

func TestCheckTrustRefusesWhatItCannotResolve(t *testing.T) {
	tests := map[string]string{
		"not loaded":               "LoadState=not-found\n",
		"no unit file":             "LoadState=loaded\nFragmentPath=\n",
		"sh -c inline code":        goodShow("ExecStartPre=" + execLine("/bin/sh", "/bin/sh", "-c", "touch")),
		"combined -lc":             goodShow("ExecStartPre=" + execLine("/bin/bash", "/bin/bash", "-lc", "x")),
		"python -m module":         goodShow("ExecStartPre=" + execLine("/usr/bin/python3", "/usr/bin/python3", "-m", "http.server")),
		"perl -e":                  goodShow("ExecStartPre=" + execLine("/usr/bin/perl", "/usr/bin/perl", "-e", "1")),
		"interpreter without file": goodShow("ExecStartPre=" + execLine("/bin/dash", "/bin/dash")),
		"relative script":          goodShow("ExecStartPre=" + execLine("/bin/sh", "/bin/sh", "run.sh")),
		"script with variable":     goodShow("ExecStartPre=" + execLine("/bin/sh", "/bin/sh", "/opt/$NAME/run.sh")),
		"specifier in program":     goodShow("ExecStartPre=" + execLine("/opt/%n/run", "/opt/%n/run")),
		"program with space":       goodShow("ExecStartPre=" + execLine("/opt/my app/run", "/opt/my app/run")),
		"relative program":         goodShow("ExecStartPre=" + execLine("run", "run")),
		"env wrapper":              goodShow("ExecStartPre=" + execLine("/usr/bin/env", "/usr/bin/env", "python3", "/opt/x.py")),
		"unparseable Exec":         goodShow("ExecStartPre=garbage"),
		"unparseable environment":  goodShow("EnvironmentFiles=something odd"),
		"environment specifier":    goodShow("EnvironmentFiles=/etc/%i.env (ignore_errors=no)"),
		"drop-in with space":       "LoadState=loaded\nFragmentPath=/etc/a.service\nDropInPaths=/etc/a.service.d/x y.conf\n",
		"relative working dir":     goodShow("WorkingDirectory=app"),
	}
	for name, show := range tests {
		t.Run(name, func(t *testing.T) {
			assertNotEligible(t, CheckTrust(context.Background(), trustNode(t, show, nil, nil), "app.service"), "")
		})
	}
}

func TestCheckTrustToleratesAMissingIgnoredEnvironmentFile(t *testing.T) {
	node := trustNode(t, goodShow("EnvironmentFiles=/etc/default/app (ignore_errors=yes)"), nil, nil)
	inner := node.handlers["systemd.path_chain"]
	node.on("systemd.path_chain", func(c templates.Command) transport.Result {
		if strings.Contains(c.Line, "p='/etc/default/app';") {
			return transport.Result{ExitStatus: 1}
		}
		return inner(c)
	})
	if err := CheckTrust(context.Background(), node, "app.service"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(node.lines(), "p='/etc/default';") {
		t.Error("the parent of the missing file was not checked")
	}

	required := trustNode(t, goodShow("EnvironmentFiles=/etc/default/app (ignore_errors=no)"), nil, nil)
	required.on("systemd.path_chain", func(c templates.Command) transport.Result {
		if strings.Contains(c.Line, "p='/etc/default/app';") {
			return transport.Result{ExitStatus: 1}
		}
		return inner(c)
	})
	assertNotEligible(t, CheckTrust(context.Background(), required, "app.service"), "/etc/default/app")
}

func TestCheckTrustRefusesUnnamedUnitsWithoutTouchingTheNode(t *testing.T) {
	node := newFakeNode(t)
	assertNotEligible(t, CheckTrust(context.Background(), node, "a;b.service"), "")
	if len(node.calls) != 0 {
		t.Errorf("node was contacted: %v", node.ran())
	}
}

func TestPreflightIsTheTrustProfile(t *testing.T) {
	node := trustNode(t, goodShow(), map[string]string{"/usr/local/bin/app": "0 777"}, nil)
	assertNotEligible(t, New().Preflight(context.Background(), node, ref("app.service")), "/usr/local/bin/app")
	if err := New().Preflight(context.Background(), trustNode(t, goodShow(), nil, nil), ref("app.service")); err != nil {
		t.Fatal(err)
	}
}

func assertNotEligible(t *testing.T, err error, pathInMessage string) {
	t.Helper()
	if !errors.Is(err, smerr.FromReason(smerr.ReasonUnitNotEligible, "")) {
		t.Fatalf("got %v, want CAPABILITY_UNAVAILABLE/UNIT_NOT_ELIGIBLE", err)
	}
	if !strings.Contains(err.Error(), pathInMessage) {
		t.Errorf("error %q does not name %q", err, pathInMessage)
	}
}
