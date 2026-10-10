//go:build fixtures

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/jobs"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/runtimes/docker"
	"github.com/autarquico/supermgmt/internal/runtimes/systemd"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

const (
	slowUnit = "sm-slow.service"
	// busyboxImage is the digest the fixture's demo container already pulled.
	busyboxImage = "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
)

func unitRef(p *provisioned, unit string) runtimes.ServiceRef {
	return runtimes.ServiceRef{NodeID: p.id, Kind: domain.ServiceSystemdUnit, NativeID: unit, Name: unit}
}

func containerRef(p *provisioned, name string) runtimes.ServiceRef {
	return runtimes.ServiceRef{NodeID: p.id, Kind: domain.ServiceDockerContainer, NativeID: name, Name: name}
}

// dispatch runs a mutating command through the dedicated user's session and
// requires a clean exit.
func dispatch(t *testing.T, ex transport.Executor, c templates.Command) {
	t.Helper()
	res, err := ex.Run(t.Context(), c)
	if err != nil || res.ExitStatus != 0 {
		t.Fatalf("dispatch %s: exit %d, err %v, stderr %q", c.Template, res.ExitStatus, err, res.Stderr)
	}
}

func assertEvidence(t *testing.T, ev jobs.Evidence, proof string, class jobs.Classification, pre json.RawMessage) {
	t.Helper()
	if !ev.Done || ev.ExitStatus != 0 || ev.Proof != proof || ev.Classification != class {
		t.Errorf("evidence = {done:%v exit:%d proof:%q class:%q}; want {done:true exit:0 proof:%q class:%q}",
			ev.Done, ev.ExitStatus, ev.Proof, ev.Classification, proof, class)
	}
	if len(ev.Fingerprint) == 0 || !json.Valid(ev.Fingerprint) || string(ev.Fingerprint) == "null" {
		t.Errorf("fingerprint = %q; want non-empty JSON (an empty one would pair in confirm)", ev.Fingerprint)
	}
	if string(ev.Pre) != string(pre) {
		t.Errorf("pre = %s; want the recorded pre-state %s", ev.Pre, pre)
	}
}

func fingerprintField(t *testing.T, ev jobs.Evidence, field string) string {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(ev.Fingerprint, &fields); err != nil {
		t.Fatalf("decode fingerprint %s: %v", ev.Fingerprint, err)
	}
	s, _ := fields[field].(string)
	return s
}

func TestFixturesSystemd_DiscoveryLogsAndTrust(t *testing.T) {
	p := provision(t, fixture.Options{}, nil)
	sd := systemd.New()

	t.Run("discovery lists the fixture units and hides systemd machinery", func(t *testing.T) {
		d, err := sd.Discover(t.Context(), p.super, runtimes.Filter{})
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		if d.Runtime.Type != domain.RuntimeSystemd || d.Runtime.Version == "" {
			t.Errorf("runtime = %+v; want systemd with a version", d.Runtime)
		}
		names := serviceNames(d)
		for _, want := range []string{demoUnit, slowUnit, "ssh.service"} {
			if !slices.Contains(names, want) {
				t.Errorf("services %v lack %s", names, want)
			}
		}
		for _, name := range names {
			if strings.HasPrefix(name, "systemd-") {
				t.Errorf("default excludes must hide %s", name)
			}
		}
		for _, s := range d.Services {
			if s.NativeID == demoUnit && (s.Status != "active" || s.Kind != domain.ServiceSystemdUnit) {
				t.Errorf("%s = %+v; want an active systemd_unit", demoUnit, s)
			}
		}
	})

	t.Run("include and exclude filters select by glob and exclude wins", func(t *testing.T) {
		d, err := sd.Discover(t.Context(), p.super, runtimes.Filter{Include: []string{"sm-*"}, Exclude: []string{"sm-slow*"}})
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		names := serviceNames(d)
		if !slices.Contains(names, demoUnit) || slices.Contains(names, slowUnit) || slices.Contains(names, "ssh.service") {
			t.Errorf("services = %v; want sm-demo without sm-slow and ssh", names)
		}
	})

	t.Run("logs are bounded to the requested line count", func(t *testing.T) {
		p.shell(t, "systemd-run --quiet --unit=sm-chatty --remain-after-exit /bin/sh -c 'seq 1 500'")
		waitUntil(t, func() bool {
			chunk, err := sd.Logs(t.Context(), p.super, unitRef(p, "sm-chatty.service"), runtimes.LogQuery{Lines: 1, Mode: p.meta.LogsMode})
			return err == nil && len(chunk.Lines) > 0 && strings.HasSuffix(chunk.Lines[len(chunk.Lines)-1], "500")
		})
		chunk, err := sd.Logs(t.Context(), p.super, unitRef(p, "sm-chatty.service"), runtimes.LogQuery{Lines: 50, Mode: p.meta.LogsMode})
		if err != nil {
			t.Fatalf("logs: %v", err)
		}
		if len(chunk.Lines) < 50 || len(chunk.Lines) > 51 {
			t.Errorf("got %d lines; want the last 50 (plus at most a journalctl header)", len(chunk.Lines))
		}
		if last := chunk.Lines[len(chunk.Lines)-1]; !strings.HasSuffix(last, " 500") {
			t.Errorf("last line = %q; want the newest entry (500)", last)
		}
	})

	t.Run("ANSI escapes in a unit's output never reach the caller", func(t *testing.T) {
		p.shell(t, `systemd-run --quiet --unit=sm-ansi --remain-after-exit /bin/sh -c 'printf "\033[31mred\033[0m \033]0;title\007 plain\n"; printf "\302\205c1 line\n"'`)
		waitUntil(t, func() bool {
			chunk, err := sd.Logs(t.Context(), p.super, unitRef(p, "sm-ansi.service"), runtimes.LogQuery{Lines: 20, Mode: p.meta.LogsMode})
			return err == nil && len(chunk.Lines) > 1
		})
		chunk, err := sd.Logs(t.Context(), p.super, unitRef(p, "sm-ansi.service"), runtimes.LogQuery{Lines: 20, Mode: p.meta.LogsMode})
		if err != nil {
			t.Fatalf("logs: %v", err)
		}
		var sawText bool
		for _, line := range chunk.Lines {
			if strings.ContainsAny(line, "\x1b\x07\u0085") {
				t.Errorf("control character in log line %q", line)
			}
			sawText = sawText || (strings.Contains(line, "red") && strings.Contains(line, "plain"))
		}
		if !sawText {
			t.Errorf("the printable text around the escapes was lost: %q", chunk.Lines)
		}
	})

	t.Run("line counts outside 1..10000 are rejected", func(t *testing.T) {
		for _, lines := range []int{0, -1, runtimes.MaxLogLines + 1} {
			_, err := sd.Logs(t.Context(), p.super, unitRef(p, demoUnit), runtimes.LogQuery{Lines: lines, Mode: p.meta.LogsMode})
			if codeOf(err) != smerr.CodeInvalidArgument {
				t.Errorf("lines=%d: %v; want INVALID_ARGUMENT", lines, err)
			}
		}
	})

	t.Run("a trusted unit passes the trust profile", func(t *testing.T) {
		if err := sd.Preflight(t.Context(), p.super, unitRef(p, demoUnit)); err != nil {
			t.Errorf("preflight of %s: %v", demoUnit, err)
		}
	})
}

func serviceNames(d runtimes.Discovered) []string {
	names := make([]string, 0, len(d.Services))
	for _, s := range d.Services {
		names = append(names, s.NativeID)
	}
	return names
}

// eventually polls cond for up to 15 seconds of wall time.
func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for !cond() {
		select {
		case <-ctx.Done():
			t.Fatal("condition not met within 15s")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestFixturesSystemd_TrustProfileRejectsUnitsRunningWritableCode(t *testing.T) {
	p := provision(t, fixture.Options{}, nil)
	sd := systemd.New()

	writeUnit := func(name, body string) {
		p.shell(t, "printf '%s\\n' "+templates.Quote(body)+" > /etc/systemd/system/"+name+" && systemctl daemon-reload")
	}
	p.shell(t, "printf '#!/bin/sh\\nexec sleep infinity\\n' > /tmp/evil.sh && chmod 0755 /tmp/evil.sh && "+
		"printf '#!/bin/sh\\nexec sleep infinity\\n' > /usr/local/bin/group-writable && chown root:root /usr/local/bin/group-writable && chmod 0775 /usr/local/bin/group-writable && "+
		"printf 'A=1\\n' > /tmp/env")

	cases := []struct{ unit, body, why string }{
		{"sm-bad-tmp.service", "[Service]\nExecStart=/tmp/evil.sh\n", "executable in a world-writable directory"},
		{"sm-bad-script.service", "[Service]\nExecStart=/bin/sh /tmp/evil.sh\n", "interpreter script in a world-writable directory"},
		{"sm-bad-mode.service", "[Service]\nExecStart=/usr/local/bin/group-writable\n", "group-writable executable"},
		{"sm-bad-env.service", "[Service]\nEnvironmentFile=/tmp/env\nExecStart=/bin/sleep infinity\n", "EnvironmentFile in a world-writable directory"},
		{"sm-bad-inline.service", "[Service]\nExecStart=/bin/sh -c 'exec sleep infinity'\n", "inline interpreter code"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			writeUnit(tc.unit, "[Unit]\nDescription=trust fixture\n"+tc.body)
			err := sd.Preflight(t.Context(), p.super, unitRef(p, tc.unit))
			if codeOf(err) != smerr.CodeCapabilityUnavailable || reasonOf(err) != smerr.ReasonUnitNotEligible {
				t.Errorf("preflight of %s = %v; want CAPABILITY_UNAVAILABLE / UNIT_NOT_ELIGIBLE", tc.unit, err)
			}
		})
	}

	t.Run("a unit that is not loaded is not eligible", func(t *testing.T) {
		err := sd.Preflight(t.Context(), p.super, unitRef(p, "sm-does-not-exist.service"))
		if reasonOf(err) != smerr.ReasonUnitNotEligible {
			t.Errorf("preflight of a missing unit = %v; want UNIT_NOT_ELIGIBLE", err)
		}
	})

	t.Run("a unit name outside the grammar never reaches the node", func(t *testing.T) {
		for _, name := range []string{"x.service,/bin/sh", "a b.service", "-rf.service", "../x.service", "x.service\n", "x.timer", "a:b.service", "a\\b.service"} {
			err := sd.Preflight(t.Context(), p.super, unitRef(p, name))
			if reasonOf(err) != smerr.ReasonUnitNotEligible {
				t.Errorf("preflight of %q = %v; want UNIT_NOT_ELIGIBLE", name, err)
			}
		}
	})
}

func TestFixturesSetup_RefusesToGrantAnUntrustedUnit(t *testing.T) {
	n := startNode(t, fixture.Options{})
	id := newIdentity(t)
	useAgent(t, n.ClientSigner)
	h := newHarness(t, defaultPoolConfig(), id)
	n.shell(t, "printf '#!/bin/sh\\nexec sleep infinity\\n' > /tmp/evil.sh && chmod 0755 /tmp/evil.sh && "+
		"printf '[Service]\\nExecStart=/tmp/evil.sh\\n' > /etc/systemd/system/sm-bad.service && systemctl daemon-reload")

	_, err := systemd.Setup(t.Context(), h.pool.For(n.target(fixture.AdminUser)), setupParams(id, func(p *systemd.SetupParams) {
		p.Grants = append(p.Grants, runtimes.UnitGrant{Unit: "sm-bad.service", Verbs: []domain.ServiceVerb{domain.VerbRestart}})
	}))
	if reasonOf(err) != smerr.ReasonUnitNotEligible {
		t.Fatalf("setup granting an untrusted unit: %v; want UNIT_NOT_ELIGIBLE", err)
	}
	if n.hasUser(t, dedicatedUser) {
		t.Error("the user was created although a granted unit failed the trust profile; nothing may be written before the check")
	}
	if _, err := n.tryShell(t, "test -e /etc/sudoers.d/supermgmt"); err == nil {
		t.Error("a sudoers drop-in exists although setup was refused")
	}
}

func TestFixturesSystemd_ActionsProduceEvidence(t *testing.T) {
	p := provision(t, fixture.Options{}, func(p *systemd.SetupParams) {
		p.Grants = append(p.Grants, runtimes.UnitGrant{Unit: slowUnit, Verbs: domain.AllServiceVerbs()})
	})
	sd := systemd.New()
	ref := unitRef(p, demoUnit)
	epoch := time.Unix(0, 0)

	markerState := func(marker string) templates.MarkerState {
		state, err := templates.ParseMarkerState(run(t, p.super, "marker.state", map[string]string{"marker": marker}).Stdout)
		if err != nil {
			t.Fatalf("marker state: %v", err)
		}
		return state
	}

	t.Run("restart: new invocation, proof from systemd, completion classified", func(t *testing.T) {
		pre, err := sd.PreState(t.Context(), p.super, ref)
		if err != nil {
			t.Fatalf("pre-state: %v", err)
		}
		cmd, err := sd.Mutate(ref, domain.VerbRestart, "t9a-sd-restart", p.meta)
		if err != nil {
			t.Fatalf("mutate: %v", err)
		}
		if markerState("t9a-sd-restart").Kind != templates.MarkerAbsent {
			t.Error("the marker exists before dispatch")
		}
		dispatch(t, p.super, cmd)
		if got := markerState("t9a-sd-restart"); !got.CompletionProof() {
			t.Errorf("marker after dispatch = %+v; want .done with exit 0", got)
		}
		ev, err := sd.Observe(t.Context(), p.super, ref, domain.VerbRestart, "t9a-sd-restart", pre, epoch)
		if err != nil {
			t.Fatalf("observe: %v", err)
		}
		assertEvidence(t, ev, systemd.ProofNoJobs, jobs.ClassComplete, pre)
		if before, after := fingerprintFieldOf(t, pre, "invocation_id"), fingerprintField(t, ev, "invocation_id"); before == "" || before == after {
			t.Errorf("invocation id %q -> %q; a restart must change it", before, after)
		}
	})

	t.Run("a restart that never ran is classified not_started", func(t *testing.T) {
		pre, err := sd.PreState(t.Context(), p.super, ref)
		if err != nil {
			t.Fatalf("pre-state: %v", err)
		}
		ev, err := sd.Observe(t.Context(), p.super, ref, domain.VerbRestart, "t9a-never-sent", pre, epoch)
		if err != nil {
			t.Fatalf("observe: %v", err)
		}
		assertEvidence(t, ev, systemd.ProofNoJobs, jobs.ClassNotStarted, pre)
		if got := markerState("t9a-never-sent"); got.Kind != templates.MarkerAbsent {
			t.Errorf("marker = %+v; want absent", got)
		}
	})

	t.Run("stop and start", func(t *testing.T) {
		for _, step := range []struct {
			verb   domain.ServiceVerb
			marker string
			active string
		}{
			{domain.VerbStop, "t9a-sd-stop", "inactive"},
			{domain.VerbStart, "t9a-sd-start", "active"},
		} {
			pre, err := sd.PreState(t.Context(), p.super, ref)
			if err != nil {
				t.Fatalf("%s pre-state: %v", step.verb, err)
			}
			cmd, err := sd.Mutate(ref, step.verb, step.marker, p.meta)
			if err != nil {
				t.Fatalf("%s mutate: %v", step.verb, err)
			}
			dispatch(t, p.super, cmd)
			ev, err := sd.Observe(t.Context(), p.super, ref, step.verb, step.marker, pre, epoch)
			if err != nil {
				t.Fatalf("%s observe: %v", step.verb, err)
			}
			assertEvidence(t, ev, systemd.ProofNoJobs, jobs.ClassComplete, pre)
			if got := fingerprintField(t, ev, "active_state"); got != step.active {
				t.Errorf("%s left the unit %q; want %q", step.verb, got, step.active)
			}
		}
	})

	t.Run("observe reports settling while systemd still has a job for the unit", func(t *testing.T) {
		slow := unitRef(p, slowUnit)
		pre, err := sd.PreState(t.Context(), p.super, slow)
		if err != nil {
			t.Fatalf("pre-state: %v", err)
		}
		cmd, err := sd.Mutate(slow, domain.VerbRestart, "t9a-slow", p.meta)
		if err != nil {
			t.Fatalf("mutate: %v", err)
		}
		finished := make(chan error, 1)
		go func() {
			res, err := p.super.Run(t.Context(), cmd)
			if err == nil && res.ExitStatus != 0 {
				err = errors.New("restart exited " + strconv.Itoa(res.ExitStatus))
			}
			finished <- err
		}()
		waitUntil(t, func() bool {
			_, err := sd.Observe(t.Context(), p.super, slow, domain.VerbRestart, "t9a-slow", pre, epoch)
			return errors.Is(err, systemd.ErrSettling)
		})
		if err := <-finished; err != nil {
			t.Fatalf("slow restart: %v", err)
		}
		ev, err := sd.Observe(t.Context(), p.super, slow, domain.VerbRestart, "t9a-slow", pre, epoch)
		if err != nil {
			t.Fatalf("observe after settling: %v", err)
		}
		assertEvidence(t, ev, systemd.ProofNoJobs, jobs.ClassComplete, pre)
	})

	t.Run("sudoers grants nothing beyond the rendered lines", func(t *testing.T) {
		systemctl := p.meta.SystemctlPath
		for _, line := range []string{
			"sudo -n " + systemctl + " restart ssh.service",
			"sudo -n " + systemctl + " restart " + demoUnit + " ssh.service",
			"sudo -n " + systemctl + " daemon-reload",
			"sudo -n /usr/bin/id",
			"sudo -n -u root id",
		} {
			res, err := p.super.Run(t.Context(), rawCommand(line, 4096, 20))
			if err != nil || res.ExitStatus == 0 {
				t.Errorf("%q: exit %d, err %v; want sudo to refuse", line, res.ExitStatus, err)
			}
		}
		if got := p.shell(t, "systemctl is-active ssh.service"); got != "active" {
			t.Errorf("ssh.service = %q after the refused restarts", got)
		}
	})

	t.Run("a verb or unit setup did not grant is not rendered", func(t *testing.T) {
		narrow := p.meta
		narrow.Units = []runtimes.UnitGrant{{Unit: demoUnit, Verbs: []domain.ServiceVerb{domain.VerbStart}}}
		if _, err := sd.Mutate(ref, domain.VerbRestart, "t9a-x", narrow); codeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Errorf("restart without a grant: %v; want CAPABILITY_UNAVAILABLE", err)
		}
		if _, err := sd.Mutate(unitRef(p, "ssh.service"), domain.VerbRestart, "t9a-y", p.meta); codeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Errorf("restart of an ungranted unit: %v; want CAPABILITY_UNAVAILABLE", err)
		}
	})
}

func fingerprintFieldOf(t *testing.T, raw json.RawMessage, field string) string {
	t.Helper()
	return fingerprintField(t, jobs.Evidence{Fingerprint: raw}, field)
}

func TestFixturesSystemd_BrokerModeReadsOnlyAllowedUnits(t *testing.T) {
	p := provision(t, fixture.Options{}, func(p *systemd.SetupParams) { p.LogsMode = runtimes.LogsBroker })
	sd := systemd.New()

	chunk, err := sd.Logs(t.Context(), p.super, unitRef(p, demoUnit), runtimes.LogQuery{Lines: 5, Mode: runtimes.LogsBroker})
	if err != nil || len(chunk.Lines) == 0 {
		t.Fatalf("broker logs of a granted unit: %d lines, err %v", len(chunk.Lines), err)
	}
	if len(chunk.Lines) > 6 {
		t.Errorf("got %d lines for a request of 5", len(chunk.Lines))
	}

	t.Run("a unit outside allowed-units is refused by the broker", func(t *testing.T) {
		_, err := sd.Logs(t.Context(), p.super, unitRef(p, "ssh.service"), runtimes.LogQuery{Lines: 5, Mode: runtimes.LogsBroker})
		if codeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Errorf("broker logs of ssh.service: %v; want CAPABILITY_UNAVAILABLE", err)
		}
	})

	t.Run("the broker rejects malformed requests", func(t *testing.T) {
		for _, args := range []string{demoUnit, demoUnit + " 0", demoUnit + " 10001", demoUnit + " 5x", demoUnit + " 5 extra"} {
			res, err := p.super.Run(t.Context(), rawCommand("sudo -n "+templates.BrokerPath+" "+args, 4096, 20))
			if err != nil || res.ExitStatus != 64 {
				t.Errorf("broker %q: exit %d, err %v; want 64 (usage)", args, res.ExitStatus, err)
			}
		}
	})

	t.Run("the dedicated user cannot read the journal directly", func(t *testing.T) {
		res, err := p.super.Run(t.Context(), rawCommand("journalctl --no-pager -u ssh.service -n 5 2>&1", 4096, 20))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if strings.Contains(string(res.Stdout), "sshd") {
			t.Errorf("supermgmt read ssh.service's journal without the journal group: %q", res.Stdout)
		}
	})
}

func TestFixturesDocker_DiscoveryLogsAndActions(t *testing.T) {
	p := provision(t, fixture.Options{DemoContainer: true}, func(p *systemd.SetupParams) { p.DockerAccess = true })
	dk := docker.New()
	ref := containerRef(p, demoContainer)

	t.Run("discovery lists the demo container as running", func(t *testing.T) {
		d, err := dk.Discover(t.Context(), p.super, runtimes.Filter{})
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		if d.Runtime.Type != domain.RuntimeDocker || d.Runtime.Version == "" {
			t.Errorf("runtime = %+v; want docker with a version", d.Runtime)
		}
		var found bool
		for _, s := range d.Services {
			if s.Name == demoContainer {
				found = true
				if s.Kind != domain.ServiceDockerContainer || s.Status != "running" {
					t.Errorf("%s = %+v; want a running docker_container", demoContainer, s)
				}
			}
		}
		if !found {
			t.Errorf("services %v lack %s", serviceNames(d), demoContainer)
		}
	})

	t.Run("filters select containers by glob", func(t *testing.T) {
		d, err := dk.Discover(t.Context(), p.super, runtimes.Filter{Include: []string{"sm-*"}, Exclude: []string{"*-web"}})
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		for _, s := range d.Services {
			if s.Name == demoContainer {
				t.Errorf("%s survived an exclude of *-web", demoContainer)
			}
		}
	})

	t.Run("logs are bounded and ANSI-free", func(t *testing.T) {
		p.shell(t, `docker run -d --name sm-ansi `+busyboxImage+` sh -c 'printf "\033[31mred\033[0m \033]0;t\007x\n"; seq 1 300; sleep infinity'`)
		waitUntil(t, func() bool {
			chunk, err := dk.Logs(t.Context(), p.super, containerRef(p, "sm-ansi"), runtimes.LogQuery{Lines: 1})
			return err == nil && len(chunk.Lines) == 1 && strings.HasSuffix(chunk.Lines[0], " 300")
		})
		chunk, err := dk.Logs(t.Context(), p.super, containerRef(p, "sm-ansi"), runtimes.LogQuery{Lines: 20})
		if err != nil || len(chunk.Lines) != 20 {
			t.Fatalf("got %d lines, err %v; want exactly the last 20", len(chunk.Lines), err)
		}
		all, err := dk.Logs(t.Context(), p.super, containerRef(p, "sm-ansi"), runtimes.LogQuery{Lines: 400})
		if err != nil {
			t.Fatalf("logs: %v", err)
		}
		var sawRed bool
		for _, line := range all.Lines {
			if strings.ContainsAny(line, "\x1b\x07") {
				t.Errorf("control character in log line %q", line)
			}
			sawRed = sawRed || strings.Contains(line, "red")
		}
		if !sawRed {
			t.Error("the printable text of the ANSI line was lost")
		}
	})

	t.Run("restart, stop and start are proven by the .done file and classified from State", func(t *testing.T) {
		for _, step := range []struct {
			verb   domain.ServiceVerb
			marker string
		}{
			{domain.VerbRestart, "t9a-dk-restart"},
			{domain.VerbStop, "t9a-dk-stop"},
			{domain.VerbStart, "t9a-dk-start"},
		} {
			pre, err := dk.PreState(t.Context(), p.super, ref)
			if err != nil {
				t.Fatalf("%s pre-state: %v", step.verb, err)
			}
			before := nodeClock(t, p)
			cmd, err := dk.Mutate(ref, step.verb, step.marker, p.meta)
			if err != nil {
				t.Fatalf("%s mutate: %v", step.verb, err)
			}
			dispatch(t, p.super, cmd)
			ev, err := dk.Observe(t.Context(), p.super, ref, step.verb, step.marker, pre, before)
			if err != nil {
				t.Fatalf("%s observe: %v", step.verb, err)
			}
			assertEvidence(t, ev, docker.ProofDoneFile, jobs.ClassComplete, pre)
		}
	})

	t.Run("without a .done file there is no evidence", func(t *testing.T) {
		pre, err := dk.PreState(t.Context(), p.super, ref)
		if err != nil {
			t.Fatalf("pre-state: %v", err)
		}
		_, err = dk.Observe(t.Context(), p.super, ref, domain.VerbRestart, "t9a-dk-never", pre, time.Unix(0, 0))
		if !errors.Is(err, docker.ErrNoCompletionProof) {
			t.Errorf("observe with no marker = %v; want ErrNoCompletionProof", err)
		}
	})

	t.Run("a failed action leaves .done non-zero and still no evidence", func(t *testing.T) {
		p.shell(t, "docker rm -f sm-ansi")
		cmd, err := dk.Mutate(containerRef(p, "sm-ansi"), domain.VerbRestart, "t9a-dk-failed", p.meta)
		if err != nil {
			t.Fatalf("mutate: %v", err)
		}
		if res, err := p.super.Run(t.Context(), cmd); err != nil || res.ExitStatus == 0 {
			t.Fatalf("restart of a removed container: exit %d, err %v; want a non-zero exit", res.ExitStatus, err)
		}
		state, err := templates.ParseMarkerState(run(t, p.super, "marker.state", map[string]string{"marker": "t9a-dk-failed"}).Stdout)
		if err != nil || state.Kind != templates.MarkerDone || state.ExitStatus == 0 {
			t.Fatalf("marker = %+v, %v; want .done holding the non-zero status", state, err)
		}
		_, err = dk.Observe(t.Context(), p.super, ref, domain.VerbRestart, "t9a-dk-failed", json.RawMessage(`{}`), time.Unix(0, 0))
		if !errors.Is(err, docker.ErrNoCompletionProof) {
			t.Errorf("observe after a failed action = %v; want ErrNoCompletionProof", err)
		}
	})

	t.Run("actions need docker_access from node.setup", func(t *testing.T) {
		without := p.meta
		without.DockerAccess = false
		if _, err := dk.Mutate(ref, domain.VerbRestart, "t9a-dk-x", without); codeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Errorf("mutate without docker_access: %v; want CAPABILITY_UNAVAILABLE", err)
		}
	})

	t.Run("a container name outside the grammar never reaches the node", func(t *testing.T) {
		for _, name := range []string{"-rm", "a b", "x;id", "$(id)", "a\nb", ""} {
			if _, err := dk.Mutate(containerRef(p, name), domain.VerbStop, "t9a-dk-y", p.meta); err == nil {
				t.Errorf("mutate accepted container %q", name)
			}
		}
	})
}

// nodeClock reads the node's clock, which is what container timestamps are
// judged against (the test process has no injectable clock to compare with).
func nodeClock(t *testing.T, p *provisioned) time.Time {
	t.Helper()
	seconds, err := strconv.ParseInt(p.shell(t, "date +%s"), 10, 64)
	if err != nil {
		t.Fatalf("node clock: %v", err)
	}
	return time.Unix(seconds-1, 0)
}
