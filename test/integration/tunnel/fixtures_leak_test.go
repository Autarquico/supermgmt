//go:build fixtures

package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/providers/cloudflare/cffake"
)

// Scenario "secrets never leak", with a node: setup, dialling, rotation and
// disable, with Cloudflare faults and a failed verification on the way. The
// credentials are the ones cffake minted and the store holds; the places are
// every table of the database, the job engine's log, every command the control
// plane ran on the node and what came back, the carrier's argv and environment,
// a decompressed backup, and on the node its unit, its journal, its process
// list and every file that contains one.

const tokenPath = "/etc/supermgmt/cloudflared/token"

// credentialPath is the copy of the token systemd hands the running unit
// (LoadCredential), readable by that unit alone.
const credentialPath = "/run/credentials/" + tunnelSvc + "/token"

// nodePlaces reads what the node itself remembers.
func (f *tunnelFixture) nodePlaces() map[string][]byte {
	f.t.Helper()
	places := map[string][]byte{}
	read := func(name, script string) {
		out, _ := trySh(f.t, f.docker, script) // a unit that is gone has no text to leak from
		places[name] = []byte(out)
	}
	read("node unit file", "systemctl cat "+tunnelSvc+" 2>&1")
	read("node unit status", "systemctl status --no-pager -l "+tunnelSvc+" 2>&1")
	read("node journal", "journalctl --no-pager -a -o short 2>&1")
	read("node process list", "ps -eo args 2>&1")
	read("node stub record", stubRecords+" 2>&1")
	return places
}

// filesHolding lists the files on the node that contain value, outside /proc
// and /sys. The value travels as the argument of this one docker exec only.
func (f *tunnelFixture) filesHolding(value string) []string {
	f.t.Helper()
	out, _ := f.docker.Exec(f.t.Context(), "sh", "-c",
		`grep -rlIF -e "$0" /etc /var /usr/local /opt /srv /root /home /run /tmp 2>/dev/null; true`, value)
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}
	slices.Sort(files)
	return files
}

// carrierPlaces are the argv and environment of every carrier the dialler
// started. The environment holds the service token on purpose (it is how
// cloudflared receives it); the other credentials must not be there.
func (s *stack) carrierPlaces(allowServiceSecret string) map[string][]byte {
	places := map[string][]byte{}
	for i, r := range s.carrierRecords() {
		places["carrier argv #"+string(rune('a'+i%26))] = []byte(strings.Join(r.Argv, "\x00"))
		var env []string
		for _, kv := range r.Env {
			if strings.HasPrefix(kv, "TUNNEL_SERVICE_TOKEN_SECRET=") && allowServiceSecret != "" {
				continue
			}
			env = append(env, kv)
		}
		places["carrier environment #"+string(rune('a'+i%26))] = []byte(strings.Join(env, "\x00"))
	}
	return places
}

func (f *tunnelFixture) scanEverywhere(creds credentials, stage string) {
	f.t.Helper()
	places := f.scanControlPlane()
	for name, data := range f.nodePlaces() {
		places[name] = data
	}
	// The runtime service token secret is expected in the carrier's environment
	// variable of that name and nowhere else.
	for name, data := range f.carrierPlaces(f.serviceTokenSecret()) {
		places[name] = data
	}
	for _, leak := range leaks(creds, places) {
		f.t.Errorf("%s: leak: %s", stage, leak)
	}
}

func TestNoCredentialLeaksThroughEnableRotateAndDisableWithFaults(t *testing.T) {
	f := newTunnelFixture(t, fixtureOptions{})
	creds := credentials{}
	f.mustSucceed(f.setup(false), "setup over the direct route")

	// A failed verification first: Access refuses the token. Its failure output
	// is one of the places a credential could hide.
	f.denyAccess.Store(true)
	denied := f.setup(true)
	f.denyAccess.Store(false)
	if denied.Error == nil {
		t.Fatalf("setup --tunnel with Access denying the token did not fail: %s", outcome(denied, nil))
	}
	f.collect(creds)
	f.scanEverywhere(creds, "after a failed verification")

	// Then the real thing, with a lost response and a refusal on the way.
	base := len(f.cf.Mutations())
	f.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		switch m.Seq - base {
		case 2:
			return cffake.LostResponse
		case 4:
			return cffake.FailBefore
		}
		return cffake.NoFault
	})
	f.mustSucceed(f.setup(true), "setup --tunnel under faults")
	f.cf.ClearFaults()
	f.collect(creds)

	// Positive controls: the scan is only worth something if the credentials are
	// where they should be.
	tunnelToken := ""
	for name, value := range creds {
		if strings.HasPrefix(name, "tunnel token ") {
			tunnelToken = value
		}
	}
	if tunnelToken == "" || f.serviceTokenSecret() == "" {
		t.Fatalf("the credentials to look for were not all minted: %v", names(creds))
	}
	sum := sha256.Sum256([]byte(tunnelToken + "\n"))
	if got := sh(t, f.docker, "sha256sum "+tokenPath+" | cut -d' ' -f1"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("the node's token file does not hold the tunnel token (hash %s)", got)
	}
	f.scanEverywhere(creds, "after setup --tunnel")
	for name, value := range creds {
		files := f.filesHolding(value)
		switch {
		case value == tunnelToken:
			if want := []string{tokenPath, credentialPath}; !slices.Equal(files, want) {
				t.Errorf("files on the node holding the tunnel token = %v, want only %v", files, want)
			}
		case len(files) != 0:
			t.Errorf("files on the node holding %s: %v, want none", name, files)
		}
	}

	f.blockDirectRoute()
	f.mustSucceed(f.run("node.probe", nodeRef(f.node), nil), "probe through the tunnel")
	if env := f.carrierPlaces(""); !strings.Contains(string(env["carrier environment #a"]), "TUNNEL_SERVICE_TOKEN_SECRET="+f.serviceTokenSecret()) {
		t.Error("positive control: the carrier did not receive the service token in its environment")
	}

	// Rotation with a lost response on its first mutation and a refusal later.
	base = len(f.cf.Mutations())
	f.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		switch m.Seq - base {
		case 1:
			return cffake.LostResponse
		case 4:
			return cffake.FailBefore
		}
		return cffake.NoFault
	})
	f.mustSucceed(f.run("cloudflare.access_token.rotate", f.instanceRef(), nil), "rotation under faults")
	f.cf.ClearFaults()
	f.collect(creds)
	f.mustSucceed(f.run("node.probe", nodeRef(f.node), nil), "probe after the rotation")
	f.scanEverywhere(creds, "after the rotation")

	// Disable under a fault.
	f.restoreDirectRoute()
	base = len(f.cf.Mutations())
	f.cf.Plan(func(m cffake.Mutation) cffake.Fault {
		if m.Seq-base == 2 {
			return cffake.LostResponse
		}
		return cffake.NoFault
	})
	f.mustSucceed(f.run("node.tunnel.disable", nodeRef(f.node), nil), "disable under a fault")
	f.cf.ClearFaults()
	f.scanEverywhere(creds, "after the disable")
	for name, value := range creds {
		if files := f.filesHolding(value); len(files) != 0 {
			t.Errorf("after the disable, files on the node holding %s: %v, want none", name, files)
		}
	}
}
