package join

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/autarquico/supermgmt/internal/api/wire"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

func publicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptossh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key)))
}

type installed struct {
	data  string
	mode  fs.FileMode
	owner string
}

// fakeHost records what join asks of the node and keeps a tiny account table.
type fakeHost struct {
	files     map[string][]byte
	accounts  map[string]Account
	calls     []string
	dirs      map[string]fs.FileMode
	installed map[string]installed

	preflightErr error
	passwordErr  error
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		files: map[string][]byte{}, accounts: map[string]Account{},
		dirs: map[string]fs.FileMode{}, installed: map[string]installed{},
	}
}

func (h *fakeHost) record(call string) { h.calls = append(h.calls, call) }

func (h *fakeHost) Preflight() error {
	h.record("preflight")
	return h.preflightErr
}
func (h *fakeHost) Hostname() (string, error) { return "edge-1", nil }
func (h *fakeHost) Addresses() []string       { return []string{"192.0.2.10"} }
func (h *fakeHost) ReadFile(path string) ([]byte, error) {
	if b, ok := h.files[path]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}

func (h *fakeHost) LookupAccount(name string) (Account, bool, error) {
	a, ok := h.accounts[name]
	return a, ok, nil
}

func (h *fakeHost) AddAccount(_ context.Context, name string) error {
	h.record("add " + name)
	h.accounts[name] = Account{UID: 998, GID: 998, Home: templates.HomeDir, Shell: "/bin/sh", PrimaryGroup: name}
	return nil
}

func (h *fakeHost) DisablePassword(_ context.Context, name string) error {
	h.record("password " + name)
	return h.passwordErr
}

func (h *fakeHost) EnsureDir(path string, mode fs.FileMode, owner string) error {
	h.record("dir " + path)
	h.dirs[path] = mode
	_ = owner
	return nil
}

func (h *fakeHost) InstallFile(path string, data []byte, mode fs.FileMode, owner string) error {
	h.record("install " + path)
	h.installed[path] = installed{string(data), mode, owner}
	return nil
}

func (h *fakeHost) did(call string) bool { return slices.Contains(h.calls, call) }

type fakeEnroller struct {
	got      []wire.EnrollRequest
	answer   wire.Enrolled
	err      error
	host     *fakeHost
	preflown bool
}

func (e *fakeEnroller) Enroll(_ context.Context, r wire.EnrollRequest) (wire.Enrolled, error) {
	e.got = append(e.got, r)
	e.preflown = e.host != nil && e.host.did("preflight")
	return e.answer, e.err
}

func enrolledWith(key string) wire.Enrolled {
	return wire.Enrolled{
		NodeID: "node-1", InstanceID: "instance-1", SSHUser: "supermgmt",
		AuthorizedKey: key, KeyVersion: 1, FingerprintSHA256: "SHA256:instance",
	}
}

func joinerWith(host *fakeHost, key string) (Joiner, *fakeEnroller) {
	enroller := &fakeEnroller{host: host, answer: enrolledWith(key)}
	return Joiner{Host: host, Enroller: enroller}, enroller
}

func TestJoinPresentsTheHostKeyAndPreparesTheDedicatedAccount(t *testing.T) {
	host := newFakeHost()
	hostKey, instanceKey := publicKey(t), publicKey(t)
	host.files["/etc/ssh/ssh_host_ed25519_key.pub"] = []byte(hostKey + " root@edge-1\n")
	joiner, enroller := joinerWith(host, instanceKey)

	got, err := joiner.Run(context.Background(), Request{Token: " smj_abc\n", SSHPort: 2222})

	if err != nil || got.NodeID != "node-1" {
		t.Fatalf("Run = %+v, %v", got, err)
	}
	want := wire.EnrollRequest{Token: "smj_abc", HostPublicKey: hostKey, Hostname: "edge-1", Addresses: []string{"192.0.2.10"}, SSHPort: 2222}
	if len(enroller.got) != 1 || !slices.Equal(enroller.got[0].Addresses, want.Addresses) || enroller.got[0].HostPublicKey != want.HostPublicKey ||
		enroller.got[0].Token != want.Token || enroller.got[0].Hostname != want.Hostname || enroller.got[0].SSHPort != want.SSHPort {
		t.Fatalf("request = %+v, want %+v (the comment of the host key dropped)", enroller.got, want)
	}
	if !enroller.preflown {
		t.Error("the token was presented before the preflight")
	}
	if line := host.installed[templates.AuthorizedKeysPath]; line.data != "restrict "+instanceKey+" supermgmt@instance-1\n" || line.mode != 0o600 || line.owner != "supermgmt" {
		t.Errorf("authorized_keys = %+v", line)
	}
	for path, mode := range map[string]fs.FileMode{templates.HomeDir: 0o750, templates.MarkerDir: 0o700, templates.SSHDir: 0o700} {
		if host.dirs[path] != mode {
			t.Errorf("dir %s mode = %o, want %o", path, host.dirs[path], mode)
		}
	}
	if !host.did("add supermgmt") || !host.did("password supermgmt") {
		t.Errorf("calls = %v, want the account created and its password field set", host.calls)
	}
}

func TestJoinPrefersEd25519ThenFallsBack(t *testing.T) {
	host := newFakeHost()
	ecdsa := publicKey(t)
	host.files["/etc/ssh/ssh_host_ecdsa_key.pub"] = []byte(ecdsa + "\n")
	joiner, enroller := joinerWith(host, publicKey(t))

	if _, err := joiner.Run(context.Background(), Request{Token: "smj_abc"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if enroller.got[0].HostPublicKey != ecdsa {
		t.Fatalf("host key = %q, want the ecdsa fallback", enroller.got[0].HostPublicKey)
	}

	host.files["/etc/ssh/ssh_host_ed25519_key.pub"] = []byte(publicKey(t) + "\n")
	if _, err := joiner.Run(context.Background(), Request{Token: "smj_abc"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if enroller.got[1].HostPublicKey == ecdsa {
		t.Fatal("ed25519 must win over ecdsa")
	}
}

func TestJoinChecksEverythingLocalBeforeSpendingTheToken(t *testing.T) {
	tests := map[string]func(*fakeHost){
		"not root":    func(h *fakeHost) { h.preflightErr = smerr.New(smerr.CodeCapabilityUnavailable, "", "must run as root") },
		"no host key": func(h *fakeHost) { delete(h.files, "/etc/ssh/ssh_host_ed25519_key.pub") },
		"junk host key": func(h *fakeHost) {
			h.files["/etc/ssh/ssh_host_ed25519_key.pub"] = []byte("not a key")
		},
	}
	for name, break_ := range tests {
		t.Run(name, func(t *testing.T) {
			host := newFakeHost()
			host.files["/etc/ssh/ssh_host_ed25519_key.pub"] = []byte(publicKey(t))
			break_(host)
			joiner, enroller := joinerWith(host, publicKey(t))

			_, err := joiner.Run(context.Background(), Request{Token: "smj_abc"})

			if err == nil || len(enroller.got) != 0 {
				t.Fatalf("err = %v, enrollments = %d; want a refusal before the server is asked", err, len(enroller.got))
			}
		})
	}
}

func TestJoinRefusesAnEmptyToken(t *testing.T) {
	host := newFakeHost()
	joiner, enroller := joinerWith(host, publicKey(t))

	_, err := joiner.Run(context.Background(), Request{Token: " \n"})

	wantCode(t, err, smerr.CodeInvalidArgument)
	if len(enroller.got) != 0 {
		t.Fatal("the server was asked with an empty token")
	}
}

func TestJoinPassesServerRefusalsThroughAndTouchesNothing(t *testing.T) {
	host := newFakeHost()
	host.files["/etc/ssh/ssh_host_ed25519_key.pub"] = []byte(publicKey(t))
	joiner, enroller := joinerWith(host, publicKey(t))
	enroller.err = smerr.New(smerr.CodeConflict, "", "join token is expired, invalidated or exhausted")

	_, err := joiner.Run(context.Background(), Request{Token: "smj_abc"})

	wantCode(t, err, smerr.CodeConflict)
	if len(host.installed) != 0 || host.did("add supermgmt") {
		t.Fatalf("calls = %v, want the node untouched", host.calls)
	}
}

func TestProvisionConvergesWhenRunAgainAndKeepsAnAccountThatIsOurs(t *testing.T) {
	host := newFakeHost()
	e := enrolledWith(publicKey(t))
	if err := Provision(context.Background(), host, e); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	first := host.installed[templates.AuthorizedKeysPath]
	adds := count(host.calls, "add supermgmt")

	if err := Provision(context.Background(), host, e); err != nil {
		t.Fatalf("second Provision: %v", err)
	}

	if count(host.calls, "add supermgmt") != adds {
		t.Error("the account was created twice")
	}
	if host.installed[templates.AuthorizedKeysPath] != first {
		t.Error("a second run changed authorized_keys")
	}
}

func TestProvisionResumesAfterAnInterruptedFirstRun(t *testing.T) {
	host := newFakeHost()
	host.passwordErr = errors.New("usermod killed")
	e := enrolledWith(publicKey(t))
	if err := Provision(context.Background(), host, e); err == nil {
		t.Fatal("want the interrupted run to fail")
	}
	host.passwordErr = nil

	if err := Provision(context.Background(), host, e); err != nil {
		t.Fatalf("resumed Provision: %v", err)
	}

	if _, ok := host.installed[templates.AuthorizedKeysPath]; !ok {
		t.Fatal("the resumed run did not install authorized_keys")
	}
	if count(host.calls, "add supermgmt") != 1 {
		t.Errorf("calls = %v, want one account creation", host.calls)
	}
}

func TestProvisionNeverAdoptsAForeignAccount(t *testing.T) {
	foreign := map[string]Account{
		"login uid":     {UID: 1000, GID: 1000, Home: templates.HomeDir, Shell: "/bin/sh", PrimaryGroup: "supermgmt"},
		"other home":    {UID: 998, GID: 998, Home: "/home/supermgmt", Shell: "/bin/sh", PrimaryGroup: "supermgmt"},
		"other shell":   {UID: 998, GID: 998, Home: templates.HomeDir, Shell: "/bin/bash", PrimaryGroup: "supermgmt"},
		"shared group":  {UID: 998, GID: 100, Home: templates.HomeDir, Shell: "/bin/sh", PrimaryGroup: "users"},
		"root":          {UID: 0, GID: 0, Home: templates.HomeDir, Shell: "/bin/sh", PrimaryGroup: "supermgmt"},
		"group unknown": {UID: 998, GID: 998, Home: templates.HomeDir, Shell: "/bin/sh"},
	}
	for name, account := range foreign {
		t.Run(name, func(t *testing.T) {
			host := newFakeHost()
			host.accounts["supermgmt"] = account

			err := Provision(context.Background(), host, enrolledWith(publicKey(t)))

			wantCode(t, err, smerr.CodeConflict)
			if len(host.installed) != 0 || len(host.dirs) != 0 {
				t.Fatalf("calls = %v, want nothing written for a foreign account", host.calls)
			}
		})
	}
}

func TestProvisionRefusesWhatTheServerMustNotChoose(t *testing.T) {
	tests := map[string]wire.Enrolled{
		"other user":   {NodeID: "n", InstanceID: "i", SSHUser: "root", AuthorizedKey: publicKey(t)},
		"junk key":     {NodeID: "n", InstanceID: "i", SSHUser: "supermgmt", AuthorizedKey: "nope"},
		"options key":  {NodeID: "n", InstanceID: "i", SSHUser: "supermgmt", AuthorizedKey: `command="rm -rf /" ` + publicKey(t)},
		"bad instance": {NodeID: "n", InstanceID: "i i", SSHUser: "supermgmt", AuthorizedKey: publicKey(t)},
	}
	for name, e := range tests {
		t.Run(name, func(t *testing.T) {
			host := newFakeHost()

			if err := Provision(context.Background(), host, e); err == nil {
				t.Fatal("want a refusal")
			}
			if len(host.calls) != 0 {
				t.Fatalf("calls = %v, want nothing done", host.calls)
			}
		})
	}
}

func TestProvisionGrantsNothingBeyondTheKey(t *testing.T) {
	host := newFakeHost()

	if err := Provision(context.Background(), host, enrolledWith(publicKey(t))); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	for _, call := range host.calls {
		if strings.Contains(call, "sudoers") || strings.Contains(call, "group") {
			t.Errorf("unexpected step %q: join writes no sudoers and joins no group (ADR-0022)", call)
		}
	}
}

func count(calls []string, call string) int {
	n := 0
	for _, c := range calls {
		if c == call {
			n++
		}
	}
	return n
}

func wantCode(t *testing.T, err error, code smerr.Code) {
	t.Helper()
	if got := smerr.CodeOf(err); got != code {
		t.Fatalf("err = %v (code %q), want %q", err, got, code)
	}
}
