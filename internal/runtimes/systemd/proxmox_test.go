package systemd

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/pveid"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const (
	pveSecret   = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
	pveInstance = "inst-1"
)

// pveNode is a setup node that is a Proxmox VE host: pveversion, pveum users,
// roles, ACLs and tokens, socat and the root CA, all with state.
type pveNode struct {
	*setupNode
	version  string // pveversion output; "" means the tool is missing
	socat    bool
	aptRuns  int
	ca       string
	hostname string

	users  map[string]string // userid -> comment
	roles  map[string]string // role -> privs
	tokens map[string]string // tokenid -> comment
	loose  map[string]bool   // tokenid -> privilege separation switched off
	acls   []string
}

func newPVENode(t *testing.T) *pveNode {
	n := &pveNode{
		setupNode: newSetupNode(t), version: "pve-manager/9.0.3/abcdef (running kernel: 6.14.8-2-pve)\n",
		ca: testCAPEM(t), hostname: "pve1\n",
		users: map[string]string{}, roles: map[string]string{}, tokens: map[string]string{}, loose: map[string]bool{},
	}
	n.on(templates.PVEVersionStep, func(templates.Command) transport.Result {
		if n.version == "" {
			return transport.Result{ExitStatus: 127}
		}
		return transport.Result{Stdout: []byte(n.version)}
	})
	n.on(templates.PVEUserListStep, func(templates.Command) transport.Result {
		return n.rows(n.users, "userid", "comment")
	})
	n.on(templates.PVERoleListStep, func(templates.Command) transport.Result { return n.rows(n.roles, "roleid", "privs") })
	n.on(templates.PVETokenListStep, func(templates.Command) transport.Result {
		var rows []string
		for id, comment := range n.tokens {
			rows = append(rows, fmt.Sprintf(`{"tokenid":%q,"comment":%q,"privsep":%d}`, id, comment, map[bool]int{false: 1, true: 0}[n.loose[id]]))
		}
		return transport.Result{Stdout: []byte("[" + strings.Join(rows, ",") + "]")}
	})
	n.on(templates.PVEUserAddStep, func(c templates.Command) transport.Result {
		n.users[argument(c.Line, 0)] = argument(c.Line, 1)
		return transport.Result{}
	})
	n.on(templates.PVERoleAddStep, func(c templates.Command) transport.Result {
		n.roles[argument(c.Line, 0)] = argument(c.Line, 1)
		return transport.Result{}
	})
	n.on(templates.PVEACLAddUserStep, func(c templates.Command) transport.Result {
		n.acls = append(n.acls, argument(c.Line, 0)+"|"+argument(c.Line, 1)+"|user|"+argument(c.Line, 2))
		return transport.Result{}
	})
	n.on(templates.PVEACLAddTokenStep, func(c templates.Command) transport.Result {
		n.acls = append(n.acls, argument(c.Line, 0)+"|"+argument(c.Line, 1)+"|token|"+argument(c.Line, 2))
		return transport.Result{}
	})
	n.on(templates.PVETokenAddStep, func(c templates.Command) transport.Result {
		user, id := argument(c.Line, 0), argument(c.Line, 1)
		n.tokens[id] = argument(c.Line, 2)
		delete(n.loose, id)
		return transport.Result{Stdout: []byte(fmt.Sprintf(`{"full-tokenid":%q,"info":{"privsep":1},"value":%q}`, user+"!"+id, pveSecret))}
	})
	n.on(templates.PVETokenRemoveStep, func(c templates.Command) transport.Result {
		delete(n.tokens, argument(c.Line, 1))
		return transport.Result{}
	})
	n.on(templates.PVERootCAStep, func(templates.Command) transport.Result { return transport.Result{Stdout: []byte(n.ca)} })
	n.on(templates.AptInstallSocatStep, func(templates.Command) transport.Result {
		n.aptRuns++
		n.socat = true
		return transport.Result{}
	})
	n.on(templates.SocatPathRead, func(templates.Command) transport.Result {
		if !n.socat {
			return transport.Result{ExitStatus: 1}
		}
		return transport.Result{Stdout: []byte("/usr/bin/socat\n")}
	})
	n.on(templates.HostnameRead, func(templates.Command) transport.Result { return transport.Result{Stdout: []byte(n.hostname)} })
	return n
}

// rows lists a map as the JSON array pveum prints; value is the field named valueKey.
func (n *pveNode) rows(m map[string]string, idKey, valueKey string) transport.Result {
	var rows []string
	for id, v := range m {
		rows = append(rows, fmt.Sprintf(`{%q:%q,%q:%q}`, idKey, id, valueKey, v))
	}
	return transport.Result{Stdout: []byte("[" + strings.Join(rows, ",") + "]")}
}

// touched says whether anything on the node was changed.
func (n *pveNode) touched() bool {
	for _, name := range n.ran() {
		if strings.HasPrefix(name, "setup.user_add") || strings.Contains(name, "pve_user_add") || strings.Contains(name, "pve_token") && strings.Contains(name, "add") ||
			strings.Contains(name, "apt_install") || strings.Contains(name, "file_stage") {
			return true
		}
	}
	return false
}

// proxmoxRecorder records what the step handed to its callbacks.
type proxmoxRecorder struct {
	stored  []string
	secrets []audit.Secret
	removed []string
	owned   []string // the role journal, as the caller keeps it between runs
	// roleAddsAtJournal is how many role-add commands had run at each journal call.
	roleAddsAtJournal []int
	journalErr        error
	node              *pveNode
}

func (r *proxmoxRecorder) params(tokenStored bool) *ProxmoxParams {
	return &ProxmoxParams{
		InstanceID: pveInstance, TokenStored: tokenStored, OwnedRoles: r.owned,
		StoreToken: func(_ context.Context, id string, s audit.Secret) error {
			r.stored, r.secrets = append(r.stored, id), append(r.secrets, s)
			return nil
		},
		TokenRemoved: func(_ context.Context, id string) error { r.removed = append(r.removed, id); return nil },
		RoleOwned: func(_ context.Context, role string) error {
			if r.node != nil {
				r.roleAddsAtJournal = append(r.roleAddsAtJournal, r.node.count(templates.PVERoleAddStep))
			}
			if r.journalErr != nil {
				return r.journalErr
			}
			if !slices.Contains(r.owned, role) {
				r.owned = append(r.owned, role)
			}
			return nil
		},
	}
}

func setupWithProxmox(t *testing.T, n *pveNode, r *proxmoxRecorder, tokenStored bool) (SetupOutcome, error) {
	t.Helper()
	p := setupParams()
	p.InstanceID = pveInstance
	p.Proxmox = r.params(tokenStored)
	return Setup(context.Background(), n, p)
}

func index(names []string, want string) int {
	for i, n := range names {
		if n == want {
			return i
		}
	}
	return -1
}

func TestProxmoxStepCreatesTheIdentityAndHandsOverTheSecret(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	out, err := setupWithProxmox(t, n, r, false)
	if err != nil {
		t.Fatal(err)
	}
	user := pveid.User(pveInstance)
	if len(r.stored) != 1 || r.stored[0] != pveid.Token(pveInstance) || r.secrets[0].Reveal() != pveSecret || len(r.removed) != 0 {
		t.Errorf("stored %v removed %v", r.stored, r.removed)
	}
	want := ProxmoxOutcome{CAPEM: n.ca, Hostname: "pve1", SocatPath: "/usr/bin/socat", TokenID: user + "!sm"}
	if *out.Proxmox != want {
		t.Errorf("outcome = %+v", *out.Proxmox)
	}
	if n.users[user] != pveid.Mark(pveInstance) || n.tokens["sm"] != pveid.Mark(pveInstance) || len(n.roles) != 2 || len(n.acls) != 4 {
		t.Errorf("host state: users %v roles %v tokens %v acls %v", n.users, n.roles, n.tokens, n.acls)
	}
	ran := n.ran()
	if index(ran, templates.PVEVersionStep) > index(ran, "setup.user_add") {
		t.Errorf("pveversion must come before the first change: %v", ran)
	}
	if index(ran, templates.PVETokenAddStep) < index(ran, "setup.sudoers_check") || index(ran, templates.PVETokenAddStep) > index(ran, "setup.own_file_stage") {
		t.Errorf("the proxmox step belongs after the sudoers and before authorized_keys: %v", ran)
	}
	if strings.Contains(fmt.Sprintf("%+v %v", out, n.lines()), pveSecret) {
		t.Error("the secret reached the outcome or a command line")
	}
}

func TestProxmoxStepRefusesWhatIsNotPVE9BeforeAnyChange(t *testing.T) {
	for name, version := range map[string]string{
		"pve 8":          "pve-manager/8.4.1/abc (running kernel: 6.8.12-4-pve)\n",
		"no pveversion":  "",
		"unreadable":     "hello\n",
		"future version": "pve-manager/10.0.1/abc\n",
	} {
		n, r := newPVENode(t), &proxmoxRecorder{}
		n.version = version
		_, err := setupWithProxmox(t, n, r, false)
		if smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
			t.Errorf("%s: err = %v", name, err)
		}
		if n.touched() || len(r.stored) != 0 || len(n.users) != 0 {
			t.Errorf("%s: something changed: %v", name, n.ran())
		}
	}
}

func TestProxmoxStepInstallsSocatWhenAbsent(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	out, err := setupWithProxmox(t, n, r, false)
	if err != nil || n.aptRuns != 1 || out.Proxmox.SocatPath != "/usr/bin/socat" {
		t.Fatalf("apt runs %d, err %v", n.aptRuns, err)
	}
	n2, r2 := newPVENode(t), &proxmoxRecorder{}
	n2.socat = true
	if _, err := setupWithProxmox(t, n2, r2, false); err != nil || n2.aptRuns != 0 {
		t.Errorf("socat present: apt runs %d, err %v", n2.aptRuns, err)
	}
	n3, r3 := newPVENode(t), &proxmoxRecorder{}
	n3.on(templates.AptInstallSocatStep, ok) // apt "works" but installs nothing
	if _, err := setupWithProxmox(t, n3, r3, false); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable || len(n3.users) != 0 {
		t.Errorf("socat still absent: err %v, users %v", err, n3.users)
	}
}

func TestProxmoxStepRefusesForeignObjectsAndAdoptsNone(t *testing.T) {
	user := pveid.User(pveInstance)
	cases := map[string]func(*pveNode){
		"user": func(n *pveNode) { n.users[user] = "somebody else's" },
		"role": func(n *pveNode) { n.roles[pveid.AuditRole(pveInstance)] = "Sys.Modify" },
		"role with our privileges": func(n *pveNode) {
			n.roles[pveid.AuditRole(pveInstance)] = "Datastore.Audit,Pool.Audit,Sys.Audit,VM.Audit"
		},
		"token": func(n *pveNode) { n.users[user] = pveid.Mark(pveInstance); n.tokens["sm"] = "mine, honest" },
	}
	for name, setup := range cases {
		n, r := newPVENode(t), &proxmoxRecorder{}
		setup(n)
		_, err := setupWithProxmox(t, n, r, false)
		if smerr.CodeOf(err) != smerr.CodeConflict {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(r.stored) != 0 || len(r.removed) != 0 || n.count(templates.PVETokenRemoveStep) != 0 {
			t.Errorf("%s: touched a foreign object: %v", name, n.ran())
		}
		if n.count(templates.PVEACLAddTokenStep) != 0 || strings.HasPrefix(name, "role") && len(n.acls) != 0 {
			t.Errorf("%s: granted something after the refusal: %v", name, n.acls)
		}
		if name == "token" && n.tokens["sm"] != "mine, honest" {
			t.Error("the foreign token was replaced")
		}
	}
}

func TestProxmoxStepRecreatesAnOwnedTokenWhoseSecretIsLost(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	if _, err := setupWithProxmox(t, n, r, false); err != nil {
		t.Fatal(err)
	}
	r2 := &proxmoxRecorder{owned: r.owned}
	if _, err := setupWithProxmox(t, n, r2, false); err != nil {
		t.Fatal(err)
	}
	if len(r2.removed) != 1 || r2.removed[0] != pveid.Token(pveInstance) || len(r2.stored) != 1 {
		t.Errorf("removed %v stored %v", r2.removed, r2.stored)
	}
	if n.count(templates.PVETokenRemoveStep) != 1 || n.count(templates.PVETokenAddStep) != 2 || n.count(templates.PVEUserAddStep) != 1 {
		t.Errorf("ran %v", n.ran())
	}
}

func TestProxmoxStepRerunWithTheSecretStoredCreatesNothing(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	if _, err := setupWithProxmox(t, n, r, false); err != nil {
		t.Fatal(err)
	}
	r2 := &proxmoxRecorder{owned: r.owned}
	out, err := setupWithProxmox(t, n, r2, true)
	if err != nil || len(r2.stored) != 0 || len(r2.removed) != 0 || out.Proxmox.TokenID != pveid.Token(pveInstance) {
		t.Fatalf("stored %v removed %v err %v", r2.stored, r2.removed, err)
	}
	if n.count(templates.PVETokenAddStep) != 1 || n.count(templates.PVEUserAddStep) != 1 || n.count(templates.PVERoleAddStep) != 2 {
		t.Errorf("ran %v", n.ran())
	}
}

func TestProxmoxStepNeverQuotesTheTokenInAnError(t *testing.T) {
	leaky := map[string]transport.Result{
		"exit":       {ExitStatus: 1, Stdout: []byte(pveSecret), Stderr: []byte(pveSecret)},
		"wrong id":   {Stdout: []byte(fmt.Sprintf(`{"full-tokenid":"x@pve!sm","value":%q}`, pveSecret))},
		"extra data": {Stdout: []byte(fmt.Sprintf(`{"full-tokenid":"%s!sm","value":%q} %s`, pveid.User(pveInstance), pveSecret, pveSecret))},
		"extra key":  {Stdout: []byte(fmt.Sprintf(`{"full-tokenid":"%s!sm","value":%q,"x":%q}`, pveid.User(pveInstance), pveSecret, pveSecret))},
	}
	for name, res := range leaky {
		n, r := newPVENode(t), &proxmoxRecorder{}
		n.on(templates.PVETokenAddStep, func(templates.Command) transport.Result { return res })
		out, err := setupWithProxmox(t, n, r, false)
		if err == nil || strings.Contains(err.Error(), pveSecret) || len(r.stored) != 0 {
			t.Errorf("%s: err %v stored %v", name, err, r.stored)
		}
		if strings.Contains(fmt.Sprintf("%+v", out), pveSecret) || n.count("setup.own_file_stage") != 0 {
			t.Errorf("%s: outcome leaked or the account became reachable", name)
		}
	}
}

func TestProxmoxStepRefusesAHostWithoutASingleCA(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	n.ca += n.ca
	if _, err := setupWithProxmox(t, n, r, false); smerr.CodeOf(err) != smerr.CodeCapabilityUnavailable {
		t.Errorf("err = %v", err)
	}
}

func TestProxmoxStoreFailureStopsSetupBeforeTheKey(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	p := setupParams()
	p.InstanceID = pveInstance
	p.Proxmox = r.params(false)
	p.Proxmox.StoreToken = func(context.Context, string, audit.Secret) error { return fmt.Errorf("disk full") }
	_, err := Setup(context.Background(), n, p)
	if err == nil || !strings.Contains(err.Error(), "disk full") || n.count("setup.own_file_stage") != 0 {
		t.Errorf("err = %v", err)
	}
}

func TestProxmoxParamsAreValidated(t *testing.T) {
	r := &proxmoxRecorder{}
	for name, p := range map[string]ProxmoxParams{
		"bad id":       {InstanceID: "a b", StoreToken: r.params(false).StoreToken, TokenRemoved: r.params(false).TokenRemoved, RoleOwned: r.params(false).RoleOwned},
		"no store":     {InstanceID: pveInstance, TokenRemoved: r.params(false).TokenRemoved, RoleOwned: r.params(false).RoleOwned},
		"no remove cb": {InstanceID: pveInstance, StoreToken: r.params(false).StoreToken, RoleOwned: r.params(false).RoleOwned},
		"no journal":   {InstanceID: pveInstance, StoreToken: r.params(false).StoreToken, TokenRemoved: r.params(false).TokenRemoved},
	} {
		if smerr.CodeOf(p.Validate()) != smerr.CodeInvalidArgument {
			t.Errorf("%s: %v", name, p.Validate())
		}
	}
}

func TestProxmoxStepReusesRolesTheLastRunRecordedAndRefusesOthers(t *testing.T) {
	n := newPVENode(t)
	n.roles[pveid.AuditRole(pveInstance)] = "Datastore.Audit,Pool.Audit,Sys.Audit,VM.Audit"
	r := &proxmoxRecorder{owned: []string{pveid.AuditRole(pveInstance)}}
	if _, err := setupWithProxmox(t, n, r, false); err != nil {
		t.Fatal(err)
	}
	if n.count(templates.PVERoleAddStep) != 1 || !slices.Contains(r.owned, pveid.PowerRole(pveInstance)) {
		t.Errorf("the journaled role was not reused: ran %v, journal %v", n.ran(), r.owned)
	}
	n2 := newPVENode(t)
	n2.roles[pveid.AuditRole(pveInstance)] = "Sys.Modify"
	r2 := &proxmoxRecorder{owned: []string{pveid.AuditRole(pveInstance)}}
	if _, err := setupWithProxmox(t, n2, r2, false); smerr.CodeOf(err) != smerr.CodeConflict {
		t.Errorf("a recorded role whose privileges changed: err = %v", err)
	}
}

func TestProxmoxStepStoresTheSecretBeforeTheFirstTokenGrant(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	p := setupParams()
	p.InstanceID = pveInstance
	p.Proxmox = r.params(false)
	grantsAtStore := -1
	p.Proxmox.StoreToken = func(context.Context, string, audit.Secret) error {
		grantsAtStore = n.count(templates.PVEACLAddTokenStep)
		return nil
	}
	if _, err := Setup(context.Background(), n, p); err != nil {
		t.Fatal(err)
	}
	if grantsAtStore != 0 || n.count(templates.PVEACLAddTokenStep) != 2 {
		t.Errorf("token grants at store time %d, in total %d", grantsAtStore, n.count(templates.PVEACLAddTokenStep))
	}
}

func TestProxmoxStepGrantsNothingToATokenWhoseSecretCouldNotBeStored(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	p := setupParams()
	p.InstanceID = pveInstance
	p.Proxmox = r.params(false)
	p.Proxmox.StoreToken = func(context.Context, string, audit.Secret) error { return fmt.Errorf("disk full") }
	if _, err := Setup(context.Background(), n, p); err == nil {
		t.Fatal("setup went on")
	}
	if n.count(templates.PVEACLAddTokenStep) != 0 {
		t.Errorf("token grants after a failed store: %v", n.acls)
	}
}

func TestProxmoxStepRecreatesAnOwnedTokenThatIsNotPrivilegeSeparated(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	if _, err := setupWithProxmox(t, n, r, false); err != nil {
		t.Fatal(err)
	}
	n.loose["sm"] = true
	r2 := &proxmoxRecorder{owned: r.owned}
	if _, err := setupWithProxmox(t, n, r2, true); err != nil {
		t.Fatal(err)
	}
	if len(r2.removed) != 1 || len(r2.stored) != 1 || r2.secrets[0].Reveal() != pveSecret || n.loose["sm"] {
		t.Errorf("removed %v stored %v loose %v", r2.removed, r2.stored, n.loose)
	}
	if n.count(templates.PVETokenRemoveStep) != 1 || n.count(templates.PVETokenAddStep) != 2 {
		t.Errorf("ran %v", n.ran())
	}
}

func TestProxmoxStepRerunReusesTheRolesAFailedRunCreated(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	n.on(templates.PVETokenAddStep, func(templates.Command) transport.Result {
		return transport.Result{ExitStatus: 1, Stderr: []byte("boom")}
	})
	if _, err := setupWithProxmox(t, n, r, false); err == nil {
		t.Fatal("the first run went on")
	}
	if len(n.roles) != 2 || len(r.owned) != 2 {
		t.Fatalf("roles %v journal %v", n.roles, r.owned)
	}
	healthy := newPVENode(t)
	healthy.users, healthy.roles = n.users, n.roles
	r2 := &proxmoxRecorder{owned: r.owned}
	if _, err := setupWithProxmox(t, healthy, r2, false); err != nil {
		t.Fatalf("the rerun refused its own roles: %v", err)
	}
	if healthy.count(templates.PVERoleAddStep) != 0 || len(healthy.tokens) != 1 {
		t.Errorf("ran %v", healthy.ran())
	}
}

func TestProxmoxStepJournalsEachRoleBeforeCreatingIt(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{}
	r.node = n
	if _, err := setupWithProxmox(t, n, r, false); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.roleAddsAtJournal, []int{0, 1}) {
		t.Errorf("role-add commands already run at each journal call: %v", r.roleAddsAtJournal)
	}
}

func TestProxmoxStepCreatesNoRoleWhenTheJournalFails(t *testing.T) {
	n, r := newPVENode(t), &proxmoxRecorder{journalErr: fmt.Errorf("lease lost")}
	_, err := setupWithProxmox(t, n, r, false)
	if err == nil || !strings.Contains(err.Error(), "lease lost") {
		t.Fatalf("err = %v", err)
	}
	if n.count(templates.PVERoleAddStep) != 0 || len(n.roles) != 0 {
		t.Errorf("a role was created without a journal: %v", n.ran())
	}
}
