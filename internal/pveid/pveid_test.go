package pveid

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/internal/audit"
)

var bg = context.Background()

// fakeHost records what an identity creation does, in order.
type fakeHost struct {
	log       []string
	users     map[string]bool
	roles     map[string]bool
	tokens    map[string]bool
	failToken error
}

func newFakeHost() *fakeHost {
	return &fakeHost{users: map[string]bool{}, roles: map[string]bool{}, tokens: map[string]bool{}}
}

func (h *fakeHost) note(format ...string) { h.log = append(h.log, strings.Join(format, " ")) }

func (h *fakeHost) UserExists(_ context.Context, u string) (bool, error) { return h.users[u], nil }
func (h *fakeHost) CreateUser(_ context.Context, u, comment string) error {
	h.note("user", u, comment)
	h.users[u] = true
	return nil
}
func (h *fakeHost) RemoveUser(_ context.Context, u string) error { h.note("rmuser", u); return nil }
func (h *fakeHost) RoleExists(_ context.Context, r string) (bool, error) {
	return h.roles[r], nil
}

func (h *fakeHost) CreateRole(_ context.Context, r string, privs []string) error {
	h.note("role", r, strings.Join(privs, ","))
	h.roles[r] = true
	return nil
}
func (h *fakeHost) RemoveRole(_ context.Context, r string) error { h.note("rmrole", r); return nil }
func (h *fakeHost) ACLs(context.Context) ([]ACL, error)          { return nil, nil }
func (h *fakeHost) AddACL(_ context.Context, a ACL) error        { h.note("acl", ACLName(a)); return nil }

func (h *fakeHost) RemoveACL(_ context.Context, a ACL) error { h.note("rmacl", ACLName(a)); return nil }

func (h *fakeHost) TokenExists(_ context.Context, u, id string) (bool, error) {
	return h.tokens[u+"!"+id], nil
}

func (h *fakeHost) AddToken(_ context.Context, u, id string) (audit.Secret, error) {
	h.note("token", u, id)
	if h.failToken != nil {
		return "", h.failToken
	}
	return "0123456789abcdef", nil
}

func (h *fakeHost) RemoveToken(_ context.Context, u, id string) error {
	h.note("rmtoken", u, id)
	return nil
}

func TestNamesAreDerivedFromTheID(t *testing.T) {
	if User("ab12") != "sm-ab12@pve" || AuditRole("ab12") != "SMAudit-ab12" || PowerRole("ab12") != "SMPower-ab12" ||
		Token("ab12") != "sm-ab12@pve!sm" || Mark("ab12") != "supermgmt install ab12" {
		t.Error("derived names changed")
	}
	if TokenComment(User("ab12")) != Mark("ab12") {
		t.Errorf("token comment = %q", TokenComment(User("ab12")))
	}
}

func TestCreateIdentitiesOrderAndPower(t *testing.T) {
	h := newFakeHost()
	if err := CreateIdentities(bg, h, "ab12", true, Unjournaled{}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"user sm-ab12@pve supermgmt install ab12",
		"role SMAudit-ab12 VM.Audit,Sys.Audit,Datastore.Audit,Pool.Audit",
		"role SMPower-ab12 VM.Audit,VM.PowerMgmt",
		"acl /|SMAudit-ab12|u:sm-ab12@pve",
		"acl /vms|SMPower-ab12|u:sm-ab12@pve",
	}
	if !slices.Equal(h.log, want) {
		t.Errorf("log = %q", h.log)
	}
	h = newFakeHost()
	if err := CreateIdentities(bg, h, "ab12", false, Unjournaled{}); err != nil || len(h.log) != 3 {
		t.Errorf("without power: %q, %v", h.log, err)
	}
}

func TestCreateTokenReturnsTheSecretBeforeAnyGrant(t *testing.T) {
	h := newFakeHost()
	secret, err := CreateToken(bg, h, "ab12", Unjournaled{})
	if err != nil || secret.Reveal() != "0123456789abcdef" {
		t.Fatalf("secret %v err %v", secret, err)
	}
	if want := []string{"token sm-ab12@pve sm"}; !slices.Equal(h.log, want) {
		t.Errorf("log = %q", h.log)
	}
	if err := GrantToken(bg, h, "ab12", true, Unjournaled{}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"token sm-ab12@pve sm",
		"acl /|SMAudit-ab12|t:sm-ab12@pve!sm",
		"acl /vms|SMPower-ab12|t:sm-ab12@pve!sm",
	}
	if !slices.Equal(h.log, want) {
		t.Errorf("log = %q", h.log)
	}
}

func TestAnExistingObjectIsRefusedAndNothingElseIsDone(t *testing.T) {
	cases := map[string]func(*fakeHost){
		"user":  func(h *fakeHost) { h.users["sm-ab12@pve"] = true },
		"role":  func(h *fakeHost) { h.roles["SMAudit-ab12"] = true },
		"token": nil,
	}
	for kind, setup := range cases {
		h := newFakeHost()
		var err error
		if kind == "token" {
			h.tokens["sm-ab12@pve!sm"] = true
			_, err = CreateToken(bg, h, "ab12", Unjournaled{})
		} else {
			setup(h)
			err = CreateIdentities(bg, h, "ab12", false, Unjournaled{})
		}
		var foreign *ForeignError
		var failure *Failure
		if !errors.As(err, &foreign) || !errors.As(err, &failure) || foreign.Kind != kind {
			t.Errorf("%s: err = %v", kind, err)
		}
		for _, line := range h.log {
			if strings.HasPrefix(line, "acl") || strings.HasPrefix(line, "token") {
				t.Errorf("%s: went on after the refusal: %q", kind, h.log)
			}
		}
	}
}

func TestAFailedTokenCreationIsReportedWithoutItsOutput(t *testing.T) {
	h := newFakeHost()
	h.failToken = errors.New("pveum could not create the API token")
	_, err := CreateToken(bg, h, "ab12", Unjournaled{})
	var failure *Failure
	if !errors.As(err, &failure) || failure.What != "create the Proxmox token" {
		t.Errorf("err = %v", err)
	}
	if len(h.log) != 1 {
		t.Errorf("an ACL was granted to a token that does not exist: %q", h.log)
	}
}

func TestValidatorsRefuseWhatCouldBecomeAnOption(t *testing.T) {
	for _, v := range []string{"", "-x", "a b", "a;b", "a\nb", "a", "a@"} {
		if ValidUserID(v) == nil {
			t.Errorf("user %q accepted", v)
		}
	}
	for _, v := range []string{"", "-x", "a b", "a;b", "a\nb", "a@pve", "a/b"} {
		if ValidName("role", v) == nil {
			t.Errorf("name %q accepted", v)
		}
	}
	for _, a := range []ACL{
		{Path: "/", Role: "R"},
		{Path: "/", Role: "R", User: "u@pve", Token: "u@pve!t"},
		{Path: "/../x", Role: "R", User: "u@pve"},
		{Path: "/", Role: "R", Token: "u@pve"},
		{Path: "/", Role: "-R", User: "u@pve"},
	} {
		if err := ValidACL(a); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%+v accepted (%v)", a, err)
		}
	}
	if ValidACL(ACL{Path: "/vms", Role: "R", Token: "u@pve!t"}) != nil {
		t.Error("a good token ACL was refused")
	}
}
