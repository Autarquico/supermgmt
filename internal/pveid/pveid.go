// Package pveid is the Proxmox identity SuperMgmt creates for itself: the user,
// its audit and power roles, the ACLs and the API token (ADR-0023, ADR-0026).
// The appliance installer and node setup share it, so both derive the same
// names, grant the same privileges and refuse a foreign object the same way.
package pveid

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
)

// TokenID is the id of the API token under the SuperMgmt user.
const TokenID = "sm"

// Mark is the ownership proof an object carries: the install (or setup) id it
// was created by. A same-named object without it is somebody else's.
func Mark(id string) string { return "supermgmt install " + id }

// User, AuditRole and PowerRole are derived from the id and nothing else: a
// name that is not the derived one is never acted on.
func User(id string) string      { return "sm-" + id + "@pve" }
func AuditRole(id string) string { return "SMAudit-" + id }
func PowerRole(id string) string { return "SMPower-" + id }

// Token is the full token id user@pve!sm.
func Token(id string) string { return User(id) + "!" + TokenID }

// TokenComment is the ownership mark of a token: the id its user was derived
// from. A token without it was not created under that id.
func TokenComment(user string) string {
	return Mark(strings.TrimSuffix(strings.TrimPrefix(user, "sm-"), "@pve"))
}

var (
	auditPrivileges = []string{"VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit"}
	// VM.Audit is repeated because PVE replaces inherited permissions at a deeper path (ADR-0023).
	powerPrivileges = []string{"VM.Audit", "VM.PowerMgmt"}
)

// Grant is one role with the privileges it carries and the path it is granted on.
type Grant struct {
	Role       string
	Privileges []string
	Path       string
}

// Grants are the roles of an identity: audit always, power only on request.
func Grants(id string, power bool) []Grant {
	grants := []Grant{{AuditRole(id), auditPrivileges, "/"}}
	if power {
		grants = append(grants, Grant{PowerRole(id), powerPrivileges, "/vms"})
	}
	return grants
}

// ACL is one access-control entry; exactly one of User and Token is set.
type ACL struct {
	Path  string
	Role  string
	User  string
	Token string // user@realm!tokenid
}

// Host is the Proxmox user, role, ACL and token administration an identity is
// created through (and a token replaced through; the rest of its removal is the
// installer's): pveum run by the installer on the host, or over SSH by node
// setup.
type Host interface {
	UserExists(ctx context.Context, user string) (bool, error)
	CreateUser(ctx context.Context, user, comment string) error
	RoleExists(ctx context.Context, role string) (bool, error)
	CreateRole(ctx context.Context, role string, privileges []string) error
	AddACL(ctx context.Context, acl ACL) error
	// TokenExists is true only for a token this identity owns (TokenComment).
	TokenExists(ctx context.Context, user, id string) (bool, error)
	// AddToken creates a privilege-separated token and returns its secret,
	// read from the command's captured output only.
	AddToken(ctx context.Context, user, id string) (audit.Secret, error)
	RemoveToken(ctx context.Context, user, id string) error
}

// ErrInvalidArgument marks a value refused before any command is built.
var ErrInvalidArgument = errors.New("invalid argument")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}

var (
	reName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reUserID    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}@[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
	rePrivilege = regexp.MustCompile(`^[A-Z][A-Za-z.]{1,63}$`)
	reACLPath   = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)
)

// ValidName accepts a plain Proxmox name (role, token id, storage...).
func ValidName(kind, v string) error {
	if !reName.MatchString(v) {
		return invalidf("%s %q is not a plain name", kind, v)
	}
	return nil
}

// ValidUserID accepts user@realm.
func ValidUserID(v string) error {
	if !reUserID.MatchString(v) {
		return invalidf("user %q is not user@realm", v)
	}
	return nil
}

// ValidText accepts printable ASCII that cannot be read as an option.
func ValidText(kind, v string) error {
	if v == "" || len(v) > 255 || strings.HasPrefix(v, "-") {
		return invalidf("%s %q is empty, too long or starts with a dash", kind, v)
	}
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			return invalidf("%s contains a control or non-ASCII character", kind)
		}
	}
	return nil
}

// ValidPrivilege accepts one Proxmox privilege name.
func ValidPrivilege(v string) error {
	if !rePrivilege.MatchString(v) {
		return invalidf("privilege %q", v)
	}
	return nil
}

// ValidPrivileges accepts a non-empty privilege list.
func ValidPrivileges(privileges []string) error {
	if len(privileges) == 0 {
		return invalidf("a role needs privileges")
	}
	for _, priv := range privileges {
		if err := ValidPrivilege(priv); err != nil {
			return err
		}
	}
	return nil
}

// ValidACLPath accepts an absolute ACL path without "..".
func ValidACLPath(v string) error {
	if !reACLPath.MatchString(v) || strings.Contains(v, "..") {
		return invalidf("ACL path %q", v)
	}
	return nil
}

// ValidTokenName accepts user@realm!id.
func ValidTokenName(v string) error {
	user, id, ok := strings.Cut(v, "!")
	if !ok {
		return invalidf("token %q is not user@realm!id", v)
	}
	return ValidToken(user, id)
}

// ValidToken accepts a token's user and id.
func ValidToken(user, id string) error {
	if err := ValidUserID(user); err != nil {
		return err
	}
	return ValidName("token id", id)
}

// ValidACL accepts an ACL naming exactly one of a user and a token.
func ValidACL(a ACL) error {
	if err := ValidACLPath(a.Path); err != nil {
		return err
	}
	if err := ValidName("role", a.Role); err != nil {
		return err
	}
	if (a.User == "") == (a.Token == "") {
		return invalidf("an ACL names exactly one of user and token")
	}
	if a.User != "" {
		return ValidUserID(a.User)
	}
	return ValidTokenName(a.Token)
}
