package pveid

import (
	"context"
	"fmt"

	"github.com/autarquico/supermgmt/internal/audit"
)

// Resource kinds a Recorder is told about; the installer journals them under
// these names.
const (
	ResUser  = "user"
	ResRole  = "role"
	ResACL   = "acl"
	ResToken = "token"
)

// Journal steps of the installer's S12 (ADR-0026); other callers ignore them.
const (
	StepUser  = "S12a"
	StepRole  = "S12b"
	StepACL   = "S12c"
	StepToken = "S12d"
)

// Recorder wraps each creation of an identity, so a caller can journal it and
// decide what an object that already exists means.
type Recorder interface {
	// CreateNew creates an object that must not exist yet; build runs only
	// when exists says it does not.
	CreateNew(step, resource, name string, exists func() (bool, error), build func() error) error
	// Create runs an idempotent grant.
	Create(step, resource, name string, build func() error) error
}

// Failure is an error with the sentence naming what could not be done.
type Failure struct {
	What string
	Err  error
}

func (f *Failure) Error() string { return f.What + ": " + f.Err.Error() }
func (f *Failure) Unwrap() error { return f.Err }

func failed(what string, err error) error {
	if err == nil {
		return nil
	}
	return &Failure{What: what, Err: err}
}

// ForeignError is the refusal to adopt an object this identity did not create.
type ForeignError struct{ Kind, Name string }

func (e *ForeignError) Error() string {
	return fmt.Sprintf("Proxmox %s %s already exists and was not created by this identity", e.Kind, e.Name)
}

// Unjournaled is the Recorder of a caller that keeps no journal: an existing
// object is refused, a grant is just run.
type Unjournaled struct{}

func (Unjournaled) CreateNew(_, resource, name string, exists func() (bool, error), build func() error) error {
	present, err := exists()
	if err != nil {
		return fmt.Errorf("look up Proxmox %s %s: %w", resource, name, err)
	}
	if present {
		return &ForeignError{Kind: resource, Name: name}
	}
	return build()
}

func (Unjournaled) Create(_, _, _ string, build func() error) error { return build() }

// CreateIdentities creates the user, its roles and the user's ACLs. Anything of
// those names that already exists is refused, never adopted.
func CreateIdentities(ctx context.Context, h Host, id string, power bool, rec Recorder) error {
	user := User(id)
	if err := rec.CreateNew(StepUser, ResUser, user,
		func() (bool, error) { return h.UserExists(ctx, user) },
		func() error { return h.CreateUser(ctx, user, Mark(id)) }); err != nil {
		return failed("create the Proxmox user", err)
	}
	grants := Grants(id, power)
	for _, g := range grants {
		if err := rec.CreateNew(StepRole, ResRole, g.Role,
			func() (bool, error) { return h.RoleExists(ctx, g.Role) },
			func() error { return h.CreateRole(ctx, g.Role, g.Privileges) }); err != nil {
			return failed("create the Proxmox role", err)
		}
	}
	for _, g := range grants {
		if err := grantACL(ctx, h, rec, StepACL, ACL{Path: g.Path, Role: g.Role, User: user}); err != nil {
			return err
		}
	}
	return nil
}

// CreateToken creates the privilege-separated token and grants it the same
// roles as the user. The secret is returned even when a later grant fails, so
// the caller can still dispose of it.
func CreateToken(ctx context.Context, h Host, id string, power bool, rec Recorder) (audit.Secret, error) {
	user := User(id)
	var secret audit.Secret
	if err := rec.CreateNew(StepToken, ResToken, Token(id),
		func() (bool, error) { return h.TokenExists(ctx, user, TokenID) },
		func() (err error) {
			secret, err = h.AddToken(ctx, user, TokenID)
			return err
		}); err != nil {
		return secret, failed("create the Proxmox token", err)
	}
	for _, g := range Grants(id, power) {
		if err := grantACL(ctx, h, rec, StepToken, ACL{Path: g.Path, Role: g.Role, Token: Token(id)}); err != nil {
			return secret, err
		}
	}
	return secret, nil
}

func grantACL(ctx context.Context, h Host, rec Recorder, step string, acl ACL) error {
	return failed("grant the Proxmox role", rec.Create(step, ResACL, ACLName(acl), func() error { return h.AddACL(ctx, acl) }))
}

// ACLName is the journal name of an ACL.
func ACLName(a ACL) string {
	if a.User != "" {
		return a.Path + "|" + a.Role + "|u:" + a.User
	}
	return a.Path + "|" + a.Role + "|t:" + a.Token
}
