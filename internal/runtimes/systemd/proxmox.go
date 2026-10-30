package systemd

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/pveid"
	"github.com/autarquico/supermgmt/internal/textsafe"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

// proxmoxPower: the token carries the power role as well as the audit one, so
// the provider can start and stop guests through the node (spec: same scope as
// the appliance's).
const proxmoxPower = true

// ProxmoxParams switch on the Proxmox step of node.setup (--proxmox). The
// token's secret never leaves the step through its outcome: StoreToken receives
// it the moment pveum prints it.
type ProxmoxParams struct {
	// InstanceID derives every identity name; the same id on every run is what
	// makes the objects found on the host ours.
	InstanceID string
	// TokenStored says the secret store holds the token's secret. An owned
	// token on the host without it is deleted and created again.
	TokenStored bool
	// StoreToken keeps the secret ("user@realm!id=secret" is the caller's to
	// build) before anything else is done with it. tokenID is the public id.
	StoreToken func(ctx context.Context, tokenID string, secret audit.Secret) error
	// TokenRemoved records the owned token the step deleted, by public id.
	TokenRemoved func(ctx context.Context, tokenID string) error
}

// Validate checks the parameters before anything touches the node.
func (p ProxmoxParams) Validate() error {
	if err := pveid.ValidToken(pveid.User(p.InstanceID), pveid.TokenID); err != nil {
		return invalid("instance id: " + err.Error())
	}
	if p.StoreToken == nil || p.TokenRemoved == nil {
		return invalid("proxmox: StoreToken and TokenRemoved are required")
	}
	return nil
}

// ProxmoxOutcome is what the step found out about the host: public values only.
type ProxmoxOutcome struct {
	CAPEM     string // the cluster root CA, canonical PEM
	Hostname  string // hostname -s
	SocatPath string // where the relay's socat lives
	TokenID   string // user@realm!id
}

// requirePVE refuses a node that is not a Proxmox VE 9 host, before any change.
func (s stepper) requirePVE(ctx context.Context) error {
	res, err := s.run(ctx, templates.PVEVersionStep, nil, nil)
	if err != nil {
		return err
	}
	if res.ExitStatus != 0 {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "--proxmox needs a Proxmox VE host: pveversion did not run on this node")
	}
	version, ok := pveid.ParseManagerVersion(string(res.Stdout))
	if !ok {
		return smerr.New(smerr.CodeCapabilityUnavailable, "", "--proxmox needs a Proxmox VE host: pveversion reported no pve-manager version")
	}
	if major, _, _ := strings.Cut(version, "."); major != fmt.Sprint(pveid.SupportedMajor) {
		return smerr.New(smerr.CodeCapabilityUnavailable, "",
			fmt.Sprintf("Proxmox VE %s is not supported; only %d.x is", textsafe.Line(version), pveid.SupportedMajor))
	}
	return nil
}

// ensureProxmox creates or verifies the instance's identities and token, hands
// the secret to p.StoreToken and reads the CA and the hostname. requirePVE has
// already passed.
func (s stepper) ensureProxmox(ctx context.Context, p ProxmoxParams) (*ProxmoxOutcome, error) {
	socat, err := s.ensureSocat(ctx)
	if err != nil {
		return nil, err
	}
	h := newPVEHost(s, p.InstanceID)
	if err := pveid.CreateIdentities(ctx, h, p.InstanceID, proxmoxPower, ownedRecorder{}); err != nil {
		return nil, proxmoxError(err)
	}
	if err := s.ensureToken(ctx, h, p); err != nil {
		return nil, err
	}
	ca, err := s.readRootCA(ctx)
	if err != nil {
		return nil, err
	}
	hostname, err := s.readHostname(ctx)
	if err != nil {
		return nil, err
	}
	return &ProxmoxOutcome{CAPEM: ca, Hostname: hostname, SocatPath: socat, TokenID: pveid.Token(p.InstanceID)}, nil
}

func (s stepper) ensureSocat(ctx context.Context) (string, error) {
	path, err := s.socatPath(ctx)
	if err != nil || path != "" {
		return path, err
	}
	if err := s.do(ctx, templates.AptInstallSocatStep, nil, nil); err != nil {
		return "", err
	}
	if path, err = s.socatPath(ctx); err != nil || path != "" {
		return path, err
	}
	return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "socat is not on the node after installing it")
}

// socatPath is the socat the relay will run, "" when there is none.
func (s stepper) socatPath(ctx context.Context) (string, error) {
	res, err := read(ctx, s.ex, templates.SocatPathRead, nil)
	if err != nil {
		return "", err
	}
	if res.ExitStatus != 0 {
		return "", nil
	}
	path := strings.TrimSpace(string(res.Stdout))
	if err := templates.ValidateRelayPath(path); err != nil {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "socat path is not usable for the relay: "+err.Error())
	}
	return path, nil
}

// ensureToken leaves an owned, privilege-separated token on the host and its
// secret in the store: an existing one stays when the store has its secret,
// otherwise it is deleted and created again.
func (s stepper) ensureToken(ctx context.Context, h pveHost, p ProxmoxParams) error {
	user, tokenID := pveid.User(p.InstanceID), pveid.Token(p.InstanceID)
	owned, err := h.TokenExists(ctx, user, pveid.TokenID)
	if err != nil {
		return proxmoxError(err)
	}
	if owned && !p.TokenStored {
		if err := h.RemoveToken(ctx, user, pveid.TokenID); err != nil {
			return fmt.Errorf("remove the Proxmox token: %w", err)
		}
		if err := p.TokenRemoved(ctx, tokenID); err != nil {
			return fmt.Errorf("record the Proxmox token deletion: %w", err)
		}
	}
	secret, err := pveid.CreateToken(ctx, h, p.InstanceID, proxmoxPower, ownedRecorder{})
	if secret != "" {
		if storeErr := p.StoreToken(ctx, tokenID, secret); storeErr != nil {
			return fmt.Errorf("store the Proxmox token: %w", storeErr)
		}
	}
	return proxmoxError(err)
}

func (s stepper) readRootCA(ctx context.Context) (string, error) {
	res, err := s.run(ctx, templates.PVERootCAStep, nil, nil)
	if err != nil {
		return "", err
	}
	if res.ExitStatus != 0 || res.Truncated {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "cannot read "+templates.PVERootCAPath)
	}
	_, canonical, err := pveid.ParseCAPEM(res.Stdout)
	if err != nil {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", templates.PVERootCAPath+" is not a single CA certificate")
	}
	return canonical, nil
}

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func (s stepper) readHostname(ctx context.Context) (string, error) {
	out, err := succeeded(ctx, s.ex, templates.HostnameRead, nil)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(out)
	if !hostnamePattern.MatchString(name) {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", "the node's hostname is not a plain DNS label")
	}
	return name, nil
}

// proxmoxError names a refusal for the job: an object of ours that is not ours
// is a conflict, anything else keeps the code its step gave it.
func proxmoxError(err error) error {
	var foreign *pveid.ForeignError
	if errors.As(err, &foreign) {
		return smerr.New(smerr.CodeConflict, "", foreign.Error())
	}
	return err
}

// ownedRecorder is the pveid.Recorder of node setup: it keeps no journal, and
// an object its host reports as present is ours (pveHost refuses the others),
// so creating it again is skipped.
type ownedRecorder struct{}

func (ownedRecorder) CreateNew(_, _, _ string, exists func() (bool, error), build func() error) error {
	present, err := exists()
	if err != nil || present {
		return err
	}
	return build()
}

func (ownedRecorder) Create(_, _, _ string, build func() error) error { return build() }

// pveHost is pveid.Host over the setup's executor: the fixed pveum templates,
// each run as root (or through sudo).
type pveHost struct {
	s     stepper
	roles map[string][]string // role -> its privileges, sorted
}

var _ pveid.Host = pveHost{}

func newPVEHost(s stepper, id string) pveHost {
	roles := map[string][]string{}
	for _, g := range pveid.Grants(id, proxmoxPower) {
		roles[g.Role] = slices.Sorted(slices.Values(g.Privileges))
	}
	return pveHost{s: s, roles: roles}
}

// list runs a pveum list step and returns its JSON.
func (h pveHost) list(ctx context.Context, step string, args map[string]string) ([]byte, error) {
	res, err := h.s.run(ctx, step, args, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitStatus != 0 || res.Truncated {
		return nil, fmt.Errorf("%s did not complete (exit %d)", step, res.ExitStatus)
	}
	return res.Stdout, nil
}

func (h pveHost) UserExists(ctx context.Context, user string) (bool, error) {
	out, err := h.list(ctx, templates.PVEUserListStep, nil)
	if err != nil {
		return false, err
	}
	present, owned, err := pveid.ParseOwnedUser(out, user)
	if err != nil {
		return false, err
	}
	if present && !owned {
		return false, &pveid.ForeignError{Kind: pveid.ResUser, Name: user}
	}
	return present, nil
}

func (h pveHost) CreateUser(ctx context.Context, user, comment string) error {
	return h.s.do(ctx, templates.PVEUserAddStep, map[string]string{"user": user, "comment": comment}, nil)
}

// RoleExists is true for a role with exactly the privileges setup grants it; a
// same-named role with others is somebody else's.
func (h pveHost) RoleExists(ctx context.Context, role string) (bool, error) {
	out, err := h.list(ctx, templates.PVERoleListStep, nil)
	if err != nil {
		return false, err
	}
	privileges, present, err := pveid.ParseRolePrivileges(out, role)
	if err != nil || !present {
		return false, err
	}
	if !slices.Equal(privileges, h.roles[role]) {
		return false, &pveid.ForeignError{Kind: pveid.ResRole, Name: role}
	}
	return true, nil
}

func (h pveHost) CreateRole(ctx context.Context, role string, privileges []string) error {
	return h.s.do(ctx, templates.PVERoleAddStep, map[string]string{"role": role, "privs": strings.Join(privileges, ",")}, nil)
}

func (h pveHost) AddACL(ctx context.Context, a pveid.ACL) error {
	return h.aclStep(ctx, a)
}

func (h pveHost) aclStep(ctx context.Context, a pveid.ACL) error {
	if err := pveid.ValidACL(a); err != nil {
		return err
	}
	args := map[string]string{"path": a.Path, "role": a.Role}
	if a.User != "" {
		args["user"] = a.User
		return h.s.do(ctx, templates.PVEACLAddUserStep, args, nil)
	}
	args["token"] = a.Token
	return h.s.do(ctx, templates.PVEACLAddTokenStep, args, nil)
}

// TokenExists is true for a token carrying this identity's mark only.
func (h pveHost) TokenExists(ctx context.Context, user, id string) (bool, error) {
	out, err := h.list(ctx, templates.PVETokenListStep, map[string]string{"user": user})
	if err != nil {
		return false, err
	}
	return pveid.ParseOwnedToken(out, user, id)
}

// AddToken refuses a token of that name which is not ours, and otherwise reads
// the secret from the step's output only: whatever else the step printed or
// failed with is dropped by the executor and never reaches an error.
func (h pveHost) AddToken(ctx context.Context, user, id string) (audit.Secret, error) {
	out, err := h.list(ctx, templates.PVETokenListStep, map[string]string{"user": user})
	if err != nil {
		return "", err
	}
	if listed, err := pveid.ParseListed(out, "tokenid", id); err != nil || listed {
		if err == nil {
			err = &pveid.ForeignError{Kind: pveid.ResToken, Name: user + "!" + id}
		}
		return "", err
	}
	res, err := h.s.run(ctx, templates.PVETokenAddStep,
		map[string]string{"user": user, "id": id, "comment": pveid.TokenComment(user)}, nil)
	if err != nil {
		return "", err
	}
	if res.ExitStatus != 0 {
		return "", errors.New("pveum could not create the API token")
	}
	secret, err := pveid.ParseTokenAdd(res.Stdout, user, id)
	if err != nil {
		return "", errors.New("pveum returned an unreadable token answer")
	}
	return secret, nil
}

func (h pveHost) RemoveToken(ctx context.Context, user, id string) error {
	return h.s.do(ctx, templates.PVETokenRemoveStep, map[string]string{"user": user, "id": id}, nil)
}
