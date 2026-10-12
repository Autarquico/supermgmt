package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/autarquico/supermgmt/internal/audit"
)

// The Proxmox tools are run by absolute path with an empty environment plus
// the two variables below, so neither PATH nor the caller's locale can
// redirect or reshape them (ADR-0026).
const (
	pveVersionTool = "/usr/bin/pveversion"
	pctTool        = "/usr/sbin/pct"
	pveamTool      = "/usr/sbin/pveam"
	pveumTool      = "/usr/sbin/pveum"
	pvesmTool      = "/usr/sbin/pvesm"
	pveshTool      = "/usr/bin/pvesh"
	hostnameTool   = "/usr/bin/hostname"
	runuserTool    = "/usr/sbin/runuser"
	envTool        = "/usr/bin/env"

	pveToolPath = "/usr/sbin:/usr/bin:/sbin:/bin"
	maxNextIDs  = 100
)

var errInvalidArgument = errors.New("invalid argument")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errInvalidArgument, fmt.Sprintf(format, args...))
}

var (
	reName       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reUserID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}@[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
	rePrivilege  = regexp.MustCompile(`^[A-Z][A-Za-z.]{1,63}$`)
	reTemplate   = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,127}$`)
	reVolumeID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}:vztmpl/[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$`)
	reHostLabel  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	rePathChars  = regexp.MustCompile(`^[A-Za-z0-9_./+@-]+$`)
	reACLPath    = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)
	reMgrVersion = regexp.MustCompile(`pve-manager/(\d+(?:\.\d+){0,2})`)
	reMountKey   = regexp.MustCompile(`^mp\d+$`)
)

func validVMID(vmid int) error {
	if vmid < 100 || vmid > 999999999 {
		return invalidf("VMID %d is outside 100-999999999", vmid)
	}
	return nil
}

func validName(kind, v string) error {
	if !reName.MatchString(v) {
		return invalidf("%s %q is not a plain name", kind, v)
	}
	return nil
}

func validUserID(v string) error {
	if !reUserID.MatchString(v) {
		return invalidf("user %q is not user@realm", v)
	}
	return nil
}

func validHostname(v string) error {
	if len(v) > 253 || v == "" {
		return invalidf("hostname %q has an invalid length", v)
	}
	for _, label := range strings.Split(v, ".") {
		if !reHostLabel.MatchString(label) {
			return invalidf("hostname %q is not RFC 1123", v)
		}
	}
	return nil
}

// validPath requires a clean absolute path of plain characters: no "..", no
// separator tricks, nothing an option parser could take for a flag.
func validPath(p string) error {
	if !path.IsAbs(p) || path.Clean(p) != p || strings.Contains(p, "..") || !rePathChars.MatchString(p) {
		return invalidf("path %q must be absolute, clean and plain", p)
	}
	return nil
}

func validText(kind, v string) error {
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

func validACL(a ACL) error {
	if !reACLPath.MatchString(a.Path) || strings.Contains(a.Path, "..") {
		return invalidf("ACL path %q", a.Path)
	}
	if err := validName("role", a.Role); err != nil {
		return err
	}
	if (a.User == "") == (a.Token == "") {
		return invalidf("an ACL names exactly one of user and token")
	}
	if a.User != "" {
		return validUserID(a.User)
	}
	user, id, ok := strings.Cut(a.Token, "!")
	if !ok {
		return invalidf("token %q is not user@realm!id", a.Token)
	}
	if err := validUserID(user); err != nil {
		return err
	}
	return validName("token id", id)
}

func validTemplateVolume(v string) error {
	if !reVolumeID.MatchString(v) {
		return invalidf("template %q is not storage:vztmpl/name", v)
	}
	return nil
}

// execPVE implements PVE over the Proxmox command-line tools.
type execPVE struct{ runner Runner }

func newExecPVE(r Runner) execPVE { return execPVE{runner: r} }

func (p execPVE) run(ctx context.Context, sensitive bool, stdin io.Reader, tool string, args ...string) ([]byte, error) {
	argv := append([]string{"-i", "PATH=" + pveToolPath, "LC_ALL=C", tool}, args...)
	return p.runner.Run(ctx, Command{Name: envTool, Args: argv, Stdin: stdin, Sensitive: sensitive})
}

func (p execPVE) text(ctx context.Context, tool string, args ...string) (string, error) {
	out, err := p.run(ctx, false, nil, tool, args...)
	return string(out), err
}

func (p execPVE) json(ctx context.Context, into any, tool string, args ...string) error {
	out, err := p.run(ctx, false, nil, tool, append(args, "--output-format", "json")...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, into); err != nil {
		return fmt.Errorf("%s: unreadable JSON output: %w", path.Base(tool), err)
	}
	return nil
}

func (p execPVE) do(ctx context.Context, tool string, args ...string) error {
	_, err := p.run(ctx, false, nil, tool, args...)
	return err
}

func (p execPVE) Version(ctx context.Context) (string, error) {
	out, err := p.text(ctx, pveVersionTool)
	if err != nil {
		return "", err
	}
	m := reMgrVersion.FindStringSubmatch(out)
	if m == nil {
		return "", errors.New("pveversion: no pve-manager version in output")
	}
	return m[1], nil
}

// NextID returns the first VMID at or above from that the cluster reports free.
func (p execPVE) NextID(ctx context.Context, from int) (int, error) {
	for id := from; id < from+maxNextIDs; id++ {
		if err := validVMID(id); err != nil {
			return 0, err
		}
		err := p.do(ctx, pveshTool, "get", "/cluster/nextid", "--vmid", strconv.Itoa(id))
		var status *ExitStatus
		switch {
		case err == nil:
			return id, nil
		case !errors.As(err, &status):
			return 0, err
		}
	}
	return 0, fmt.Errorf("no free VMID in %d-%d", from, from+maxNextIDs-1)
}

func (p execPVE) Storages(ctx context.Context) ([]PVEStorage, error) {
	var rows []struct {
		Storage string          `json:"storage"`
		Type    string          `json:"type"`
		Content string          `json:"content"`
		Active  json.RawMessage `json:"active"`
	}
	if err := p.json(ctx, &rows, pvesmTool, "status"); err != nil {
		return nil, err
	}
	out := make([]PVEStorage, 0, len(rows))
	for _, r := range rows {
		active := strings.Trim(string(r.Active), `" `)
		out = append(out, PVEStorage{
			ID: r.Storage, Type: r.Type, Content: strings.Split(r.Content, ","), Active: active == "1" || active == "true",
		})
	}
	return out, nil
}

type networkRow struct {
	Iface   string `json:"iface"`
	Address string `json:"address"`
}

func (p execPVE) bridgeRows(ctx context.Context) ([]networkRow, error) {
	node, err := p.text(ctx, hostnameTool, "-s")
	if err != nil {
		return nil, err
	}
	node = strings.TrimSpace(node)
	if err := validName("node", node); err != nil {
		return nil, err
	}
	var rows []networkRow
	err = p.json(ctx, &rows, pveshTool, "get", "/nodes/"+node+"/network", "--type", "any_bridge")
	return rows, err
}

func (p execPVE) Bridges(ctx context.Context) ([]string, error) {
	rows, err := p.bridgeRows(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		names = append(names, r.Iface)
	}
	return names, nil
}

// BridgeAddress is the host's own address on bridge, the one the container
// reaches the Proxmox API on.
func (p execPVE) BridgeAddress(ctx context.Context, bridge string) (netip.Addr, error) {
	if err := validName("bridge", bridge); err != nil {
		return netip.Addr{}, err
	}
	rows, err := p.bridgeRows(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, r := range rows {
		if r.Iface == bridge {
			return netip.ParseAddr(r.Address)
		}
	}
	return netip.Addr{}, fmt.Errorf("bridge %s has no address", bridge)
}

func (p execPVE) Templates(ctx context.Context, storage string) ([]string, error) {
	if err := validName("storage", storage); err != nil {
		return nil, err
	}
	out, err := p.text(ctx, pveamTool, "list", storage)
	if err != nil {
		return nil, err
	}
	var vols []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.Contains(f[0], ":vztmpl/") {
			vols = append(vols, f[0])
		}
	}
	return vols, nil
}

func (p execPVE) AvailableTemplates(ctx context.Context) ([]string, error) {
	out, err := p.text(ctx, pveamTool, "available", "--section", "system")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "system" {
			names = append(names, f[1])
		}
	}
	return names, nil
}

func (p execPVE) DownloadTemplate(ctx context.Context, storage, name string) error {
	if err := validName("storage", storage); err != nil {
		return err
	}
	if !reTemplate.MatchString(name) {
		return invalidf("template name %q", name)
	}
	return p.do(ctx, pveamTool, "download", storage, name)
}

func (p execPVE) Create(ctx context.Context, s GuestSpec) error {
	args, err := createArgs(s)
	if err != nil {
		return err
	}
	return p.do(ctx, pctTool, args...)
}

// createArgs is the frozen `pct create` argument vector (ADR-0026 "Container
// shape"): always unprivileged, no mounts, no raw lxc keys.
func createArgs(s GuestSpec) ([]string, error) {
	if err := validateSpec(s); err != nil {
		return nil, err
	}
	net0 := "name=eth0,bridge=" + s.Network.Bridge
	if s.Network.DHCP {
		net0 += ",ip=dhcp"
	} else {
		net0 += ",ip=" + s.Network.Address.String() + ",gw=" + s.Network.Gateway.String()
	}
	args := []string{
		"create", strconv.Itoa(s.VMID), s.Template,
		"--hostname", s.Hostname,
		"--cores", strconv.Itoa(s.Cores), "--memory", strconv.Itoa(s.MemoryMiB), "--swap", strconv.Itoa(s.SwapMiB),
		"--rootfs", s.Storage + ":" + strconv.Itoa(s.DiskGiB),
		"--net0", net0,
		"--unprivileged", "1", "--features", "nesting=0,keyctl=0", "--onboot", "1",
		"--tags", strings.Join(s.Tags, ";"), "--description", s.Description,
	}
	if len(s.Network.DNS) > 0 {
		servers := make([]string, len(s.Network.DNS))
		for i, d := range s.Network.DNS {
			servers[i] = d.String()
		}
		args = append(args, "--nameserver", strings.Join(servers, " "))
	}
	return args, nil
}

func validateSpec(s GuestSpec) error {
	for _, err := range []error{
		validVMID(s.VMID), validHostname(s.Hostname), validTemplateVolume(s.Template),
		validName("storage", s.Storage), validName("bridge", s.Network.Bridge), validText("description", s.Description),
	} {
		if err != nil {
			return err
		}
	}
	if s.DiskGiB < 1 || s.Cores < 1 || s.MemoryMiB < 16 || s.SwapMiB < 0 {
		return invalidf("sizing out of range")
	}
	if len(s.Tags) == 0 {
		return invalidf("at least one tag is required")
	}
	for _, t := range s.Tags {
		if err := validName("tag", t); err != nil {
			return err
		}
	}
	if !s.Network.DHCP && (!s.Network.Address.IsValid() || !s.Network.Gateway.IsValid()) {
		return invalidf("static network needs an address and a gateway")
	}
	return nil
}

func (p execPVE) Config(ctx context.Context, vmid int) (GuestConfig, error) {
	if err := validVMID(vmid); err != nil {
		return GuestConfig{}, err
	}
	out, err := p.text(ctx, pctTool, "config", strconv.Itoa(vmid))
	if err != nil {
		return GuestConfig{}, err
	}
	return parseGuestConfig(out), nil
}

func parseGuestConfig(out string) GuestConfig {
	c := GuestConfig{Features: map[string]string{}}
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch {
		case key == "unprivileged":
			c.Unprivileged = val == "1"
		case key == "features":
			for _, kv := range strings.Split(val, ",") {
				if k, v, ok := strings.Cut(kv, "="); ok {
					c.Features[k] = v
				}
			}
		case key == "tags":
			c.Tags = strings.FieldsFunc(val, func(r rune) bool { return r == ';' || r == ',' })
		case key == "description":
			c.Description = strings.TrimSpace(val)
		case key == "lock":
			c.Lock = val
		case strings.HasPrefix(key, "lxc."):
			c.RawLXC = append(c.RawLXC, key)
		case reMountKey.MatchString(key):
			c.Mounts = append(c.Mounts, key)
		}
	}
	return c
}

// State reads `pct list`, which shows every container of this node with its status and lock.
func (p execPVE) State(ctx context.Context, vmid int) (GuestState, error) {
	if err := validVMID(vmid); err != nil {
		return GuestState{}, err
	}
	out, err := p.text(ctx, pctTool, "list")
	if err != nil {
		return GuestState{}, err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != strconv.Itoa(vmid) {
			continue
		}
		st := GuestState{Exists: true, Status: f[1]}
		if len(f) >= 4 {
			st.Lock = f[2]
		}
		return st, nil
	}
	return GuestState{}, nil
}

func (p execPVE) vmidCommand(ctx context.Context, verb string, vmid int) error {
	if err := validVMID(vmid); err != nil {
		return err
	}
	return p.do(ctx, pctTool, verb, strconv.Itoa(vmid))
}

func (p execPVE) Start(ctx context.Context, vmid int) error { return p.vmidCommand(ctx, "start", vmid) }

func (p execPVE) Stop(ctx context.Context, vmid int) error { return p.vmidCommand(ctx, "stop", vmid) }

func (p execPVE) Destroy(ctx context.Context, vmid int) error {
	return p.vmidCommand(ctx, "destroy", vmid)
}

func (p execPVE) Exec(ctx context.Context, vmid int, user string, argv []string, stdin io.Reader, sensitive bool) ([]byte, error) {
	if err := validVMID(vmid); err != nil {
		return nil, err
	}
	if len(argv) == 0 {
		return nil, invalidf("empty command")
	}
	if err := validPath(argv[0]); err != nil {
		return nil, err
	}
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return nil, invalidf("argument contains NUL")
		}
	}
	args := []string{"exec", strconv.Itoa(vmid), "--"}
	if user != "" {
		if err := validName("user", user); err != nil {
			return nil, err
		}
		args = append(args, runuserTool, "-u", user, "--")
	}
	return p.run(ctx, sensitive, stdin, pctTool, append(args, argv...)...)
}

func (p execPVE) Push(ctx context.Context, vmid int, src, dst string, owner Owner, mode fs.FileMode) error {
	if err := validVMID(vmid); err != nil {
		return err
	}
	for _, err := range []error{validPath(src), validPath(dst)} {
		if err != nil {
			return err
		}
	}
	args := []string{"push", strconv.Itoa(vmid), src, dst, "--perms", fmt.Sprintf("%04o", mode.Perm())}
	if owner.User != "" {
		if err := validName("user", owner.User); err != nil {
			return err
		}
		args = append(args, "--user", owner.User)
	}
	if owner.Group != "" {
		if err := validName("group", owner.Group); err != nil {
			return err
		}
		args = append(args, "--group", owner.Group)
	}
	return p.do(ctx, pctTool, args...)
}

func (p execPVE) listed(ctx context.Context, field, want string, tool string, args ...string) (bool, error) {
	var rows []map[string]any
	if err := p.json(ctx, &rows, tool, args...); err != nil {
		return false, err
	}
	for _, r := range rows {
		if v, _ := r[field].(string); v == want {
			return true, nil
		}
	}
	return false, nil
}

func (p execPVE) UserExists(ctx context.Context, user string) (bool, error) {
	if err := validUserID(user); err != nil {
		return false, err
	}
	return p.listed(ctx, "userid", user, pveumTool, "user", "list")
}

func (p execPVE) CreateUser(ctx context.Context, user, comment string) error {
	if err := validUserID(user); err != nil {
		return err
	}
	if err := validText("comment", comment); err != nil {
		return err
	}
	return p.do(ctx, pveumTool, "user", "add", user, "--comment", comment)
}

func (p execPVE) RemoveUser(ctx context.Context, user string) error {
	if err := validUserID(user); err != nil {
		return err
	}
	return p.do(ctx, pveumTool, "user", "delete", user)
}

func (p execPVE) RoleExists(ctx context.Context, role string) (bool, error) {
	if err := validName("role", role); err != nil {
		return false, err
	}
	return p.listed(ctx, "roleid", role, pveumTool, "role", "list")
}

func (p execPVE) CreateRole(ctx context.Context, role string, privileges []string) error {
	if err := validName("role", role); err != nil {
		return err
	}
	if len(privileges) == 0 {
		return invalidf("a role needs privileges")
	}
	for _, priv := range privileges {
		if !rePrivilege.MatchString(priv) {
			return invalidf("privilege %q", priv)
		}
	}
	return p.do(ctx, pveumTool, "role", "add", role, "--privs", strings.Join(privileges, ","))
}

func (p execPVE) RemoveRole(ctx context.Context, role string) error {
	if err := validName("role", role); err != nil {
		return err
	}
	return p.do(ctx, pveumTool, "role", "delete", role)
}

func (p execPVE) ACLs(ctx context.Context) ([]ACL, error) {
	var rows []struct {
		Path   string `json:"path"`
		RoleID string `json:"roleid"`
		Type   string `json:"type"`
		UGID   string `json:"ugid"`
	}
	if err := p.json(ctx, &rows, pveumTool, "acl", "list"); err != nil {
		return nil, err
	}
	var acls []ACL
	for _, r := range rows {
		switch r.Type {
		case "user":
			acls = append(acls, ACL{Path: r.Path, Role: r.RoleID, User: r.UGID})
		case "token":
			acls = append(acls, ACL{Path: r.Path, Role: r.RoleID, Token: r.UGID})
		}
	}
	return acls, nil
}

func aclArgs(verb string, a ACL) ([]string, error) {
	if err := validACL(a); err != nil {
		return nil, err
	}
	args := []string{"acl", verb, a.Path, "--roles", a.Role}
	if a.User != "" {
		return append(args, "--users", a.User), nil
	}
	return append(args, "--tokens", a.Token), nil
}

func (p execPVE) AddACL(ctx context.Context, a ACL) error {
	args, err := aclArgs("modify", a)
	if err != nil {
		return err
	}
	return p.do(ctx, pveumTool, args...)
}

func (p execPVE) RemoveACL(ctx context.Context, a ACL) error {
	args, err := aclArgs("delete", a)
	if err != nil {
		return err
	}
	return p.do(ctx, pveumTool, args...)
}

func validToken(user, id string) error {
	if err := validUserID(user); err != nil {
		return err
	}
	return validName("token id", id)
}

func (p execPVE) TokenExists(ctx context.Context, user, id string) (bool, error) {
	if err := validToken(user, id); err != nil {
		return false, err
	}
	return p.listed(ctx, "tokenid", id, pveumTool, "user", "token", "list", user)
}

// AddToken reads the secret from the captured output only; a failure or an
// unreadable answer is reported without that output.
func (p execPVE) AddToken(ctx context.Context, user, id string) (audit.Secret, error) {
	if err := validToken(user, id); err != nil {
		return "", err
	}
	out, err := p.run(ctx, true, nil, pveumTool, "user", "token", "add", user, id, "--privsep", "1", "--output-format", "json")
	if err != nil {
		return "", errors.New("pveum could not create the API token")
	}
	var reply struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(out, &reply) != nil || reply.Value == "" {
		return "", errors.New("pveum returned no token secret")
	}
	return audit.Secret(reply.Value), nil
}

func (p execPVE) RemoveToken(ctx context.Context, user, id string) error {
	if err := validToken(user, id); err != nil {
		return err
	}
	return p.do(ctx, pveumTool, "user", "token", "remove", user, id)
}
