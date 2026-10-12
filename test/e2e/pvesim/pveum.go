package pvesim

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type pveUser struct {
	comment string
	tokens  map[string]bool // token id -> privilege separation
}

type pveRole struct {
	privs   []string
	special bool
}

type pveACL struct {
	path      string
	role      string
	subject   string // userid or userid!tokenid
	token     bool
	propagate bool
}

// privileges of the PVE 9 admin guide, chapter "User Management", section "Privileges".
var privileges = []string{
	"Datastore.Allocate", "Datastore.AllocateSpace", "Datastore.AllocateTemplate", "Datastore.Audit",
	"Group.Allocate", "Mapping.Audit", "Mapping.Modify", "Mapping.Use", "Permissions.Modify",
	"Pool.Allocate", "Pool.Audit", "Realm.Allocate", "Realm.AllocateUser",
	"SDN.Allocate", "SDN.Audit", "SDN.Use", "Sys.AccessNetwork", "Sys.Audit", "Sys.Console", "Sys.Incoming",
	"Sys.Modify", "Sys.PowerMgmt", "Sys.Syslog", "User.Modify",
	"VM.Allocate", "VM.Audit", "VM.Backup", "VM.Clone", "VM.Config.CDROM", "VM.Config.CPU", "VM.Config.Cloudinit",
	"VM.Config.Disk", "VM.Config.HWType", "VM.Config.Memory", "VM.Config.Network", "VM.Config.Options",
	"VM.Console", "VM.GuestAgent.Audit", "VM.GuestAgent.FileExecute", "VM.GuestAgent.FileRead",
	"VM.GuestAgent.FileSystemMgmt", "VM.GuestAgent.FileWrite", "VM.Migrate", "VM.PowerMgmt",
	"VM.Replicate", "VM.Snapshot", "VM.Snapshot.Rollback",
}

var auditPrivileges = []string{"Datastore.Audit", "Pool.Audit", "Sys.Audit", "VM.Audit"}

func builtinRoles() map[string]*pveRole {
	roles := map[string]*pveRole{"Administrator": {privs: privileges, special: true}, "PVEAuditor": {privs: auditPrivileges, special: true}}
	for _, name := range []string{
		"NoAccess", "PVEAdmin", "PVEDatastoreAdmin", "PVEDatastoreUser", "PVEMappingAdmin", "PVEMappingUser", "PVEPoolAdmin",
		"PVEPoolUser", "PVESDNAdmin", "PVESDNUser", "PVESysAdmin", "PVETemplateUser", "PVEUserAdmin", "PVEVMAdmin", "PVEVMUser",
	} {
		roles[name] = &pveRole{special: true}
	}
	return roles
}

var (
	reUserID  = regexp.MustCompile(`^[^\s:/@!]+@([A-Za-z0-9][A-Za-z0-9._-]*)$`)
	reTokenID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]+$`)
	reRoleID  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	reACLPath = regexp.MustCompile(`^/(?:(?:vms|pool|storage|nodes|access|sdn|mapping)(?:/[A-Za-z0-9._/-]+)?)?$`)
)

func userIDCheck(v string) error {
	m := reUserID.FindStringSubmatch(v)
	switch {
	case m == nil:
		return fmt.Errorf("'%s' is not a valid user ID (user@realm)", v)
	case m[1] != "pve" && m[1] != "pam":
		return fmt.Errorf("authentication realm '%s' does not exist", m[1])
	}
	return nil
}

func privsCheck(v string) error {
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if !contains(privileges, p) {
			return fmt.Errorf("invalid privilege '%s'", p)
		}
	}
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("value is empty")
	}
	return nil
}

func aclPathCheck(v string) error {
	if !reACLPath.MatchString(v) || strings.Contains(v, "..") {
		return fmt.Errorf("invalid ACL path '%s'", v)
	}
	return nil
}

var pveumCommands = map[string]command{
	"user list":   {opts: merge(outputFormat, map[string]check{"enabled": boolean, "full": boolean})},
	"user add":    {positional: []string{"userid"}, opts: merge(optionNames("comment", "email", "firstname", "lastname", "groups", "keys", "password"), map[string]check{"enable": boolean, "expire": integer(0, 1<<40)})},
	"user delete": {positional: []string{"userid"}},
	"user token add": {positional: []string{"userid", "tokenid"}, opts: merge(outputFormat, optionNames("comment"),
		map[string]check{"expire": integer(0, 1<<40), "privsep": boolean})},
	"user token list":   {positional: []string{"userid"}, opts: outputFormat},
	"user token remove": {positional: []string{"userid", "tokenid"}, opts: outputFormat},
	"role list":         {opts: outputFormat},
	"role add":          {positional: []string{"roleid"}, opts: map[string]check{"privs": privsCheck}},
	"role delete":       {positional: []string{"roleid"}},
	"acl list":          {opts: outputFormat},
	"acl modify":        {positional: []string{"path"}, opts: aclOptions(true), required: []string{"roles"}},
	"acl delete":        {positional: []string{"path"}, opts: aclOptions(false), required: []string{"roles"}},
}

func aclOptions(modify bool) map[string]check {
	opts := map[string]check{"roles": anyText, "users": anyText, "tokens": anyText, "groups": anyText, "propagate": boolean}
	if modify {
		opts["delete"] = boolean
	}
	return opts
}

func (s *Sim) pveum(ctx context.Context, args []string) (string, error) {
	cmd, rest, err := subcommand("pveum", pveumCommands, args)
	if err != nil {
		return "", err
	}
	p, err := cmd.parse(rest)
	if err != nil {
		return "", err
	}
	key := args[:len(args)-len(rest)]
	if len(p.pos) > 0 {
		if err := s.checkPositional(strings.Join(key, " "), p.pos); err != nil {
			return "", die("400 Parameter verification failed.\n%v", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pveumRun(ctx, strings.Join(key, " "), p)
}

func (s *Sim) checkPositional(verb string, pos []string) error {
	switch verb {
	case "user add", "user delete", "user token add", "user token list", "user token remove":
		if err := userIDCheck(pos[0]); err != nil {
			return fmt.Errorf("userid: %w", err)
		}
		if len(pos) > 1 && !reTokenID.MatchString(pos[1]) {
			return fmt.Errorf("tokenid: '%s' is not a valid token ID", pos[1])
		}
	case "role add", "role delete":
		if !reRoleID.MatchString(pos[0]) {
			return fmt.Errorf("roleid: '%s' is not a valid role ID", pos[0])
		}
	case "acl modify", "acl delete":
		if err := aclPathCheck(pos[0]); err != nil {
			return fmt.Errorf("path: %w", err)
		}
	}
	return nil
}

func (s *Sim) pveumRun(ctx context.Context, verb string, p parsed) (string, error) {
	switch verb {
	case "user list", "role list", "acl list", "user token list":
		if err := p.requireJSON(); err != nil {
			return "", err
		}
		rows, err := s.listing(verb, p)
		if err != nil {
			return "", err
		}
		return render(rows, p), nil
	case "user add":
		return "", s.addUser(p)
	case "user delete":
		return "", s.deleteUser(ctx, p.pos[0])
	case "user token add":
		return s.addToken(ctx, p)
	case "user token remove":
		return "", s.removeToken(ctx, p.pos[0], p.pos[1])
	case "role add":
		return "", s.addRole(ctx, p)
	case "role delete":
		return "", s.deleteRole(ctx, p.pos[0])
	}
	return "", s.changeACL(ctx, verb == "acl delete" || p.boolOpt("delete", false), p)
}

func (s *Sim) listing(verb string, p parsed) (any, error) {
	switch verb {
	case "user list":
		rows := []map[string]any{{"userid": "root@pam", "enable": 1, "expire": 0}}
		for _, id := range sortedKeys(s.users) {
			rows = append(rows, map[string]any{"userid": id, "enable": 1, "expire": 0, "comment": s.users[id].comment})
		}
		return rows, nil
	case "role list":
		rows := []map[string]any{}
		for _, id := range sortedKeys(s.roles) {
			r := s.roles[id]
			rows = append(rows, map[string]any{"roleid": id, "privs": strings.Join(r.privs, ","), "special": boolInt(r.special)})
		}
		return rows, nil
	case "acl list":
		rows := []map[string]any{{"path": "/", "roleid": "Administrator", "type": "user", "ugid": "root@pam", "propagate": 1}}
		for _, a := range s.acls {
			typ := "user"
			if a.token {
				typ = "token"
			}
			rows = append(rows, map[string]any{"path": a.path, "roleid": a.role, "type": typ, "ugid": a.subject, "propagate": boolInt(a.propagate)})
		}
		return rows, nil
	}
	u, ok := s.users[p.pos[0]]
	if !ok {
		return nil, die("no such user ('%s')", p.pos[0])
	}
	rows := []map[string]any{}
	for _, id := range sortedKeys(u.tokens) {
		rows = append(rows, map[string]any{"tokenid": id, "privsep": boolInt(u.tokens[id]), "expire": 0})
	}
	return rows, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (s *Sim) addUser(p parsed) error {
	id := p.pos[0]
	if _, exists := s.users[id]; exists || id == "root@pam" {
		return die("user '%s' already exists", id)
	}
	s.users[id] = &pveUser{comment: p.opts["comment"], tokens: map[string]bool{}}
	return nil
}

func (s *Sim) deleteUser(ctx context.Context, id string) error {
	u, ok := s.users[id]
	if !ok {
		return die("no such user ('%s')", id)
	}
	for tok := range u.tokens {
		if err := s.dropACLs(ctx, func(a pveACL) bool { return a.subject == id+"!"+tok }); err != nil {
			return err
		}
	}
	if err := s.dropACLs(ctx, func(a pveACL) bool { return a.subject == id }); err != nil {
		return err
	}
	delete(s.users, id)
	return nil
}

func (s *Sim) addToken(ctx context.Context, p parsed) (string, error) {
	if err := p.requireJSON(); err != nil {
		return "", err
	}
	user, id := p.pos[0], p.pos[1]
	u, ok := s.users[user]
	if !ok {
		return "", die("no such user ('%s')", user)
	}
	if _, exists := u.tokens[id]; exists {
		return "", die("Token already exists: %s!%s", user, id)
	}
	privsep := p.boolOpt("privsep", true)
	secret, err := s.api.AddToken(ctx, user, id, privsep)
	if err != nil {
		return "", die("pvesim: create the token in the fake API: %v", err)
	}
	u.tokens[id] = privsep
	s.noteSecret(user, id, secret)
	reply := map[string]any{"full-tokenid": user + "!" + id, "info": map[string]string{"privsep": map[bool]string{true: "1", false: "0"}[privsep]}, "value": secret}
	return render(reply, p), nil
}

func (s *Sim) removeToken(ctx context.Context, user, id string) error {
	u, ok := s.users[user]
	if !ok {
		return die("no such user ('%s')", user)
	}
	if _, exists := u.tokens[id]; !exists {
		return die("no such token ('%s!%s')", user, id)
	}
	delete(u.tokens, id)
	return s.dropACLs(ctx, func(a pveACL) bool { return a.subject == user+"!"+id })
}

func (s *Sim) addRole(ctx context.Context, p parsed) error {
	id := p.pos[0]
	if _, exists := s.roles[id]; exists {
		return die("role '%s' already exists", id)
	}
	privs := strings.FieldsFunc(p.opts["privs"], func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	if err := s.api.SetRole(ctx, id, privs); err != nil {
		return die("pvesim: create the role in the fake API: %v", err)
	}
	s.roles[id] = &pveRole{privs: privs}
	return nil
}

func (s *Sim) deleteRole(ctx context.Context, id string) error {
	r, ok := s.roles[id]
	switch {
	case !ok:
		return die("role '%s' does not exist", id)
	case r.special:
		return die("unable to delete the built-in role '%s'", id)
	}
	if err := s.dropACLs(ctx, func(a pveACL) bool { return a.role == id }); err != nil {
		return err
	}
	delete(s.roles, id)
	return nil
}

// dropACLs removes every entry matching drop, in the fake API as well.
func (s *Sim) dropACLs(ctx context.Context, drop func(pveACL) bool) error {
	kept := s.acls[:0]
	for _, a := range s.acls {
		if !drop(a) {
			kept = append(kept, a)
			continue
		}
		if err := s.api.Revoke(ctx, a.subject, a.path, a.role); err != nil {
			return die("pvesim: revoke in the fake API: %v", err)
		}
	}
	s.acls = kept
	return nil
}

func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
}

func (s *Sim) changeACL(ctx context.Context, remove bool, p parsed) error {
	if p.has("groups") {
		return die("pvesim: groups are not implemented")
	}
	subjects, err := s.aclSubjects(p)
	if err != nil {
		return err
	}
	roles := splitList(p.opts["roles"])
	for _, r := range roles {
		if _, ok := s.roles[r]; !ok {
			return die("role '%s' does not exist", r)
		}
	}
	path, propagate := p.pos[0], p.boolOpt("propagate", true)
	for _, subj := range subjects {
		for _, role := range roles {
			entry := pveACL{path: path, role: role, subject: subj.id, token: subj.token, propagate: propagate}
			if err := s.applyACL(ctx, entry, remove); err != nil {
				return err
			}
		}
	}
	return nil
}

type aclSubject struct {
	id    string
	token bool
}

func (s *Sim) aclSubjects(p parsed) ([]aclSubject, error) {
	var out []aclSubject
	for _, id := range splitList(p.opts["users"]) {
		if _, ok := s.users[id]; !ok && id != "root@pam" {
			return nil, die("no such user ('%s')", id)
		}
		out = append(out, aclSubject{id: id})
	}
	for _, full := range splitList(p.opts["tokens"]) {
		user, tok, _ := strings.Cut(full, "!")
		u, ok := s.users[user]
		if !ok {
			return nil, die("no such token ('%s')", full)
		}
		if _, known := u.tokens[tok]; !known {
			return nil, die("no such token ('%s')", full)
		}
		out = append(out, aclSubject{id: full, token: true})
	}
	if len(out) == 0 {
		return nil, die("400 Parameter verification failed.\nusers: at least one of users, groups or tokens is required")
	}
	return out, nil
}

func (s *Sim) applyACL(ctx context.Context, e pveACL, remove bool) error {
	same := func(a pveACL) bool { return a.path == e.path && a.role == e.role && a.subject == e.subject }
	if remove {
		return s.dropACLs(ctx, same)
	}
	for _, a := range s.acls {
		if same(a) {
			return nil
		}
	}
	if err := s.api.Grant(ctx, e.subject, e.path, e.role, e.propagate); err != nil {
		return die("pvesim: grant in the fake API: %v", err)
	}
	s.acls = append(s.acls, e)
	return nil
}

// Dump is the users, roles and ACLs for test failure messages.
func (s *Sim) Dump() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.MarshalIndent(map[string]any{"users": sortedKeys(s.users), "acls": len(s.acls), "guests": len(s.guests)}, "", " ")
	return string(raw)
}
