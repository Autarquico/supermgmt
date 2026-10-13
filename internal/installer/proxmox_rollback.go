package installer

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// undoer rolls a journal back. It is used by the failing run itself and by a
// later run that finds a stale journal; both only need the seams below.
type undoer struct {
	pve   PVE
	files Files
	j     *journal
	h     provisionHooks
	say   func(format string, args ...any)
}

type rollbackReport struct {
	kept    []string // resources left for manual recovery, with the reason
	pending bool     // a PVE task may still be running: recovery is pending
}

func (r rollbackReport) clean() bool { return len(r.kept) == 0 && !r.pending }

type undoResult struct {
	resolved bool
	note     string
	pending  bool
}

func resolved() undoResult { return undoResult{resolved: true} }

func kept(format string, args ...any) undoResult {
	return undoResult{note: fmt.Sprintf(format, args...)}
}

// run undoes every unresolved entry, newest first, journaling its own
// progress. Journal removal happens only when nothing was kept.
func (u undoer) run(ctx context.Context) (rollbackReport, error) {
	var rep rollbackReport
	for _, e := range u.j.toUndo() {
		res, err := u.undo(ctx, e)
		if err != nil && isCrash(err) {
			return rep, err
		}
		if err != nil {
			res = kept("%v", err)
		}
		if !res.resolved {
			rep.kept = append(rep.kept, fmt.Sprintf("%s %s: %s", e.Resource, e.Name, res.note))
			rep.pending = rep.pending || res.pending
			continue
		}
		if res.note != "" {
			u.say("%s", res.note)
		}
		if err := u.hit("rollback:" + e.Resource + ":undone"); err != nil {
			return rep, err
		}
		if err := u.j.mark(e.Seq, phaseUndone); err != nil {
			rep.kept = append(rep.kept, fmt.Sprintf("%s %s: journal write failed: %v", e.Resource, e.Name, err))
		}
	}
	if !rep.clean() {
		return rep, nil
	}
	if err := u.hit("rollback:journal"); err != nil {
		return rep, err
	}
	if err := u.j.remove(); err != nil {
		rep.kept = append(rep.kept, "journal "+u.j.dir+": "+err.Error())
	}
	return rep, nil
}

func (u undoer) undo(ctx context.Context, e journalEntry) (undoResult, error) {
	if e.Phase == phaseAmbiguous {
		return kept("it already existed when this install tried to create it, so it may be somebody else's; left untouched"), nil
	}
	switch e.Resource {
	case resLXC:
		return u.undoGuest(ctx, e)
	case resUser:
		return u.undoNamed(e, e.Name == userIDFor(u.j.id), func() (bool, error) { return u.pve.UserExists(ctx, e.Name) },
			func() error { return u.pve.RemoveUser(ctx, e.Name) })
	case resRole:
		return u.undoNamed(e, slices.Contains(u.roleNames(), e.Name), func() (bool, error) { return u.pve.RoleExists(ctx, e.Name) },
			func() error { return u.pve.RemoveRole(ctx, e.Name) })
	case resToken:
		return u.undoToken(ctx, e)
	case resACL:
		return u.undoACL(ctx, e)
	case resHostTemp:
		return u.undoHostTemp(e)
	case resBootstrapDir:
		return u.undoBootstrapDir(ctx, e)
	case resTemplate:
		return undoResult{resolved: true, note: "kept template " + e.Name + " (shared cache, not deleted)"}, nil
	}
	return kept("unknown resource kind"), nil
}

// The ownership proof for PVE identities is the exact name this install derives from its id:
// a journal entry naming anything else is never acted on.
func (u undoer) roleNames() []string { return []string{auditRoleFor(u.j.id), powerRoleFor(u.j.id)} }

func (u undoer) tokenName() string { return userIDFor(u.j.id) + "!" + pveTokenID }

func (u undoer) provenACL(acl ACL) bool {
	return slices.Contains(u.roleNames(), acl.Role) && (acl.User == userIDFor(u.j.id)) != (acl.Token == u.tokenName())
}

func (u undoer) undoNamed(e journalEntry, proven bool, exists func() (bool, error), remove func() error) (undoResult, error) {
	if !proven {
		return kept("name is not one this install (%s) creates", u.j.id), nil
	}
	present, err := exists()
	if err != nil {
		return undoResult{}, err
	}
	if present {
		if err := remove(); err != nil {
			return undoResult{}, err
		}
	}
	return resolved(), nil
}

func (u undoer) undoToken(ctx context.Context, e journalEntry) (undoResult, error) {
	user, id, ok := strings.Cut(e.Name, "!")
	if !ok {
		return kept("malformed token name"), nil
	}
	return u.undoNamed(e, e.Name == u.tokenName(), func() (bool, error) { return u.pve.TokenExists(ctx, user, id) },
		func() error { return u.pve.RemoveToken(ctx, user, id) })
}

func (u undoer) undoACL(ctx context.Context, e journalEntry) (undoResult, error) {
	acl, ok := parseACLName(e.Name)
	if !ok {
		return kept("malformed ACL name"), nil
	}
	return u.undoNamed(e, u.provenACL(acl), func() (bool, error) {
		acls, err := u.pve.ACLs(ctx)
		return slices.Contains(acls, acl), err
	}, func() error { return u.pve.RemoveACL(ctx, acl) })
}

func (u undoer) undoHostTemp(e journalEntry) (undoResult, error) {
	if e.Name != path.Join(u.j.dir, stageDirName) {
		return kept("path is not the staging directory of this install"), nil
	}
	if err := u.files.RemoveAll(e.Name); err != nil {
		return undoResult{}, err
	}
	if u.files.Exists(e.Name) {
		return kept("still present after removal"), nil
	}
	return resolved(), nil
}

// undoGuest destroys the container only when its description carries this
// install's id. A guest still locked by a running PVE task is waited for; if
// the task does not finish in time, recovery stays pending.
func (u undoer) undoGuest(ctx context.Context, e journalEntry) (undoResult, error) {
	vmid, err := strconv.Atoi(e.Name)
	if err != nil {
		return kept("malformed VMID"), nil
	}
	st, err := u.pve.State(ctx, vmid)
	if err != nil {
		return undoResult{}, err
	}
	if st.Exists && st.Lock != "" {
		if st, err = u.waitUnlocked(ctx, vmid); err != nil {
			return undoResult{}, err
		}
		if st.Exists && st.Lock != "" {
			return undoResult{note: "guest " + e.Name + " is still locked by a running task (" + st.Lock + "); pending recovery", pending: true}, nil
		}
	}
	if !st.Exists {
		return resolved(), nil
	}
	cfg, err := u.pve.Config(ctx, vmid)
	if err != nil {
		return undoResult{}, err
	}
	if !strings.Contains(cfg.Description, ownershipMark(u.j.id)) {
		return kept("VMID %d exists but is not marked with install %s; left untouched", vmid, u.j.id), nil
	}
	if st.Status != "stopped" {
		if err := u.pve.Stop(ctx, vmid); err != nil {
			return undoResult{}, err
		}
	}
	if err := u.pve.Destroy(ctx, vmid); err != nil {
		return undoResult{}, err
	}
	if after, err := u.pve.State(ctx, vmid); err != nil || after.Exists {
		return kept("container %d still exists after destroy", vmid), nil
	}
	return resolved(), nil
}

func (u undoer) waitUnlocked(ctx context.Context, vmid int) (GuestState, error) {
	attempts := int(u.h.lockWait / u.h.poll)
	for i := 0; ; i++ {
		st, err := u.pve.State(ctx, vmid)
		if err != nil || !st.Exists || st.Lock == "" || i >= attempts {
			return st, err
		}
		if err := u.h.pause(ctx, u.h.poll); err != nil {
			return st, err
		}
	}
}

// undoBootstrapDir removes the secret staging directory inside a running
// container; a stopped or missing container holds nothing (/run is tmpfs).
func (u undoer) undoBootstrapDir(ctx context.Context, e journalEntry) (undoResult, error) {
	vmid, err := strconv.Atoi(e.Name)
	if err != nil {
		return kept("malformed VMID"), nil
	}
	st, err := u.pve.State(ctx, vmid)
	if err != nil {
		return undoResult{}, err
	}
	if !st.Exists || st.Status != "running" {
		return resolved(), nil
	}
	cfg, err := u.pve.Config(ctx, vmid)
	if err != nil {
		return undoResult{}, err
	}
	if !strings.Contains(cfg.Description, ownershipMark(u.j.id)) {
		return kept("VMID %d is not marked with install %s", vmid, u.j.id), nil
	}
	if _, err := u.pve.Exec(ctx, vmid, "", []string{"/usr/bin/rm", "-rf", bootstrapDir}, nil, false); err != nil {
		return undoResult{}, err
	}
	return resolved(), nil
}

// ---- failing run ----

func (p *provision) undoer(j *journal) undoer {
	return undoer{pve: p.pve, files: p.d.Files, j: j, h: p.h, say: p.say}
}

// abort rolls back what this run created and reports the original failure
// together with the outcome. It runs even when the operator interrupted.
func (p *provision) abort(ctx context.Context, cause error) error {
	if p.committed {
		return failWrap(ExitConfiguration, "installed (the access information is printed above), but cleanup of the install journal did not finish; run the installer again to finish it", cause)
	}
	p.say("install failed: %v\nrolling back what this install created...", cause)
	rep, err := p.undoer(p.j).run(context.WithoutCancel(ctx))
	if err != nil {
		return err
	}
	if rep.clean() {
		return &Error{Code: ExitCode(cause), Err: fmt.Errorf("%w; everything this install created was rolled back", cause)}
	}
	code := ExitConfiguration
	if rep.pending {
		code = ExitCreation
	}
	return &Error{Code: code, Err: fmt.Errorf("%w; NOT fully rolled back, kept for manual recovery (journal %s):\n- %s",
		cause, p.j.dir, strings.Join(rep.kept, "\n- "))}
}

// ---- commit ----

type applianceRecord struct {
	InstallID     string   `json:"install_id"`
	VMID          int      `json:"vmid"`
	Hostname      string   `json:"hostname"`
	User          string   `json:"user"`
	Token         string   `json:"token"`
	Roles         []string `json:"roles"`
	Template      string   `json:"template"`
	PVEVersion    string   `json:"pve_version"`
	Endpoint      string   `json:"endpoint"`
	CAFingerprint string   `json:"ca_fingerprint"`
}

func recordPath(vmid int) string { return path.Join(appliancesDir, strconv.Itoa(vmid)+".json") }

// commitInstall is ADR-0026's commit protocol: record, `committed`, journal removal.
func (p *provision) commitInstall() error {
	roles := make([]string, 0, 2)
	for _, g := range p.grants() {
		roles = append(roles, g.role)
	}
	data, err := json.MarshalIndent(applianceRecord{
		InstallID: p.id, VMID: p.plan.VMID, Hostname: p.plan.Hostname, User: userIDFor(p.id),
		Token: userIDFor(p.id) + "!" + pveTokenID, Roles: roles, Template: p.plan.Template,
		PVEVersion: p.plan.PVEVersion, Endpoint: p.plan.Endpoint, CAFingerprint: caFingerprint(p.appliancePEM),
	}, "", "  ")
	if err != nil {
		return failWrap(ExitConfiguration, "render the appliance record", err)
	}
	f := p.d.Files
	for _, step := range []func() error{
		func() error { return f.MkdirAll(appliancesDir, 0o700, Owner{}) },
		func() error { return f.SyncDir(path.Dir(appliancesDir)) },
		func() error { return f.WriteFile(recordPath(p.plan.VMID), append(data, '\n'), 0o600, Owner{}) },
		func() error { return f.SyncDir(appliancesDir) },
	} {
		if err := step(); err != nil {
			return p.recordFailure(err)
		}
	}
	p.committed = true
	if err := p.hit("S16:record"); err != nil {
		return err
	}
	p.printAccess() // shown once, and only the durable record makes it safe to lose the run
	if err := p.j.commit(); err != nil {
		return failWrap(ExitConfiguration, "commit the install journal", err)
	}
	if err := p.hit("S16:committed"); err != nil {
		return err
	}
	if err := p.j.remove(); err != nil {
		return failWrap(ExitConfiguration, "remove the install journal", err)
	}
	return p.hit("S16:cleaned")
}

// recordFailure undoes a half-written record so the rollback that follows does
// not leave a record for a container it destroys. If the record cannot be
// proven gone, ownership is ambiguous and the install is kept, not rolled back.
func (p *provision) recordFailure(cause error) error {
	file := recordPath(p.plan.VMID)
	if err := p.d.Files.RemoveAll(file); err != nil || p.d.Files.Exists(file) {
		p.committed = true
	}
	return failWrap(ExitConfiguration, "write the appliance record", cause)
}

func (p *provision) printAccess() {
	p.say("SuperMgmt is running in LXC %d (%s) at %s\n\n"+
		"CA certificate fingerprint (sha256): %s\n%s\n"+
		"Bootstrap code (shown once, single use): %s\n\n"+
		"On your workstation, save the CA certificate above to a file (for example supermgmt-ca.pem) and run:\n"+
		"  sm profile add supermgmt --url %s --ca-file supermgmt-ca.pem --use\n  sm login --bootstrap\n\n"+
		"Back up the instance: run `sm backup create` on the appliance and keep the key export somewhere safe.",
		p.plan.VMID, p.plan.Hostname, p.publicURL, caFingerprint(p.appliancePEM), strings.TrimSpace(string(p.appliancePEM)),
		p.bootstrapCode, p.publicURL)
	if p.plan.Download != "" {
		p.say("The template %s was downloaded for this install and is kept (shared cache).", p.plan.Template)
	}
}

// caCertificatesPEM keeps the CA certificates of a chain.
func caCertificatesPEM(chain []byte) ([]byte, error) {
	certs, err := parseCertificates(chain)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, c := range certs {
		if c.IsCA {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
	}
	if out == nil {
		return nil, errors.New("the served certificate chain holds no CA certificate")
	}
	return out, nil
}

// ---- stale journals ----

// recoverStale handles journals left by earlier runs, before any new side
// effect: committed ones are only cleaned up; uncommitted ones are rolled
// back after confirmation. It scans journalRoot and the legacy journalTmpRoot,
// which is shared, so a journal is acted on only when its name, owner, mode
// and content are exactly what this installer writes.
func (p *provision) recoverStale(ctx context.Context) error {
	if err := p.requirePrivate(journalRoot, true); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, root := range []struct {
		dir   string
		valid *regexp.Regexp
		owns  func(name string) bool
	}{
		{journalRoot, reJournalDir, func(string) bool { return true }},
		{journalTmpRoot, reLegacyJournalDir, func(name string) bool { return strings.HasPrefix(name, journalDirPrefix) }},
	} {
		if err := p.recoverRoot(ctx, root.dir, root.valid, root.owns); err != nil {
			return err
		}
	}
	return nil
}

func (p *provision) recoverRoot(ctx context.Context, root string, valid *regexp.Regexp, owns func(string) bool) error {
	names, err := p.d.Files.ListDir(root)
	if err != nil {
		return failWrap(ExitConfiguration, "look for earlier installs", err)
	}
	for _, name := range names {
		if !owns(name) {
			continue
		}
		if !valid.MatchString(name) {
			p.say("ignoring %s: not a journal directory of this installer", path.Join(root, name))
			continue
		}
		if err := p.recoverJournal(ctx, path.Join(root, name)); err != nil {
			return err
		}
	}
	return nil
}

// requirePrivate refuses anything that is not what the installer creates in a
// shared directory: a real directory or regular file, owned by root, closed to others.
func (p *provision) requirePrivate(entry string, wantDir bool) error {
	info, err := p.d.Files.Lstat(entry)
	if err != nil {
		return err
	}
	if info.Dir != wantDir || info.Regular == wantDir || info.UID != 0 || info.Mode&0o077 != 0 {
		return fail(ExitConfiguration, "%s is not a private root-owned %s (owner %d, mode %04o); it may not have been written by this installer: "+
			"inspect and remove it by hand", entry, map[bool]string{true: "directory", false: "file"}[wantDir], info.UID, info.Mode)
	}
	return nil
}

func (p *provision) recoverJournal(ctx context.Context, dir string) error {
	f := p.d.Files
	if err := p.requirePrivate(dir, true); err != nil {
		return err
	}
	file := path.Join(dir, journalFile)
	if err := p.requirePrivate(file, false); errors.Is(err, fs.ErrNotExist) {
		if err := f.RemoveAll(dir); err != nil { // crashed before the first entry: nothing was created
			return failWrap(ExitConfiguration, "remove the empty journal "+dir, err)
		}
		return nil
	} else if err != nil {
		return err
	}
	j, err := openJournal(f, dir)
	if err != nil {
		return failWrap(ExitConfiguration, "an earlier install left an unreadable journal; recover it by hand", err)
	}
	if len(j.entries) == 0 {
		return j.remove() // not even the first entry became durable
	}
	switch p.commitStateOf(j) {
	case committed:
		p.say("finishing cleanup of the completed install %s", j.id)
		if err := j.remove(); err != nil {
			return failWrap(ExitConfiguration, "remove the journal "+dir, err)
		}
		return nil
	case commitUnknown:
		return fail(ExitConfiguration, "an earlier install (%s) left a journal, but its appliance record cannot be read, so whether it completed is unknown; "+
			"nothing was removed or stopped. Inspect %s and %s", j.id, dir, appliancesDir)
	case uncommitted:
	}
	return p.rollbackStale(ctx, j)
}

type commitState int

const (
	uncommitted commitState = iota
	committed
	commitUnknown // the evidence is unreadable: never treated as "not committed"
)

// commitStateOf is three-valued on purpose: a damaged appliance record must
// not make a working appliance look like an unfinished install.
func (p *provision) commitStateOf(j *journal) commitState {
	if j.isCommitted() {
		return committed
	}
	lxc, ok := j.first(resLXC)
	if !ok {
		return uncommitted
	}
	vmid, err := strconv.Atoi(lxc.Name)
	if err != nil || validVMID(vmid) != nil {
		return commitUnknown
	}
	raw, err := p.d.Files.ReadFile(recordPath(vmid))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return uncommitted
	case err != nil:
		return commitUnknown
	}
	var rec applianceRecord
	if json.Unmarshal(raw, &rec) != nil || rec.VMID != vmid || !reInstallID.MatchString(rec.InstallID) {
		return commitUnknown
	}
	if rec.InstallID == j.id {
		return committed
	}
	return uncommitted // the record belongs to another install: the guest proof decides
}

func (p *provision) rollbackStale(ctx context.Context, j *journal) error {
	if !p.in.interactive() {
		return fail(ExitConfiguration, "an earlier install (%s) did not finish; run the installer again from a terminal to roll it back, "+
			"or remove the resources named in %s by hand", j.id, j.dir)
	}
	p.say("An earlier appliance install (%s) did not finish. It created:", j.id)
	for _, e := range j.toUndo() {
		p.say("  %s %s", e.Resource, e.Name)
	}
	if err := p.in.confirm("Roll back what it created (resources not carrying that install id are never touched)?"); err != nil {
		return err
	}
	rep, err := p.undoer(j).run(ctx)
	if err != nil {
		return err
	}
	if !rep.clean() {
		return fail(ExitConfiguration, "the earlier install could not be fully rolled back; kept for manual recovery (journal %s):\n- %s",
			j.dir, strings.Join(rep.kept, "\n- "))
	}
	return nil
}
