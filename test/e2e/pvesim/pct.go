package pvesim

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// guest is one LXC: its configuration and the container that runs it.
type guest struct {
	vmid      int
	container string
	conf      map[string]string
	running   bool
	lock      string
}

var (
	reHostname  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	reVolume    = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]*):vztmpl/([A-Za-z0-9][A-Za-z0-9_.+-]*)$`)
	reRootfs    = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]*):(\d+(?:\.\d+)?)((?:,(?:acl|quota|ro|shared|replicate|backup|mountoptions)=[^,]*)*)$`)
	reTags      = regexp.MustCompile(`^[A-Za-z0-9_+.-]+(?:[;, ][A-Za-z0-9_+.-]+)*$`)
	rePerms     = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	reIndexed   = func(prefix string) *regexp.Regexp { return regexp.MustCompile(`^` + prefix + `\d+$`) }
	netKeys     = []string{"name", "bridge", "ip", "gw", "ip6", "gw6", "hwaddr", "mtu", "rate", "tag", "type", "firewall", "trunks", "link_down"}
	featureBool = []string{"nesting", "keyctl", "fuse", "mknod", "force_rw_sys"}
)

func vmidCheck(v string) error { return integer(100, 999999999)(v) }

var pctCommands = map[string]command{
	"create": {positional: []string{"vmid", "ostemplate"}, opts: createOptions(), patterns: createPatterns()},
	"start":  {positional: []string{"vmid"}, opts: map[string]check{"skiplock": boolean, "debug": boolean}},
	"stop":   {positional: []string{"vmid"}, opts: map[string]check{"skiplock": boolean, "overrule-shutdown": boolean}},
	"destroy": {positional: []string{"vmid"}, opts: map[string]check{
		"destroy-unreferenced-disks": boolean, "force": boolean, "purge": boolean,
	}},
	"status": {positional: []string{"vmid"}, opts: map[string]check{"verbose": boolean}},
	"list":   {},
	"config": {positional: []string{"vmid"}, opts: map[string]check{"current": boolean, "snapshot": anyText}},
	"push": {positional: []string{"vmid", "file", "destination"}, opts: map[string]check{
		"group": anyText, "user": anyText, "perms": matching("octal mode", rePerms),
	}},
}

func createOptions() map[string]check {
	return merge(optionNames("description", "password", "pool", "searchdomain", "ssh-public-keys", "storage", "timezone", "hookscript", "startup", "bwlimit", "cpulimit"),
		map[string]check{
			"hostname":     matching("DNS name", reHostname),
			"cores":        integer(1, 8192),
			"cpuunits":     integer(0, 500000),
			"memory":       integer(16, 1<<30),
			"swap":         integer(0, 1<<30),
			"rootfs":       matching("volume (storage:size-in-GiB)", reRootfs),
			"features":     featuresCheck,
			"tags":         matching("tag list", reTags),
			"nameserver":   nameserverCheck,
			"arch":         oneOf("amd64", "i386", "arm64", "armhf", "riscv32", "riscv64"),
			"ostype":       oneOf("debian", "devuan", "ubuntu", "centos", "fedora", "opensuse", "archlinux", "alpine", "gentoo", "nixos", "unmanaged"),
			"cmode":        oneOf("shell", "console", "tty"),
			"tty":          integer(0, 6),
			"lock":         oneOf("backup", "create", "destroyed", "disk", "fstrim", "migrate", "mounted", "rollback", "snapshot", "snapshot-delete"),
			"unprivileged": boolean, "onboot": boolean, "start": boolean, "protection": boolean, "console": boolean,
			"force": boolean, "unique": boolean, "restore": boolean, "template": boolean, "debug": boolean, "ignore-unpack-errors": boolean,
		})
}

func createPatterns() []pattern {
	return []pattern{
		{reIndexed("net"), netCheck}, {reIndexed("mp"), anyText}, {reIndexed("dev"), anyText}, {reIndexed("unused"), anyText},
	}
}

func featuresCheck(v string) error {
	for _, kv := range strings.Split(v, ",") {
		k, val, _ := strings.Cut(kv, "=")
		switch {
		case contains(featureBool, k):
			if val != "0" && val != "1" {
				return fmt.Errorf("feature '%s' takes 0 or 1", k)
			}
		case k == "mount":
		default:
			return fmt.Errorf("unknown feature '%s'", k)
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

func nameserverCheck(v string) error {
	for _, f := range strings.Fields(v) {
		if _, err := netip.ParseAddr(f); err != nil {
			return fmt.Errorf("'%s' is not an IP address", f)
		}
	}
	return nil
}

// netConfig is a parsed net<N> value.
type netConfig map[string]string

func parseNet(v string) (netConfig, error) {
	n := netConfig{}
	for _, kv := range strings.Split(v, ",") {
		k, val, ok := strings.Cut(kv, "=")
		if !ok || !contains(netKeys, k) {
			return nil, fmt.Errorf("unknown or malformed network property '%s'", kv)
		}
		n[k] = val
	}
	if n["name"] == "" {
		return nil, fmt.Errorf("network property 'name' is missing")
	}
	switch ip := n["ip"]; ip {
	case "", "dhcp", "manual":
	default:
		if _, err := netip.ParsePrefix(ip); err != nil {
			return nil, fmt.Errorf("ip '%s' is neither dhcp, manual nor an address in CIDR notation", ip)
		}
	}
	if gw := n["gw"]; gw != "" {
		if _, err := netip.ParseAddr(gw); err != nil {
			return nil, fmt.Errorf("gw '%s' is not an IP address", gw)
		}
	}
	return n, nil
}

func netCheck(v string) error { _, err := parseNet(v); return err }

func (s *Sim) pct(ctx context.Context, args []string, stdin []byte) Response {
	if len(args) > 0 && args[0] == "exec" {
		return s.pctExec(ctx, args[1:], stdin)
	}
	cmd, rest, err := subcommand("pct", pctCommands, args)
	if err != nil {
		return failure(err)
	}
	p, err := cmd.parse(rest)
	if err != nil {
		return failure(err)
	}
	out, err := s.pctRun(ctx, args[0], p)
	if err != nil {
		return failure(err)
	}
	return Response{Stdout: []byte(out)}
}

func (s *Sim) pctRun(ctx context.Context, verb string, p parsed) (string, error) {
	if verb == "list" {
		return s.pctList(), nil
	}
	if err := vmidCheck(p.pos[0]); err != nil {
		return "", die("400 Parameter verification failed.\nvmid: %v", err)
	}
	vmid, _ := strconv.Atoi(p.pos[0])
	s.mu.Lock()
	defer s.mu.Unlock()
	if verb == "create" {
		return "", s.pctCreate(ctx, vmid, p)
	}
	g, ok := s.guests[vmid]
	if !ok {
		return "", die("Configuration file 'nodes/%s/lxc/%d.conf' does not exist", s.cfg.Node, vmid)
	}
	switch verb {
	case "start":
		return "", s.pctStart(ctx, g)
	case "stop":
		return "", s.pctStop(ctx, g)
	case "destroy":
		return "", s.pctDestroy(ctx, g, p)
	case "status":
		return "status: " + g.status() + "\n", nil
	case "config":
		return g.render(), nil
	case "push":
		return "", s.pctPush(ctx, g, p)
	}
	return "", die("pvesim: pct %s is not implemented", verb)
}

func (g *guest) status() string {
	if g.running {
		return "running"
	}
	return "stopped"
}

func (g *guest) render() string {
	keys := make([]string, 0, len(g.conf)+1)
	for k := range g.conf {
		keys = append(keys, k)
	}
	if g.lock != "" {
		keys = append(keys, "lock")
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := g.conf[k]
		if k == "lock" {
			v = g.lock
		}
		fmt.Fprintf(&b, "%s: %s\n", k, v)
	}
	return b.String()
}

func (s *Sim) pctList() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]int, 0, len(s.guests))
	for id := range s.guests {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var b strings.Builder
	fmt.Fprintf(&b, "%-10s %-10s %-10s %s\n", "VMID", "Status", "Lock", "Name")
	for _, id := range ids {
		g := s.guests[id]
		fmt.Fprintf(&b, "%-10d %-10s %-10s %s\n", id, g.status(), g.lock, g.conf["hostname"])
	}
	return b.String()
}

func (s *Sim) pctCreate(ctx context.Context, vmid int, p parsed) error {
	volume := p.pos[1]
	m := reVolume.FindStringSubmatch(volume)
	if m == nil {
		return die("unable to parse volume ID '%s'", volume)
	}
	if _, exists := s.guests[vmid]; exists {
		return die("unable to create CT %d - container already exists", vmid)
	}
	if !s.templates[volume] {
		return die("unable to create CT %d - volume '%s' does not exist", vmid, volume)
	}
	conf, spec, err := s.createConfig(vmid, m[2], p)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("sm-e2e-ct%d-%s", vmid, randomSuffix())
	if err := s.eng.Create(ctx, name, spec); err != nil {
		return die("unable to create CT %d - %v", vmid, err)
	}
	s.guests[vmid] = &guest{vmid: vmid, container: name, conf: conf}
	if err := s.api.PutGuest(ctx, FakeGuest{VMID: vmid, Name: conf["hostname"], Status: "stopped"}); err != nil {
		return die("pvesim: mirror the guest into the fake API: %v", err)
	}
	return nil
}

// createConfig validates what needs the host (storages, the bridge) and builds the stored
// configuration with PVE's defaults.
func (s *Sim) createConfig(vmid int, template string, p parsed) (map[string]string, ContainerSpec, error) {
	conf := map[string]string{"arch": "amd64", "memory": "512", "swap": "512", "ostype": ostypeOf(template)}
	for k, v := range p.opts {
		switch k {
		case "storage", "password", "ssh-public-keys", "start", "force", "restore", "unique", "debug", "ignore-unpack-errors", "pool", "bwlimit":
		default:
			conf[k] = v
		}
	}
	if conf["hostname"] == "" {
		conf["hostname"] = fmt.Sprintf("CT%d", vmid)
	}
	storage, size := s.rootfsOf(p)
	st, ok := s.cfg.storage(storage)
	switch {
	case !ok:
		return nil, ContainerSpec{}, die("storage '%s' does not exist", storage)
	case !st.Active:
		return nil, ContainerSpec{}, die("storage '%s' is not online", storage)
	case !contains(strings.Split(st.Content, ","), "rootdir"):
		return nil, ContainerSpec{}, die("unable to create CT %d - storage '%s' does not support container directories", vmid, storage)
	}
	conf["rootfs"] = fmt.Sprintf("%s:vm-%d-disk-0,size=%sG", storage, vmid, size)
	spec := ContainerSpec{Hostname: conf["hostname"]}
	for k, v := range p.opts {
		if !reIndexed("net").MatchString(k) {
			continue
		}
		n, _ := parseNet(v)
		if n["bridge"] != "" && n["bridge"] != s.cfg.Bridge {
			return nil, spec, die("unable to create CT %d - bridge '%s' does not exist", vmid, n["bridge"])
		}
		conf[k] = v + ",hwaddr=BC:24:11:00:00:01,type=veth"
		if prefix, err := netip.ParsePrefix(n["ip"]); err == nil && k == "net0" {
			spec.IP = prefix.Addr().String()
		}
	}
	return conf, spec, nil
}

func (s *Sim) rootfsOf(p parsed) (storage, size string) {
	if v, ok := p.opts["rootfs"]; ok {
		m := reRootfs.FindStringSubmatch(v)
		return m[1], m[2]
	}
	storage = p.opts["storage"]
	if storage == "" {
		storage = "local"
	}
	return storage, "4"
}

func ostypeOf(template string) string {
	for _, t := range []string{"debian", "ubuntu", "alpine", "fedora", "centos", "archlinux", "devuan", "opensuse", "gentoo", "nixos"} {
		if strings.HasPrefix(template, t) {
			return t
		}
	}
	return "unmanaged"
}

func (s *Sim) pctStart(ctx context.Context, g *guest) error {
	switch {
	case g.running:
		return die("CT %d already running", g.vmid)
	case g.lock != "":
		return die("CT is locked (%s)", g.lock)
	}
	if err := s.eng.Start(ctx, g.container); err != nil {
		return die("command 'systemctl start pve-container@%d' failed: %v", g.vmid, err)
	}
	g.running = true
	return s.mirror(ctx, g)
}

func (s *Sim) pctStop(ctx context.Context, g *guest) error {
	switch {
	case !g.running:
		return die("CT %d not running", g.vmid)
	case g.lock != "":
		return die("CT is locked (%s)", g.lock)
	}
	if err := s.eng.Stop(ctx, g.container); err != nil {
		return die("command 'lxc-stop -n %d --kill' failed: %v", g.vmid, err)
	}
	g.running = false
	return s.mirror(ctx, g)
}

func (s *Sim) pctDestroy(ctx context.Context, g *guest, p parsed) error {
	if g.running && !p.boolOpt("force", false) {
		return die("CT is running - destroy failed")
	}
	if err := s.eng.Remove(ctx, g.container); err != nil {
		return die("unable to destroy CT %d - %v", g.vmid, err)
	}
	delete(s.guests, g.vmid)
	if err := s.api.RemoveGuest(ctx, g.vmid); err != nil {
		return die("pvesim: mirror the removal into the fake API: %v", err)
	}
	return nil
}

func (s *Sim) mirror(ctx context.Context, g *guest) error {
	if err := s.api.PutGuest(ctx, FakeGuest{VMID: g.vmid, Name: g.conf["hostname"], Status: g.status()}); err != nil {
		return die("pvesim: mirror the guest into the fake API: %v", err)
	}
	return nil
}

// runningGuest looks a guest up for exec and push, which run without holding the state lock.
func (s *Sim) runningGuest(vmid string) (*guest, error) {
	if err := vmidCheck(vmid); err != nil {
		return nil, die("400 Parameter verification failed.\nvmid: %v", err)
	}
	id, _ := strconv.Atoi(vmid)
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.guests[id]
	switch {
	case !ok:
		return nil, die("Configuration file 'nodes/%s/lxc/%d.conf' does not exist", s.cfg.Node, id)
	case !g.running:
		return nil, die("CT %d not running", id)
	}
	return g, nil
}

// pctExec is `pct exec VMID [--] COMMAND...`: the exit status and the streams are the command's.
func (s *Sim) pctExec(ctx context.Context, args []string, stdin []byte) Response {
	if len(args) < 1 {
		return failure(die("400 not enough arguments (missing vmid)"))
	}
	g, err := s.runningGuest(args[0])
	if err != nil {
		return failure(err)
	}
	argv := args[1:]
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return failure(die("400 not enough arguments (missing command)"))
	}
	res, err := s.eng.Exec(ctx, g.container, argv, stdin)
	if err != nil {
		return failure(die("command 'lxc-attach -n %d' failed: %v", g.vmid, err))
	}
	return Response(res)
}

func (s *Sim) pctPush(ctx context.Context, g *guest, p parsed) error {
	src, dst := p.pos[1], p.pos[2]
	if !strings.HasPrefix(dst, "/") {
		return die("destination '%s' is not an absolute path", dst)
	}
	if !g.running {
		return die("CT %d not running", g.vmid)
	}
	data, err := s.eng.Exec(ctx, s.host, []string{"cat", src}, nil)
	if err != nil || data.Code != 0 {
		return die("unable to open file '%s' - No such file or directory", src)
	}
	dir := dst[:strings.LastIndex(dst, "/")+1]
	steps := [][]string{
		{"test", "-d", dir},
		{"sh", "-c", `cat > "$1"`, "sh", dst},
	}
	for i, argv := range steps {
		var stdin []byte
		if i == 1 {
			stdin = data.Stdout
		}
		if res, err := s.eng.Exec(ctx, g.container, argv, stdin); err != nil || res.Code != 0 {
			return die("unable to push '%s' to '%s' in CT %d: %s", src, dst, g.vmid, execFailure(res, err))
		}
	}
	perms := p.opts["perms"]
	if perms == "" {
		perms = "0644"
	}
	finish := [][]string{{"chmod", perms, dst}}
	if owner := ownerOf(p); owner != "" {
		finish = append(finish, []string{"chown", owner, dst})
	}
	for _, argv := range finish {
		if res, err := s.eng.Exec(ctx, g.container, argv, nil); err != nil || res.Code != 0 {
			return die("unable to set %s on '%s' in CT %d: %s", argv[0], dst, g.vmid, execFailure(res, err))
		}
	}
	return nil
}

func ownerOf(p parsed) string {
	user, group := p.opts["user"], p.opts["group"]
	switch {
	case user != "" && group != "":
		return user + ":" + group
	case user != "":
		return user
	case group != "":
		return ":" + group
	}
	return ""
}

func execFailure(res ExecResult, err error) string {
	if err != nil {
		return err.Error()
	}
	return strings.TrimSpace(string(res.Stderr))
}
