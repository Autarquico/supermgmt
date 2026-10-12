package pvefake

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	upidPattern = regexp.MustCompile(`^UPID:[A-Za-z0-9-]+:[0-9A-F]{8}:[0-9A-F]{8}:[0-9A-F]{8}:[a-z0-9]+:[^:]*:[^:]+:$`)
	intPattern  = regexp.MustCompile(`^[0-9]{1,10}$`)
)

type paramCheck func(string) bool

func isInt(s string) bool { return intPattern.MatchString(s) }

func oneOf(values ...string) paramCheck {
	return func(s string) bool {
		for _, v := range values {
			if s == v {
				return true
			}
		}
		return false
	}
}

func anyText(s string) bool { return s != "" }

// checkParams enforces PVE's schema validation: unknown parameters and
// malformed values are 400s with a per-parameter error map.
func checkParams(w http.ResponseWriter, got url.Values, schema map[string]paramCheck) bool {
	errs := map[string]string{}
	for name, values := range got {
		check, known := schema[name]
		switch {
		case !known:
			errs[name] = "property is not defined in schema and the schema does not allow additional properties"
		case len(values) != 1 || !check(values[0]):
			errs[name] = "value does not match the expected format"
		}
	}
	if len(errs) > 0 {
		writeError(w, http.StatusBadRequest, "Parameter verification failed.", errs)
		return false
	}
	return true
}

func (f *Fake) getVersion(w http.ResponseWriter, c *call) {
	if !checkParams(w, c.r.URL.Query(), nil) {
		return
	}
	writeData(w, map[string]string{"version": "9.0.3", "release": "9.0", "repoid": "fake0000"})
}

func (f *Fake) getResources(w http.ResponseWriter, c *call) {
	if !checkParams(w, c.r.URL.Query(), map[string]paramCheck{"type": oneOf("vm", "storage", "node", "sdn")}) {
		return
	}
	want := c.r.URL.Query().Get("type")
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := []map[string]any{}
	if want == "" || want == "node" {
		for _, name := range f.sortedNodes() {
			if !f.allowed(c.tokenID, "/nodes/"+name, "Sys.Audit") {
				continue
			}
			status := map[bool]string{true: "online", false: "offline"}[f.nodes[name].online]
			rows = append(rows, map[string]any{
				"id": "node/" + name, "type": "node", "node": name, "status": status,
				"maxcpu": 8, "maxmem": 16 << 30, "cpu": 0.05, "mem": 4 << 30, "uptime": 86400,
			})
		}
	}
	if want == "" || want == "vm" {
		for _, vmid := range f.sortedVMIDs() {
			g := f.guests[vmid]
			if !f.allowed(c.tokenID, "/vms/"+strconv.Itoa(vmid), "VM.Audit") {
				continue
			}
			rows = append(rows, guestRow(g))
		}
	}
	if want == "" || want == "storage" {
		for _, s := range f.storages {
			if !f.allowed(c.tokenID, "/storage/"+s.ID, "Datastore.Audit") {
				continue
			}
			rows = append(rows, map[string]any{
				"id": "storage/" + s.Node + "/" + s.ID, "type": "storage", "storage": s.ID, "node": s.Node,
				"plugin": s.Plugin, "content": strings.Join(s.Content, ","), "maxdisk": s.Total, "disk": s.Used,
				"shared": boolInt(s.Shared), "status": "available",
			})
		}
	}
	writeData(w, rows)
}

func guestRow(g *Guest) map[string]any {
	row := map[string]any{
		"id": g.Type + "/" + strconv.Itoa(g.VMID), "type": g.Type, "vmid": g.VMID, "node": g.Node,
		"name": g.Name, "status": g.Status, "template": boolInt(g.Template),
		"maxcpu": g.MaxCPU, "maxmem": g.MaxMem, "maxdisk": g.MaxDisk,
		"cpu": g.CPU, "mem": g.Mem, "disk": g.Disk, "uptime": g.Uptime,
	}
	if g.Pool != "" {
		row["pool"] = g.Pool
	}
	if g.Lock != "" {
		row["lock"] = g.Lock
	}
	return row
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (f *Fake) getPermissions(w http.ResponseWriter, c *call) {
	if !checkParams(w, c.r.URL.Query(), map[string]paramCheck{"path": anyText}) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	all := f.permissions(c.tokenID)
	if path := c.r.URL.Query().Get("path"); path != "" {
		one := map[string]map[string]int{}
		privs := map[string]int{}
		for p := range f.effective(c.tokenID, path) {
			privs[p] = 1
		}
		if len(privs) > 0 {
			one[path] = privs
		}
		all = one
	}
	writeData(w, all)
}

func (f *Fake) knownNode(w http.ResponseWriter, name string) bool {
	if f.nodes[name] == nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("hostname lookup '%s' failed - failed to get address info for: %s", name, name), nil)
		return false
	}
	return true
}

func (f *Fake) listTasks(w http.ResponseWriter, c *call) {
	schema := map[string]paramCheck{
		"start": isInt, "limit": isInt, "vmid": isInt, "since": isInt, "until": isInt,
		"typefilter": anyText, "userfilter": anyText,
	}
	q := c.r.URL.Query()
	if !checkParams(w, q, schema) {
		return
	}
	node := c.r.PathValue("node")
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.knownNode(w, node) {
		return
	}
	seeAll := f.allowed(c.tokenID, "/nodes/"+node, "Sys.Audit")
	var matched []*task
	for i := len(f.tasks) - 1; i >= 0; i-- { // newest first
		if tk := f.tasks[i]; tk.node == node && (seeAll || tk.user == c.tokenID) && taskMatches(tk, q) {
			matched = append(matched, tk)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].start.After(matched[j].start) })
	start, limit := atoiDefault(q.Get("start"), 0), atoiDefault(q.Get("limit"), 50)
	start = min(start, len(matched))
	end := min(start+limit, len(matched))
	rows := []map[string]any{}
	for _, tk := range matched[start:end] {
		row := map[string]any{
			"upid": tk.upid, "node": tk.node, "pid": tk.pid, "pstart": tk.pid, "starttime": tk.start.Unix(),
			"type": tk.typ, "id": tk.id, "user": tk.user,
		}
		if !tk.running {
			row["status"] = tk.exit
		}
		rows = append(rows, row)
	}
	writeJSON(w, map[string]any{"data": rows, "total": len(matched)})
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func taskMatches(tk *task, q url.Values) bool {
	switch {
	case q.Has("vmid") && tk.id != q.Get("vmid"):
	case q.Has("typefilter") && tk.typ != q.Get("typefilter"):
	case q.Has("userfilter") && !strings.Contains(tk.user, q.Get("userfilter")): // PVE: substring
	case q.Has("since") && tk.start.Unix() < int64(atoiDefault(q.Get("since"), 0)):
	case q.Has("until") && tk.start.Unix() > int64(atoiDefault(q.Get("until"), 0)):
	default:
		return true
	}
	return false
}

func (f *Fake) taskStatus(w http.ResponseWriter, c *call) {
	if !checkParams(w, c.r.URL.Query(), nil) {
		return
	}
	node, upid := c.r.PathValue("node"), c.r.PathValue("upid")
	if !upidPattern.MatchString(upid) {
		writeError(w, http.StatusBadRequest, "Parameter verification failed.", map[string]string{"upid": "value does not match the expected format"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.knownNode(w, node) {
		return
	}
	for _, tk := range f.tasks {
		if tk.upid != upid || tk.node != node {
			continue
		}
		if !f.allowed(c.tokenID, "/nodes/"+node, "Sys.Audit") && tk.user != c.tokenID {
			writeError(w, http.StatusForbidden, "Permission check failed (/nodes/"+node+", Sys.Audit)", nil)
			return
		}
		data := map[string]any{
			"upid": tk.upid, "node": node, "pid": tk.pid, "pstart": tk.pid, "starttime": tk.start.Unix(),
			"type": tk.typ, "id": tk.id, "user": tk.user, "status": "running",
		}
		if !tk.running {
			data["status"], data["exitstatus"] = "stopped", tk.exit
		}
		writeData(w, data)
		return
	}
	writeError(w, http.StatusInternalServerError, "no such task", nil)
}

func (f *Fake) power(w http.ResponseWriter, c *call) {
	node, typ, verb := c.r.PathValue("node"), c.r.PathValue("type"), c.r.PathValue("verb")
	schema, routed := powerSchema(typ, verb)
	vmid, err := strconv.Atoi(c.r.PathValue("vmid"))
	if !routed || err != nil || vmid <= 0 {
		writeError(w, http.StatusNotImplemented, fmt.Sprintf("Method 'POST %s' not implemented", strings.TrimPrefix(c.r.URL.Path, apiPrefix)), nil)
		return
	}
	if !checkParams(w, c.r.PostForm, schema) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.allowed(c.tokenID, "/vms/"+strconv.Itoa(vmid), "VM.PowerMgmt") {
		writeError(w, http.StatusForbidden, fmt.Sprintf("Permission check failed (/vms/%d, VM.PowerMgmt)", vmid), nil)
		return
	}
	if !f.knownNode(w, node) {
		return
	}
	g, msg := f.powerTarget(node, typ, vmid, verb)
	if msg != "" {
		writeError(w, http.StatusInternalServerError, msg, nil)
		return
	}
	tk := f.newTask(node, typ, verb, vmid, c.tokenID, func() { applyPower(g, verb) })
	writeData(w, tk.upid)
}

// powerSchema is the parameter schema of each power route in PVE 9: QEMU
// start/stop/shutdown/reboot and LXC start/shutdown/reboot take `timeout`
// where it applies; LXC stop takes none.
func powerSchema(typ, verb string) (map[string]paramCheck, bool) {
	switch {
	case typ == "qemu" && oneOf("start", "stop", "shutdown", "reboot")(verb):
		return map[string]paramCheck{"timeout": isInt}, true
	case typ == "lxc" && oneOf("shutdown", "reboot")(verb):
		return map[string]paramCheck{"timeout": isInt}, true
	case typ == "lxc" && oneOf("start", "stop")(verb):
		return nil, true
	}
	return nil, false
}

// powerTarget finds the guest on that node and checks the transition; the
// message is non-empty when PVE would refuse.
func (f *Fake) powerTarget(node, typ string, vmid int, verb string) (*Guest, string) {
	g := f.guests[vmid]
	if g == nil || g.Node != node || g.Type != typ {
		dir := map[string]string{"qemu": "qemu-server", "lxc": "lxc"}[typ]
		return nil, fmt.Sprintf("Configuration file 'nodes/%s/%s/%d.conf' does not exist", node, dir, vmid)
	}
	switch {
	case g.Lock != "":
		return nil, fmt.Sprintf("VM is locked (%s)", g.Lock)
	case verb == "start" && g.Template:
		return nil, "you can't start a vm if it's a template"
	case verb == "start" && g.Status == "running":
		return nil, fmt.Sprintf("VM %d already running", vmid)
	case verb != "start" && g.Status != "running":
		return nil, fmt.Sprintf("VM %d not running", vmid)
	}
	return g, ""
}

func applyPower(g *Guest, verb string) {
	switch verb {
	case "start":
		g.Status = "running"
	case "stop", "shutdown":
		g.Status = "stopped"
	}
}

func taskType(guestType, verb string) string {
	return map[string]string{"qemu": "qm", "lxc": "vz"}[guestType] + verb
}

// newTask records a task; in automatic mode it ends "OK" at once.
func (f *Fake) newTask(node, guestType, verb string, vmid int, user string, effect func()) *task {
	f.nextPID++
	start := f.now().UTC().Truncate(time.Second)
	typ := taskType(guestType, verb)
	tk := &task{
		node: node, typ: typ, id: strconv.Itoa(vmid), user: user, start: start, pid: f.nextPID,
		running: true, effect: effect,
		upid: fmt.Sprintf("UPID:%s:%08X:%08X:%08X:%s:%d:%s:", node, f.nextPID, f.nextPID, start.Unix(), typ, vmid, user),
	}
	f.tasks = append(f.tasks, tk)
	if !f.manualTasks {
		f.finish(tk, "OK")
	}
	return tk
}

func (f *Fake) sortedNodes() []string {
	out := make([]string, 0, len(f.nodes))
	for n := range f.nodes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (f *Fake) sortedVMIDs() []int {
	out := make([]int, 0, len(f.guests))
	for id := range f.guests {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}
