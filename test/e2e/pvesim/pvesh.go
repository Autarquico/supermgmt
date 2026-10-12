package pvesim

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var reNodeNetworkPath = regexp.MustCompile(`^/nodes/([^/]+)/network$`)

// pveshGlobal are the options every pvesh command takes.
var pveshGlobal = merge(outputFormat, map[string]check{
	"noproxy": boolean, "noborder": boolean, "noheader": boolean, "human-readable": boolean, "quiet": boolean,
})

var bridgeTypes = []string{"bridge", "OVSBridge"}

func networkTypeCheck(v string) error {
	return oneOf("bridge", "bond", "eth", "alias", "vlan", "OVSBridge", "OVSBond", "OVSPort", "OVSIntPort", "vnet",
		"any_bridge", "any_local_bridge", "include_sdn")(v)
}

// pvesh is the part of `pvesh get` the installer uses: /cluster/nextid, /nodes/{node}/network and
// the two discovery paths /version and /nodes.
func (s *Sim) pvesh(_ context.Context, args []string) (string, error) {
	if len(args) == 0 || args[0] != "get" {
		return "", die("USAGE: pvesh <get|create|set|delete|ls|usage> <api_path> [OPTIONS]\npvesim: only 'get' is implemented")
	}
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return "", die("400 not enough arguments (missing api_path)")
	}
	path := strings.TrimRight(args[1], "/")
	cmd, ok := s.pveshPath(path)
	if !ok {
		return "", die("Method 'GET %s' not implemented", path)
	}
	cmd.positional = nil
	p, err := cmd.parse(args[2:])
	if err != nil {
		return "", err
	}
	data, err := s.pveshGet(path, p)
	if err != nil {
		return "", err
	}
	return render(data, p), nil
}

func (s *Sim) pveshPath(path string) (command, bool) {
	switch {
	case path == "/cluster/nextid":
		return command{opts: merge(pveshGlobal, map[string]check{"vmid": vmidCheck})}, true
	case path == "/version", path == "/nodes":
		return command{opts: pveshGlobal}, true
	case reNodeNetworkPath.MatchString(path):
		return command{opts: merge(pveshGlobal, map[string]check{"type": networkTypeCheck})}, true
	}
	return command{}, false
}

func (s *Sim) pveshGet(path string, p parsed) (any, error) {
	switch path {
	case "/cluster/nextid":
		return s.nextID(p)
	case "/version":
		return map[string]any{"version": s.cfg.Version, "release": majorMinor(s.cfg.Version), "repoid": "b6ee0f0bd4aaf2e7"}, nil
	case "/nodes":
		return []map[string]any{{"node": s.cfg.Node, "status": "online", "type": "node"}}, nil
	}
	node := reNodeNetworkPath.FindStringSubmatch(path)[1]
	if node != s.cfg.Node {
		return nil, die("hostname lookup '%s' failed - failed to get address info for: %s: Name or service not known", node, node)
	}
	return s.networks(p.opts["type"]), nil
}

func majorMinor(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

func (s *Sim) nextID(p parsed) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := p.opts["vmid"]; ok {
		id, _ := strconv.Atoi(v)
		if _, taken := s.guests[id]; taken {
			return nil, die("VM %d already exists", id)
		}
		return v, nil
	}
	for id := 100; ; id++ {
		if _, taken := s.guests[id]; !taken {
			return strconv.Itoa(id), nil
		}
	}
}

func (s *Sim) networks(typ string) []map[string]any {
	rows := []map[string]any{
		{"iface": "eth0", "type": "eth", "active": 1, "method": "manual", "priority": 1},
		{
			"iface": s.cfg.Bridge, "type": "bridge", "active": 1, "method": "static", "priority": 2,
			"address": s.cfg.APIAddress, "netmask": "24", "cidr": s.cfg.APIAddress + "/24", "bridge_ports": "eth0",
		},
	}
	var out []map[string]any
	for _, r := range rows {
		kind := r["type"].(string)
		if typ == "" || typ == kind || ((typ == "any_bridge" || typ == "any_local_bridge") && contains(bridgeTypes, kind)) {
			out = append(out, r)
		}
	}
	return out
}

// render prints data the way pvesh does: JSON when asked for it, the bare value for a scalar
// otherwise. Tables are not drawn.
func render(data any, p parsed) string {
	if p.wantsJSON() {
		raw, _ := json.Marshal(data)
		return string(raw) + "\n"
	}
	if v, ok := data.(string); ok {
		return v + "\n"
	}
	raw, _ := json.MarshalIndent(data, "", "  ")
	return string(raw) + "\n"
}

// ---- pvesm ----

var pvesmCommands = map[string]command{
	"status": {opts: merge(outputFormat, map[string]check{"content": anyText, "enabled": boolean, "format": boolean, "storage": anyText, "target": anyText})},
}

func (s *Sim) pvesm(_ context.Context, args []string) (string, error) {
	cmd, rest, err := subcommand("pvesm", pvesmCommands, args)
	if err != nil {
		return "", err
	}
	p, err := cmd.parse(rest)
	if err != nil {
		return "", err
	}
	if err := p.requireJSON(); err != nil {
		return "", err
	}
	var rows []map[string]any
	for _, st := range s.cfg.Storages {
		if want := p.opts["content"]; want != "" && !hasAnyContent(st.Content, want) {
			continue
		}
		if want := p.opts["storage"]; want != "" && want != st.ID {
			continue
		}
		total := int64(st.TotalGB) << 30
		rows = append(rows, map[string]any{
			"storage": st.ID, "type": st.Type, "content": st.Content, "active": boolInt(st.Active), "enabled": 1, "shared": 0,
			"total": total, "used": 0, "avail": total, "used_fraction": 0,
		})
	}
	return render(rows, p), nil
}

func hasAnyContent(have, want string) bool {
	for _, w := range strings.Split(want, ",") {
		if contains(strings.Split(have, ","), w) {
			return true
		}
	}
	return false
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- pveam ----

var pveamCommands = map[string]command{
	"available": {opts: map[string]check{"section": oneOf("system", "turnkeylinux", "mail")}},
	"list":      {positional: []string{"storage"}},
	"download":  {positional: []string{"storage", "template"}},
	"update":    {},
}

func (s *Sim) pveam(_ context.Context, args []string) (string, error) {
	cmd, rest, err := subcommand("pveam", pveamCommands, args)
	if err != nil {
		return "", err
	}
	p, err := cmd.parse(rest)
	if err != nil {
		return "", err
	}
	switch args[0] {
	case "available":
		return s.templatesOffered(p), nil
	case "list":
		return s.templatesOn(p.pos[0])
	case "download":
		return "", s.downloadTemplate(p.pos[0], p.pos[1])
	}
	return "update successful\n", nil
}

func (s *Sim) templatesOffered(p parsed) string {
	if sec := p.opts["section"]; sec != "" && sec != "system" {
		return ""
	}
	var b strings.Builder
	for _, name := range s.cfg.Available {
		fmt.Fprintf(&b, "%-15s %s\n", "system", name)
	}
	return b.String()
}

func (s *Sim) templateStorage(id string) error {
	st, ok := s.cfg.storage(id)
	switch {
	case !ok:
		return die("storage '%s' does not exist", id)
	case !contains(strings.Split(st.Content, ","), "vztmpl"):
		return die("storage '%s' does not support templates", id)
	}
	return nil
}

func (s *Sim) templatesOn(storage string) (string, error) {
	if err := s.templateStorage(storage); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var vols []string
	for v := range s.templates {
		if strings.HasPrefix(v, storage+":vztmpl/") {
			vols = append(vols, v)
		}
	}
	sort.Strings(vols)
	var b strings.Builder
	fmt.Fprintf(&b, "%-70s %s\n", "NAME", "SIZE")
	for _, v := range vols {
		fmt.Fprintf(&b, "%-70s %s\n", v, "120.00MB")
	}
	return b.String(), nil
}

func (s *Sim) downloadTemplate(storage, name string) error {
	if err := s.templateStorage(storage); err != nil {
		return err
	}
	if !contains(s.cfg.Available, name) {
		return die("no such template '%s'", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.templates[storage+":vztmpl/"+name] = true
	return nil
}

// ---- pveversion ----

func (s *Sim) pveversion(_ context.Context, args []string) (string, error) {
	line := fmt.Sprintf("pve-manager/%s/b6ee0f0bd4aaf2e7 (running kernel: 6.14.8-2-pve)\n", s.cfg.Version)
	switch {
	case len(args) == 0:
		return line, nil
	case len(args) == 1 && (args[0] == "-v" || args[0] == "--verbose"):
		return line + "proxmox-ve: " + s.cfg.Version + " (running kernel: 6.14.8-2-pve)\n", nil
	}
	return "", die("USAGE: pveversion [--verbose]\nunknown option: %s", strings.Join(args, " "))
}
