package discovery

import (
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

const probeHeader = "@@probe"

// Parse reads the output of the "probe" template. Output is untrusted: section
// headers are taken only from templates.ProbeSections, in order, and a section
// that fails to parse stays at its zero value without failing the others (one
// failed capability never makes the node unavailable, spec §12).
func Parse(output []byte) (Snapshot, error) {
	sections, err := splitSections(string(output))
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	s.Kernel = firstLine(sections["uname"])
	s.Hostname = firstLine(sections["hostname"])
	s.OS = parseOS(sections["os"])
	s.Uptime = parseUptime(firstLine(sections["uptime"]))
	s.CPU = parseCPU(sections["cpu"])
	s.Load = parseLoad(firstLine(sections["loadavg"]))
	s.Memory = parseMemory(sections["memory"])
	s.Disk = parseDisk(sections["disk"])
	s.PackageManagers = nonEmptyLines(sections["pkgmgr"])
	s.Systemd = parseSystemd(sections["systemd"])
	s.Docker = parseDocker(sections["docker"])
	s.Tools = parseTools(sections["tools"])
	s.PasswordlessSudo = firstLine(sections["sudo"]) == "yes"
	s.Probed = parseSetup(sections["setup"])
	s.Addresses = parseAddresses(sections["addresses"])
	return s, nil
}

func splitSections(output string) (map[string][]string, error) {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != probeHeader+" "+strconv.Itoa(templates.ProbeFormatVersion) {
		return nil, smerr.New(smerr.CodeProviderError, "", "probe output has an unknown format")
	}
	sections := map[string][]string{}
	next, current := 0, ""
	for _, line := range lines[1:] {
		if next < len(templates.ProbeSections) && line == "@@"+templates.ProbeSections[next] {
			current = templates.ProbeSections[next]
			sections[current] = nil
			next++
			continue
		}
		if current != "" {
			sections[current] = append(sections[current], line)
		}
	}
	return sections, nil
}

func firstLine(lines []string) string {
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}

func nonEmptyLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// keyValues reads KEY=value lines, unquoting a surrounding pair of quotes.
func keyValues(lines []string) map[string]string {
	kv := map[string]string{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	return kv
}

func parseOS(lines []string) OSInfo {
	kv := keyValues(lines)
	if len(kv) > 0 {
		return OSInfo{ID: kv["ID"], Name: kv["PRETTY_NAME"], Version: kv["VERSION_ID"]}
	}
	// macOS sw_vers: "ProductName:\tmacOS"
	sw := map[string]string{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, ":"); ok {
			sw[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	name := strings.TrimSpace(sw["ProductName"] + " " + sw["ProductVersion"])
	return OSInfo{ID: strings.ToLower(sw["ProductName"]), Name: name, Version: sw["ProductVersion"]}
}

func parseUptime(line string) time.Duration {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0
	}
	return time.Duration(seconds * float64(time.Second))
}

// parseCPU reads the core count, then two aggregate /proc/stat lines.
func parseCPU(lines []string) CPU {
	rows := nonEmptyLines(lines)
	if len(rows) == 0 {
		return CPU{}
	}
	var c CPU
	if n, err := strconv.Atoi(rows[0]); err == nil && n > 0 {
		c.Cores = n
	}
	if len(rows) == 2 {
		if idle, ok := topIdlePercent(rows[1]); ok {
			c.UsagePercent = clamp(100-idle, 0, 100)
			c.UsageKnown = true
		}
	}
	if len(rows) >= 3 {
		a, okA := cpuTimes(rows[1])
		b, okB := cpuTimes(rows[2])
		if okA && okB && b.total > a.total {
			busy := float64(b.total-b.idle) - float64(a.total-a.idle)
			c.UsagePercent = clamp(100*busy/float64(b.total-a.total), 0, 100)
			c.UsageKnown = true
		}
	}
	return c
}

// topIdlePercent reads macOS top's "CPU usage: 9.39% user, 6.40% sys, 84.19% idle".
func topIdlePercent(line string) (float64, bool) {
	rest, ok := strings.CutPrefix(line, "CPU usage:")
	if !ok {
		return 0, false
	}
	for _, part := range strings.Split(rest, ",") {
		if value, ok := strings.CutSuffix(strings.TrimSpace(part), "% idle"); ok {
			idle, err := strconv.ParseFloat(value, 64)
			return idle, err == nil && idle >= 0 && idle <= 100
		}
	}
	return 0, false
}

type cpuSample struct{ total, idle uint64 }

// cpuTimes parses "cpu user nice system idle iowait irq softirq steal ...".
// idle includes iowait.
func cpuTimes(line string) (cpuSample, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, false
	}
	var s cpuSample
	for i, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return cpuSample{}, false
		}
		if i < 8 { // guest columns are already counted in user/nice
			s.total += v
		}
		if i == 3 || i == 4 {
			s.idle += v
		}
	}
	return s, true
}

func clamp(v, lo, hi float64) float64 { return max(lo, min(hi, v)) }

func parseLoad(line string) [3]float64 {
	var load [3]float64
	fields := strings.Fields(strings.Trim(line, "{}"))
	for i := 0; i < len(fields) && i < 3; i++ {
		load[i], _ = strconv.ParseFloat(fields[i], 64)
	}
	return load
}

// parseMemory reads Linux meminfo lines (kB), or on macOS the hw.memsize bytes
// followed by vm_stat.
func parseMemory(lines []string) Memory {
	var m Memory
	for _, l := range lines {
		fields := strings.Fields(l)
		switch {
		case len(fields) >= 2 && fields[0] == "MemTotal:":
			m.TotalKB, _ = strconv.ParseUint(fields[1], 10, 64)
		case len(fields) >= 2 && fields[0] == "MemAvailable:":
			m.AvailableKB, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	if m.TotalKB == 0 {
		if bytes, err := strconv.ParseUint(firstLine(lines), 10, 64); err == nil {
			m.TotalKB = bytes / 1024
			m.AvailableKB = min(vmStatAvailableKB(lines), m.TotalKB)
		}
	}
	return m
}

// vmStatAvailableKB is what macOS can hand out without swapping: the free,
// inactive and speculative pages of vm_stat, in its own page size. 0 when
// vm_stat is missing.
func vmStatAvailableKB(lines []string) uint64 {
	var pageSize, pages uint64
	for _, l := range lines {
		if _, rest, ok := strings.Cut(l, "(page size of "); ok {
			pageSize, _ = strconv.ParseUint(strings.TrimSuffix(rest, " bytes)"), 10, 64)
			continue
		}
		name, value, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch name {
		case "Pages free", "Pages inactive", "Pages speculative":
			n, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(value), "."), 10, 64)
			pages += n
		}
	}
	if pageSize == 0 || pages > math.MaxUint64/pageSize {
		return 0 // a hostile or garbled vm_stat is "unknown", not a wrapped number
	}
	return pages * pageSize / 1024
}

// parseDisk reads the root filesystem line of `df -Pk /`.
func parseDisk(lines []string) Disk {
	rows := nonEmptyLines(lines)
	if len(rows) < 2 {
		return Disk{}
	}
	f := strings.Fields(rows[1])
	if len(f) < 4 {
		return Disk{}
	}
	total, e1 := strconv.ParseUint(f[1], 10, 64)
	used, e2 := strconv.ParseUint(f[2], 10, 64)
	avail, e3 := strconv.ParseUint(f[3], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		return Disk{}
	}
	return Disk{TotalKB: total, UsedKB: used, AvailableKB: avail}
}

// parseSystemd reads "active|absent", the systemctl path and the version line.
func parseSystemd(lines []string) Systemd {
	rows := nonEmptyLines(lines)
	var s Systemd
	for i, row := range rows {
		switch {
		case i == 0:
			s.Active = row == "active"
		case strings.HasPrefix(row, "/"):
			s.SystemctlPath = row
		case strings.HasPrefix(row, "systemd "):
			s.Version = strings.Fields(row)[1]
		}
	}
	return s
}

func parseDocker(lines []string) Docker {
	kv := keyValues(lines)
	return Docker{Path: kv["path"], ServerVersion: kv["server"], ComposeVersion: kv["compose"]}
}

func parseTools(lines []string) Tools {
	var t Tools
	flags := map[string]*bool{
		"lazydocker": &t.Lazydocker, "btop": &t.Btop, "tmux": &t.Tmux,
		"curl": &t.Curl, "bash": &t.Bash, "timeout": &t.Timeout, "flock": &t.Flock, "jq": &t.Jq,
		"ss": &t.Ss, "sha256sum": &t.Sha256sum, "base64": &t.Base64, "df": &t.Df,
	}
	for _, name := range nonEmptyLines(lines) {
		if flag, ok := flags[name]; ok {
			*flag = true
		}
	}
	return t
}

func parseSetup(lines []string) ProbedAs {
	kv := keyValues(lines)
	return ProbedAs{User: kv["user"], HomeExists: kv["home"] == "exists", MarkersWritable: kv["markers"] == "writable"}
}

// parseAddresses reads `ip -o addr show` and `ifconfig -a` lines alike: an
// "inet"/"inet6" word followed by the address. Scope is judged from the
// address itself, so a hostile line cannot claim a scope.
func parseAddresses(lines []string) []Address {
	var out []Address
	seen := map[string]bool{}
	for _, l := range lines {
		fields := strings.Fields(l)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "inet" && fields[i] != "inet6" {
				continue
			}
			if a, ok := toAddress(fields[i+1]); ok && !seen[a.Address] {
				seen[a.Address] = true
				out = append(out, a)
			}
			break
		}
	}
	return out
}

func toAddress(token string) (Address, bool) {
	token, _, _ = strings.Cut(token, "/")
	token, _, _ = strings.Cut(token, "%")
	ip, err := netip.ParseAddr(token)
	if err != nil {
		return Address{}, false
	}
	a := Address{Address: ip.String(), Family: "ipv6", Scope: "global"}
	if ip.Is4() {
		a.Family = "ipv4"
	}
	switch {
	case ip.IsLoopback():
		a.Scope = "loopback"
	case ip.IsLinkLocalUnicast():
		a.Scope = "link"
	case ip.IsPrivate():
		a.Scope = "private"
	}
	return a, true
}
