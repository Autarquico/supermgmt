package templates

import "strings"

// ProbeFormatVersion is the number after "@@probe " on the first output line.
const ProbeFormatVersion = 1

// ProbeSections lists the sections of the "probe" output, in output order.
//
// The output is plain text. The first line is "@@probe 1"; every section then
// starts with a header line "@@<name>" and runs until the next header. Each
// section appears exactly once, in this order, even when everything inside it
// failed (an empty section means "unknown", never "false"). Remote output is
// untrusted: a parser takes headers only from this list, in this order.
//
//	uname      one line: "uname -srm" (kernel name, release, machine)
//	os         /etc/os-release (KEY=value lines) or, on macOS, "sw_vers" lines
//	hostname   one line
//	uptime     Linux: "/proc/uptime" ("<seconds> <idle>"); macOS: kern.boottime
//	cpu        line 1: online CPU count; then, on Linux, two aggregate "cpu "
//	           lines of /proc/stat taken one second apart (CPU% = delta of both)
//	loadavg    Linux: /proc/loadavg; macOS: vm.loadavg
//	memory     Linux: the first 8 /proc/meminfo lines (kB); macOS: hw.memsize
//	           bytes, then vm_stat lines
//	disk       "df -Pk /" header and root-filesystem line
//	pkgmgr     one name per line, from: apt-get dnf yum zypper apk pacman brew
//	systemd    "active" or "absent" (/run/systemd/system), then the systemctl
//	           path if any, then the first "systemctl --version" line
//	docker     "path=<docker binary>", and when present "server=<version>"
//	           (empty when the daemon is unreachable or access is denied) and
//	           "compose=<version>" (empty when the plugin is missing)
//	tools      one name per line, from: lazydocker btop tmux curl bash timeout flock jq ss sha256sum base64 df
//	sudo       "yes" when "sudo -n true" succeeds, otherwise "no"
//	setup      "user=<id -un>", "home=exists|absent" for /var/lib/supermgmt,
//	           "markers=writable|unwritable|absent" for the markers directory
//	addresses  "ip -o addr show" (or "ifconfig -a") lines, at most 64
var ProbeSections = []string{
	"uname", "os", "hostname", "uptime", "cpu", "loadavg", "memory", "disk",
	"pkgmgr", "systemd", "docker", "tools", "sudo", "setup", "addresses",
}

// probeScript is POSIX sh, run through "sh -c" so the node's login shell does
// not matter. Every section tolerates the failure of its own commands. The
// docker format string is built with octal escapes because the catalog
// reserves the double-brace sequence for placeholders.
const probeScript = `
t() { if command -v timeout >/dev/null 2>&1; then timeout 5 "$@"; else "$@"; fi; }
s() { printf "@@%s\n" "$1"; }
printf "@@probe 1\n"
s uname; uname -srm 2>/dev/null
s os; { cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null; } | head -n 30
s hostname; hostname 2>/dev/null | head -n 1
s uptime; { cat /proc/uptime 2>/dev/null || sysctl -n kern.boottime 2>/dev/null; } | head -n 1
s cpu
getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null
if [ -r /proc/stat ]; then head -n 1 /proc/stat; sleep 1; head -n 1 /proc/stat; fi
s loadavg; { cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg 2>/dev/null; } | head -n 1
s memory
if [ -r /proc/meminfo ]; then head -n 8 /proc/meminfo; else sysctl -n hw.memsize 2>/dev/null; vm_stat 2>/dev/null | head -n 8; fi
s disk; df -Pk / 2>/dev/null | head -n 2
s pkgmgr
for p in apt-get dnf yum zypper apk pacman brew; do command -v "$p" >/dev/null 2>&1 && echo "$p"; done
s systemd
if [ -d /run/systemd/system ]; then echo active; else echo absent; fi
command -v systemctl 2>/dev/null
systemctl --version 2>/dev/null | head -n 1
s docker
d=$(command -v docker 2>/dev/null)
echo "path=$d"
if [ -n "$d" ]; then
  f=$(printf "\173\173.Server.Version\175\175")
  echo "server=$(t docker version --format "$f" 2>/dev/null | head -n 1)"
  echo "compose=$(t docker compose version --short 2>/dev/null | head -n 1)"
fi
s tools
for p in lazydocker btop tmux curl bash timeout flock jq ss sha256sum base64 df; do command -v "$p" >/dev/null 2>&1 && echo "$p"; done
s sudo; if t sudo -n true >/dev/null 2>&1; then echo yes; else echo no; fi
s setup
echo "user=$(id -un 2>/dev/null)"
if [ -d /var/lib/supermgmt ]; then echo home=exists; else echo home=absent; fi
if [ ! -d @MARKERS@ ]; then echo markers=absent
elif [ -w @MARKERS@ ]; then echo markers=writable
else echo markers=unwritable; fi
s addresses; { ip -o addr show 2>/dev/null || ifconfig -a 2>/dev/null; } | head -n 64
true
`

// probeTemplates holds the node probe (spec §12): one session returns every value.
var probeTemplates = []Template{{
	Name:     "probe",
	Body:     "sh -c " + Quote(strings.ReplaceAll(probeScript, "@MARKERS@", MarkerDir)),
	MaxBytes: 64 << 10,
	MaxLines: 600,
}}
