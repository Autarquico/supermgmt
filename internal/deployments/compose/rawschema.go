package compose

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The closed schema of spec §20.3 steps 4-6, applied to the merged source
// tree (ADR-0006, first pass). Anything not listed is rejected. Exemptible
// keys (step 7) pass here only structurally and with values from the fixed
// allowlist; the exact approved values are the model pass's business.

type check func(path string, n *node) error

var (
	serviceNamePattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	resourceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	envNamePattern      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

var exemptibleCapabilities = []string{"NET_BIND_SERVICE", "CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "KILL"}

var reservedLabelPrefixes = []string{"com.docker.", "dev.supermgmt."}

func checkSchema(root *node, t Target) error {
	s := schema{target: t, volumes: declared(root, "volumes"), networks: declared(root, "networks")}
	return s.document()("", root)
}

func declared(root *node, section string) map[string]bool {
	out := map[string]bool{}
	if m := root.get(section); m != nil && m.kind == mappingNode {
		for _, e := range m.entries {
			out[e.key] = true
		}
	}
	return out
}

type schema struct {
	target   Target
	volumes  map[string]bool
	networks map[string]bool
	services map[string]bool
}

func (s *schema) document() check {
	return object(true, map[string]check{
		"services": func(path string, n *node) error {
			s.services = map[string]bool{}
			if n.kind == mappingNode {
				for _, e := range n.entries {
					s.services[e.key] = true
				}
			}
			return namedMap(serviceNamePattern, "service name", s.service())(path, n)
		},
		"volumes":  namedMap(resourceNamePattern, "volume name", nullOr(object(false, map[string]check{"labels": labels}))),
		"networks": namedMap(resourceNamePattern, "network name", nullOr(object(false, map[string]check{"labels": labels, "internal": scalarOf("!!bool")}))),
	}, "services")
}

func (s *schema) service() check {
	return object(true, map[string]check{
		"image":             nonEmptyString,
		"command":           list(str),
		"entrypoint":        list(str),
		"environment":       mapOf(matching(envNamePattern, "environment variable name"), str),
		"ports":             list(s.port()),
		"expose":            list(portNumber),
		"healthcheck":       healthcheck(),
		"restart":           oneOf("no", "always", "on-failure", "unless-stopped"),
		"depends_on":        mapOf(s.knownService, object(false, map[string]check{"condition": oneOf("service_started", "service_healthy", "service_completed_successfully")})),
		"volumes":           list(s.mount()),
		"networks":          mapOf(s.knownNetwork, nullOr(object(false, map[string]check{"aliases": list(str)}))),
		"labels":            labels,
		"logging":           logging(),
		"user":              scalarOf("!!str", "!!int"),
		"working_dir":       str,
		"read_only":         scalarOf("!!bool"),
		"init":              scalarOf("!!bool"),
		"tmpfs":             list(absolutePath),
		"stop_signal":       str,
		"stop_grace_period": duration,
		"mem_limit":         scalarOf("!!str", "!!int"),
		"cpus":              scalarOf("!!str", "!!int", "!!float"),
		"pids_limit":        integer,
		"ulimits":           object(false, map[string]check{"nofile": ulimit(), "nproc": ulimit()}),
		"deploy":            deploy(),
		// Exemptible with admin approval (step 7); values bounded here, matched
		// against the approved exceptions by the model pass.
		"cap_add":     list(oneOf(exemptibleCapabilities...)),
		"sysctls":     mapOf(prefixed("net.", "sysctl name"), scalarOf("!!str", "!!int")),
		"extra_hosts": list(nonEmptyString),
		"shm_size":    scalarOf("!!str", "!!int"),
	}, "image")
}

func (s *schema) knownService(key string) error {
	if !s.services[key] {
		return fmt.Errorf("service %q is not defined", key)
	}
	return nil
}

func (s *schema) knownNetwork(key string) error {
	if key != "default" && !s.networks[key] {
		return fmt.Errorf("network %q is not declared at the top level", key)
	}
	return nil
}

func (s *schema) port() check {
	return object(false, map[string]check{
		"target":    portNumber,
		"published": portNumber,
		"host_ip":   s.hostIP,
		"protocol":  oneOf("tcp", "udp"),
	}, "target", "published", "host_ip")
}

func (s *schema) hostIP(path string, n *node) error {
	if err := str(path, n); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(n.value)
	if err != nil || addr.Zone() != "" {
		return rejected(path, n.line, "host_ip %q is not an IP address", n.value)
	}
	if addr == netip.MustParseAddr("127.0.0.1") || addr == netip.MustParseAddr("::1") {
		return nil
	}
	for _, allowed := range s.target.AllowedBind {
		if addr == allowed {
			return nil
		}
	}
	return rejected(path, n.line, "host_ip %s is neither loopback nor an allowed bind address of the target", addr)
}

func (s *schema) mount() check {
	return func(path string, n *node) error {
		if n.kind != mappingNode {
			return rejected(path, n.line, "volumes use the long syntax only (a mapping)")
		}
		typ := n.get("type")
		if typ == nil {
			return rejected(path, n.line, "required key %q is missing", "type")
		}
		if err := oneOf("volume", "tmpfs")(joinPath(path, "type"), typ); err != nil {
			return err
		}
		if typ.value == "tmpfs" {
			return object(false, map[string]check{
				"type":   str,
				"target": absolutePath,
				"tmpfs":  object(false, map[string]check{"size": scalarOf("!!int", "!!str"), "mode": scalarOf("!!int")}),
			}, "type", "target")(path, n)
		}
		return object(false, map[string]check{
			"type":      str,
			"source":    s.knownVolume,
			"target":    absolutePath,
			"read_only": scalarOf("!!bool"),
			"volume":    object(false, map[string]check{"nocopy": scalarOf("!!bool")}),
		}, "type", "source", "target")(path, n)
	}
}

func (s *schema) knownVolume(path string, n *node) error {
	if err := str(path, n); err != nil {
		return err
	}
	if !s.volumes[n.value] {
		return rejected(path, n.line, "volume %q is not declared at the top level (bind mounts are not allowed)", n.value)
	}
	return nil
}

func healthcheck() check {
	return object(false, map[string]check{
		"test":           list(str),
		"interval":       duration,
		"timeout":        duration,
		"retries":        integer,
		"start_period":   duration,
		"start_interval": duration,
		"disable":        scalarOf("!!bool"),
	})
}

func logging() check {
	return object(false, map[string]check{
		"driver": oneOf("json-file", "local"),
		"options": object(false, map[string]check{
			"max-size": scalarOf("!!str", "!!int"),
			"max-file": scalarOf("!!str", "!!int"),
			"compress": scalarOf("!!str", "!!bool"),
		}),
	})
}

func ulimit() check {
	return object(false, map[string]check{"soft": integer, "hard": integer}, "soft", "hard")
}

func deploy() check {
	limits := object(false, map[string]check{
		"cpus":   scalarOf("!!str", "!!int", "!!float"),
		"memory": scalarOf("!!str", "!!int"),
		"pids":   integer,
	})
	resources := object(false, map[string]check{"limits": limits})
	return object(false, map[string]check{"resources": resources})
}

// --- combinators ---

// object is a closed mapping. Extension keys (x-*) are tolerated only where
// allowExtensions is set; their content is validated after merging, like
// everything else.
func object(allowExtensions bool, fields map[string]check, required ...string) check {
	return func(path string, n *node) error {
		if n.kind != mappingNode {
			return rejected(path, n.line, "must be a mapping")
		}
		for _, e := range n.entries {
			if allowExtensions && isExtension(e.key) {
				continue
			}
			field, ok := fields[e.key]
			if !ok {
				return rejected(joinPath(path, e.key), e.keyLine, "key is not allowed")
			}
			if err := field(joinPath(path, e.key), e.val); err != nil {
				return err
			}
		}
		for _, k := range required {
			if n.get(k) == nil {
				return rejected(path, n.line, "required key %q is missing", k)
			}
		}
		return nil
	}
}

func namedMap(pattern *regexp.Regexp, what string, value check) check {
	return mapOf(matching(pattern, what), value)
}

func mapOf(keyOK func(string) error, value check) check {
	return func(path string, n *node) error {
		if n.kind != mappingNode {
			return rejected(path, n.line, "must be a mapping")
		}
		for _, e := range n.entries {
			p := joinPath(path, e.key)
			if err := keyOK(e.key); err != nil {
				return rejected(p, e.keyLine, "%v", err)
			}
			if err := value(p, e.val); err != nil {
				return err
			}
		}
		return nil
	}
}

func list(item check) check {
	return func(path string, n *node) error {
		if n.kind != sequenceNode {
			return rejected(path, n.line, "must be a list")
		}
		for i, it := range n.items {
			if err := item(fmt.Sprintf("%s[%d]", path, i), it); err != nil {
				return err
			}
		}
		return nil
	}
}

func nullOr(c check) check {
	return func(path string, n *node) error {
		if n.kind == scalarNode && n.tag == "!!null" {
			return nil
		}
		return c(path, n)
	}
}

func matching(pattern *regexp.Regexp, what string) func(string) error {
	return func(key string) error {
		if !pattern.MatchString(key) {
			return fmt.Errorf("invalid %s %q", what, key)
		}
		return nil
	}
}

func prefixed(prefix, what string) func(string) error {
	return func(key string) error {
		if !strings.HasPrefix(key, prefix) {
			return fmt.Errorf("%s %q must start with %q", what, key, prefix)
		}
		return nil
	}
}

// --- scalars ---

func scalarOf(tags ...string) check {
	return func(path string, n *node) error {
		if n.kind == scalarNode {
			for _, t := range tags {
				if n.tag == t {
					return nil
				}
			}
		}
		return rejected(path, n.line, "must be a scalar of type %s", strings.Join(tags, " or "))
	}
}

var str = scalarOf("!!str")

func nonEmptyString(path string, n *node) error {
	if err := str(path, n); err != nil {
		return err
	}
	if n.value == "" {
		return rejected(path, n.line, "must not be empty")
	}
	return nil
}

func oneOf(values ...string) check {
	return func(path string, n *node) error {
		if err := str(path, n); err != nil {
			return err
		}
		for _, v := range values {
			if n.value == v {
				return nil
			}
		}
		return rejected(path, n.line, "%q is not one of %s", n.value, strings.Join(values, ", "))
	}
}

func integer(path string, n *node) error {
	if err := scalarOf("!!int")(path, n); err != nil {
		return err
	}
	if _, err := strconv.ParseInt(n.value, 0, 64); err != nil {
		return rejected(path, n.line, "%q is not a valid integer", n.value)
	}
	return nil
}

func portNumber(path string, n *node) error {
	if err := integer(path, n); err != nil {
		return rejected(path, n.line, "must be an integer port number (strings and ranges are not allowed)")
	}
	v, _ := strconv.ParseInt(n.value, 0, 64)
	if v < 1 || v > 65535 {
		return rejected(path, n.line, "port %d is outside 1-65535", v)
	}
	return nil
}

func duration(path string, n *node) error {
	if err := str(path, n); err != nil {
		return err
	}
	if _, err := time.ParseDuration(n.value); err != nil {
		return rejected(path, n.line, "%q is not a duration", n.value)
	}
	return nil
}

func absolutePath(path string, n *node) error {
	if err := str(path, n); err != nil {
		return err
	}
	if !strings.HasPrefix(n.value, "/") || strings.ContainsAny(n.value, ":\x00") {
		return rejected(path, n.line, "%q must be an absolute container path without options", n.value)
	}
	return nil
}

func labels(path string, n *node) error {
	return mapOf(func(key string) error {
		for _, p := range reservedLabelPrefixes {
			if strings.HasPrefix(strings.ToLower(key), p) {
				return fmt.Errorf("label keys under %s* are reserved", p)
			}
		}
		return nil
	}, str)(path, n)
}
