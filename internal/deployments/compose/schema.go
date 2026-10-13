package compose

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"
)

// CheckModel is the model pass of the closed-schema validation (spec §20.3
// steps 4–7, ADR-0006): the loaded project, rendered as the plain document
// the CLI would see, must contain only allowlisted keys with allowlisted
// values. The four exemptible keys pass only with the exact values in e.
// Anything the loader adds or rewrites that is not on the list fails here.
func CheckModel(p *types.Project, t Target, e Exceptions) error {
	if len(p.DisabledServices) > 0 {
		return modelViolation("services", "profiles are not allowed")
	}
	doc, err := modelDocument(p)
	if err != nil {
		return err
	}
	return newModelChecker(t, e, doc).document(doc)
}

func modelDocument(p *types.Project) (map[string]any, error) {
	raw, err := p.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("render compose model: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode compose model: %w", err)
	}
	return doc, nil
}

type modelCheck func(path string, v any) error

// modelChecker carries what the checks need beyond the document shape: the
// target (project name, bind policy), the approved exceptions and which
// top-level volumes and networks exist.
type modelChecker struct {
	target     Target
	exceptions Exceptions
	volumes    map[string]bool
	networks   map[string]bool
	services   map[string]bool
}

func newModelChecker(t Target, e Exceptions, doc map[string]any) *modelChecker {
	return &modelChecker{
		target:     t,
		exceptions: e,
		volumes:    keySet(doc["volumes"]),
		networks:   keySet(doc["networks"]),
		services:   keySet(doc["services"]),
	}
}

func keySet(v any) map[string]bool {
	set := map[string]bool{}
	m, _ := v.(map[string]any)
	for k := range m {
		set[k] = true
	}
	return set
}

func (c *modelChecker) document(doc map[string]any) error {
	for _, key := range slices.Sorted(maps.Keys(doc)) {
		if err := c.topLevel(key, doc[key]); err != nil {
			return err
		}
	}
	if len(c.services) == 0 {
		return modelViolation("services", "at least one service is required")
	}
	return nil
}

func (c *modelChecker) topLevel(key string, v any) error {
	switch {
	case key == "name":
		return c.projectName(key, v)
	case key == "services":
		return c.mapByKey(c.service)(key, v)
	case key == "volumes":
		return c.mapByKey(c.resource("volume", c.object(map[string]modelCheck{"labels": c.labelMap})))(key, v)
	case key == "networks":
		return c.mapByKey(c.resource("network", c.object(map[string]modelCheck{
			"labels": c.labelMap, "internal": c.boolean, "ipam": c.emptyObject,
		})))(key, v)
	case isExtension(key):
		return nil
	}
	return modelViolation(key, "top-level key is not allowed")
}

func isExtension(key string) bool { return strings.HasPrefix(key, "x-") }

func (c *modelChecker) projectName(path string, v any) error {
	if v != c.target.Project {
		return modelViolation(path, "must be the target's compose project")
	}
	return nil
}

// resource returns, per top-level volume or network key, a check that admits
// only the allowlisted keys and a name that is exactly the project-prefixed
// key, so an explicit `name` or `external` cannot attach to a resource of
// another workload (§20.3 step 6).
func (c *modelChecker) resource(kind string, shape modelCheck) func(key string) modelCheck {
	return func(key string) modelCheck {
		return func(path string, v any) error {
			m, ok := v.(map[string]any)
			if !ok {
				return modelViolation(path, "must be a mapping")
			}
			if name, present := m["name"]; present && name != c.target.Project+"_"+key {
				return modelViolation(join(path, "name"), "%s names are derived from the project and cannot be set", kind)
			}
			rest := maps.Clone(m)
			delete(rest, "name")
			return shape(path, rest)
		}
	}
}

func (c *modelChecker) service(name string) modelCheck {
	return c.extensible(c.object(map[string]modelCheck{
		"image":             c.str,
		"command":           c.nullable(c.listOf(c.str)),
		"entrypoint":        c.nullable(c.listOf(c.str)),
		"environment":       c.mapOf(c.str),
		"ports":             c.listOf(c.port),
		"expose":            c.listOf(c.integer),
		"healthcheck":       c.healthcheck,
		"restart":           c.oneOf("no", "always", "on-failure", "unless-stopped"),
		"depends_on":        c.mapByKey(c.dependency),
		"volumes":           c.listOf(c.volumeMount),
		"networks":          c.serviceNetworks,
		"labels":            c.serviceLabels,
		"logging":           c.logging,
		"user":              c.str,
		"working_dir":       c.str,
		"read_only":         c.boolean,
		"init":              c.boolean,
		"tmpfs":             c.listOf(c.absolutePath),
		"stop_signal":       c.str,
		"stop_grace_period": c.str,
		"mem_limit":         c.numeric,
		"cpus":              c.numeric,
		"pids_limit":        c.integer,
		"ulimits":           c.ulimits,
		"deploy":            c.deploy,
		"cap_add":           c.capAdd(name),
		"sysctls":           c.sysctls(name),
		"extra_hosts":       c.extraHosts(name),
		"shm_size":          c.shmSize(name),
	}))
}

// extensible lets `x-*` keys through next to the closed key set.
func (c *modelChecker) extensible(shape modelCheck) modelCheck {
	return func(path string, v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return modelViolation(path, "must be a mapping")
		}
		rest := maps.Clone(m)
		for k := range rest {
			if isExtension(k) {
				delete(rest, k)
			}
		}
		return shape(path, rest)
	}
}

// ---- combinators ----

func (c *modelChecker) object(fields map[string]modelCheck) modelCheck {
	return func(path string, v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return modelViolation(path, "must be a mapping")
		}
		for _, key := range slices.Sorted(maps.Keys(m)) {
			check, allowed := fields[key]
			if !allowed {
				return modelViolation(join(path, key), "key is not allowed")
			}
			if err := check(join(path, key), m[key]); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *modelChecker) emptyObject(path string, v any) error {
	if m, ok := v.(map[string]any); !ok || len(m) != 0 {
		return modelViolation(path, "must be an empty mapping")
	}
	return nil
}

func (c *modelChecker) mapOf(value modelCheck) modelCheck {
	return c.mapByKey(func(string) modelCheck { return value })
}

// mapByKey checks each entry with the check chosen for its key.
func (c *modelChecker) mapByKey(valueFor func(key string) modelCheck) modelCheck {
	return func(path string, v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return modelViolation(path, "must be a mapping")
		}
		for _, key := range slices.Sorted(maps.Keys(m)) {
			if err := valueFor(key)(join(path, key), m[key]); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *modelChecker) listOf(item modelCheck) modelCheck {
	return func(path string, v any) error {
		list, ok := v.([]any)
		if !ok {
			return modelViolation(path, "must be a list")
		}
		for i, element := range list {
			if err := item(fmt.Sprintf("%s[%d]", path, i), element); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *modelChecker) nullable(inner modelCheck) modelCheck {
	return func(path string, v any) error {
		if v == nil {
			return nil
		}
		return inner(path, v)
	}
}

func (c *modelChecker) oneOf(allowed ...string) modelCheck {
	return func(path string, v any) error {
		if s, ok := v.(string); ok && slices.Contains(allowed, s) {
			return nil
		}
		return modelViolation(path, "must be one of %s", strings.Join(allowed, ", "))
	}
}

func (c *modelChecker) str(path string, v any) error {
	if _, ok := v.(string); !ok {
		return modelViolation(path, "must be a string")
	}
	return nil
}

func (c *modelChecker) boolean(path string, v any) error {
	if _, ok := v.(bool); !ok {
		return modelViolation(path, "must be a boolean")
	}
	return nil
}

func (c *modelChecker) absolutePath(path string, v any) error {
	if s, ok := v.(string); !ok || !strings.HasPrefix(s, "/") {
		return modelViolation(path, "must be an absolute path")
	}
	return nil
}

// integer accepts a JSON integer or the decimal string the loader renders
// for byte-valued and port fields.
func (c *modelChecker) integer(path string, v any) error {
	if _, ok := integerValue(v); !ok {
		return modelViolation(path, "must be an integer")
	}
	return nil
}

func (c *modelChecker) numeric(path string, v any) error {
	var text string
	switch n := v.(type) {
	case json.Number:
		text = n.String()
	case string:
		text = n
	}
	if _, err := strconv.ParseFloat(text, 64); err != nil {
		return modelViolation(path, "must be a number")
	}
	return nil
}

func integerValue(v any) (int64, bool) {
	var text string
	switch n := v.(type) {
	case json.Number:
		text = n.String()
	case string:
		text = n
	default:
		return 0, false
	}
	i, err := strconv.ParseInt(text, 10, 64)
	return i, err == nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// ---- service keys ----

func (c *modelChecker) labelMap(path string, v any) error {
	return c.mapOf(c.str)(path, v)
}

func (c *modelChecker) serviceLabels(path string, v any) error {
	if err := c.labelMap(path, v); err != nil {
		return err
	}
	for _, key := range slices.Sorted(maps.Keys(v.(map[string]any))) {
		if strings.HasPrefix(key, "com.docker.") || strings.HasPrefix(key, "dev.supermgmt.") {
			return modelViolation(join(path, key), "label namespace is reserved")
		}
	}
	return nil
}

func (c *modelChecker) healthcheck(path string, v any) error {
	return c.object(map[string]modelCheck{
		"test":           c.listOf(c.str),
		"interval":       c.str,
		"timeout":        c.str,
		"retries":        c.integer,
		"start_period":   c.str,
		"start_interval": c.str,
		"disable":        c.boolean,
	})(path, v)
}

func (c *modelChecker) dependency(service string) modelCheck {
	shape := c.object(map[string]modelCheck{
		"condition": c.oneOf("service_started", "service_healthy", "service_completed_successfully"),
		"required":  c.mustBeTrue,
	})
	return func(path string, v any) error {
		if !c.services[service] {
			return modelViolation(path, "depends on an undefined service")
		}
		return shape(path, v)
	}
}

// mustBeTrue admits the loader's default for depends_on.required; `false`
// would let a service start without its dependency.
func (c *modelChecker) mustBeTrue(path string, v any) error {
	if v != true {
		return modelViolation(path, "must be true")
	}
	return nil
}

func (c *modelChecker) serviceNetworks(path string, v any) error {
	attachment := c.nullable(c.object(map[string]modelCheck{"aliases": c.listOf(c.str)}))
	return c.mapByKey(func(network string) modelCheck {
		return func(path string, v any) error {
			if !c.networks[network] {
				return modelViolation(path, "network is not declared at the top level")
			}
			return attachment(path, v)
		}
	})(path, v)
}

func (c *modelChecker) logging(path string, v any) error {
	return c.object(map[string]modelCheck{
		"driver": c.oneOf("json-file", "local"),
		"options": c.object(map[string]modelCheck{
			"max-size": c.str, "max-file": c.scalarText, "compress": c.scalarText,
		}),
	})(path, v)
}

// scalarText accepts an option value written as a string, number or boolean.
func (c *modelChecker) scalarText(path string, v any) error {
	switch v.(type) {
	case string, json.Number, bool:
		return nil
	}
	return modelViolation(path, "must be a string, number or boolean")
}

func (c *modelChecker) ulimits(path string, v any) error {
	limit := c.object(map[string]modelCheck{"soft": c.integer, "hard": c.integer})
	return c.object(map[string]modelCheck{"nofile": limit, "nproc": limit})(path, v)
}

func (c *modelChecker) deploy(path string, v any) error {
	limits := c.object(map[string]modelCheck{"cpus": c.numeric, "memory": c.numeric, "pids": c.integer})
	return c.object(map[string]modelCheck{
		"resources": c.object(map[string]modelCheck{"limits": limits}),
		"placement": c.emptyObject, // loader default
	})(path, v)
}

// ---- ports and volumes ----

func (c *modelChecker) port(path string, v any) error {
	if err := c.object(map[string]modelCheck{
		"target": c.integer, "published": c.integer,
		"host_ip": c.str, "protocol": c.oneOf("tcp", "udp"),
		"mode": c.oneOf("ingress"), // loader default; `host` mode is not allowlisted
	})(path, v); err != nil {
		return err
	}
	m := v.(map[string]any)
	for _, required := range []string{"target", "published", "host_ip"} {
		if _, ok := m[required]; !ok {
			return modelViolation(join(path, required), "is required")
		}
	}
	return c.checkPublishedAddress(join(path, "host_ip"), m["host_ip"].(string))
}

func (c *modelChecker) checkPublishedAddress(path, text string) error {
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return modelViolation(path, "must be an IP address")
	}
	if addr == netip.MustParseAddr("127.0.0.1") || addr == netip.MustParseAddr("::1") {
		return nil
	}
	if slices.Contains(c.target.AllowedBind, addr) {
		return nil
	}
	return modelViolation(path, "%s is neither loopback nor an allowed bind address of the target", addr)
}

func (c *modelChecker) volumeMount(path string, v any) error {
	if err := c.object(map[string]modelCheck{
		"type":      c.oneOf("volume", "tmpfs"),
		"source":    c.str,
		"target":    c.absolutePath,
		"read_only": c.boolean,
		"volume":    c.object(map[string]modelCheck{"nocopy": c.boolean}),
		"tmpfs":     c.object(map[string]modelCheck{"size": c.numeric, "mode": c.integer}),
	})(path, v); err != nil {
		return err
	}
	m := v.(map[string]any)
	for _, required := range []string{"type", "target"} {
		if _, ok := m[required]; !ok {
			return modelViolation(join(path, required), "is required")
		}
	}
	if m["type"] == "tmpfs" {
		return c.tmpfsMount(path, m)
	}
	return c.namedVolumeMount(path, m)
}

func (c *modelChecker) namedVolumeMount(path string, m map[string]any) error {
	if _, ok := m["tmpfs"]; ok {
		return modelViolation(join(path, "tmpfs"), "is only valid for type tmpfs")
	}
	source, _ := m["source"].(string)
	if !c.volumes[source] {
		return modelViolation(join(path, "source"), "must name a top-level volume")
	}
	return nil
}

func (c *modelChecker) tmpfsMount(path string, m map[string]any) error {
	for _, key := range []string{"source", "volume"} {
		if _, ok := m[key]; ok {
			return modelViolation(join(path, key), "is not valid for type tmpfs")
		}
	}
	return nil
}
