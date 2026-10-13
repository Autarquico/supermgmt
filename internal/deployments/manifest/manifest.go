package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/health"
)

// MaxBytes bounds a manifest read from a repository.
const MaxBytes = 64 << 10

// Health defaults and bounds applied to a manifest hint.
const (
	defaultHealthTimeout  = 3 * time.Second
	defaultHealthInterval = 5 * time.Second
	defaultHealthAttempts = 12

	maxHealthTimeout  = 30 * time.Second
	maxHealthInterval = time.Minute
	maxHealthAttempts = 60
	maxHealthPathLen  = 256
)

// Rollback modes (spec §19).
const (
	rollbackAutomatic = "automatic"
	rollbackManual    = "manual"
)

// controlPlaneOnly are keys the manifest may never carry (spec §19): they live
// in the apps/app_targets configuration.
var controlPlaneOnly = map[string]bool{
	"image": true, "images": true, "targets": true, "target": true, "node": true, "nodes": true,
	"environment": true, "environments": true, "secrets": true, "secret": true,
	"variables": true, "exceptions": true, "ci": true, "stateful": true,
	"backup": true, "pre_deploy_backup": true, "preDeployBackup": true, "snapshot": true,
}

// Parse reads a strict V1 manifest. Unknown fields, control-plane-only fields,
// aliases and extra documents fail with INVALID_ARGUMENT. Health timing
// defaults are applied.
func Parse(data []byte) (Manifest, error) {
	if len(data) > MaxBytes {
		return Manifest{}, invalid("manifest exceeds %d bytes", MaxBytes)
	}
	if err := checkTree(data); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, invalid("manifest: %v", err)
	}
	if err := m.validate(); err != nil {
		return Manifest{}, err
	}
	m.applyHealthDefaults()
	return m, nil
}

// checkTree rejects what strict decoding cannot name well: extra documents,
// aliases/anchors and control-plane-only keys.
func checkTree(data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		return invalid("manifest: %v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return invalid("manifest must be a single YAML document")
	}
	return walk(&root)
}

func walk(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return invalid("manifest: anchors and aliases are not allowed (line %d)", n.Line)
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if key := n.Content[i].Value; controlPlaneOnly[key] {
				return invalid("manifest: field %q is set by the control plane and not allowed here (line %d)", key, n.Content[i].Line)
			}
		}
	}
	for _, c := range n.Content {
		if err := walk(c); err != nil {
			return err
		}
	}
	return nil
}

func (m Manifest) validate() error {
	if m.APIVersion != APIVersion {
		return invalid("manifest: apiVersion must be %q", APIVersion)
	}
	if m.Kind != Kind {
		return invalid("manifest: kind must be %q", Kind)
	}
	if strings.TrimSpace(m.Metadata.Name) == "" {
		return invalid("manifest: metadata.name is required")
	}
	if s := m.Spec.Deployment.Strategy; s != "" && s != StrategyCompose {
		return invalid("manifest: spec.deployment.strategy must be %q", StrategyCompose)
	}
	if r := m.Spec.Rollback; r != nil && !validRollbackMode(r.Mode) {
		return invalid("manifest: spec.rollback.mode must be automatic or manual")
	}
	if h := m.Spec.Health; h != nil {
		return h.validate()
	}
	return nil
}

func (m *Manifest) applyHealthDefaults() {
	h := m.Spec.Health
	if h == nil {
		return
	}
	if h.Timeout == 0 {
		h.Timeout = defaultHealthTimeout
	}
	if h.Interval == 0 {
		h.Interval = defaultHealthInterval
	}
	if h.Attempts == 0 {
		h.Attempts = defaultHealthAttempts
	}
}

func (h ManifestHealth) validate() error {
	switch h.Type {
	case health.TypeHTTP:
		if err := h.requirePort(); err != nil {
			return err
		}
		if err := validatePath(h.Path); err != nil {
			return err
		}
	case health.TypeTCP:
		if err := h.requirePort(); err != nil {
			return err
		}
		if h.Path != "" {
			return invalid("manifest: spec.health.path applies to http only")
		}
	case health.TypeDockerHealth:
		if h.Port != 0 || h.Path != "" {
			return invalid("manifest: spec.health port and path do not apply to docker-health")
		}
	default:
		return invalid("manifest: spec.health.type must be http, tcp or docker-health")
	}
	return h.validateTiming()
}

func (h ManifestHealth) requirePort() error {
	if h.Port == 0 {
		return invalid("manifest: spec.health.port is required for %s", h.Type)
	}
	return nil
}

func (h ManifestHealth) validateTiming() error {
	if h.Timeout < 0 || h.Timeout > maxHealthTimeout {
		return invalid("manifest: spec.health.timeout must be within (0, %s]", maxHealthTimeout)
	}
	if h.Interval < 0 || h.Interval > maxHealthInterval {
		return invalid("manifest: spec.health.interval must be within (0, %s]", maxHealthInterval)
	}
	if h.Attempts < 0 || h.Attempts > maxHealthAttempts {
		return invalid("manifest: spec.health.attempts must be within [1, %d]", maxHealthAttempts)
	}
	return nil
}

// validatePath accepts an absolute URL path only: no scheme, host, query,
// fragment, whitespace, control or non-ASCII characters.
func validatePath(p string) error {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || len(p) > maxHealthPathLen {
		return invalid("manifest: spec.health.path must be an absolute path starting with a single '/'")
	}
	for _, r := range p {
		if r <= ' ' || r >= 0x7f || r == '?' || r == '#' || r == '\\' {
			return invalid("manifest: spec.health.path contains a forbidden character")
		}
	}
	return nil
}

func validRollbackMode(mode string) bool {
	return mode == rollbackAutomatic || mode == rollbackManual
}

func invalid(format string, args ...any) error {
	return smerr.New(smerr.CodeInvalidArgument, "", fmt.Sprintf(format, args...))
}
