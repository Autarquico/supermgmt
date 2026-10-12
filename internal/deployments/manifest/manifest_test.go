package manifest

import (
	"strings"
	"testing"
	"time"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

const validManifest = `apiVersion: supermgmt.dev/v1
kind: Application
metadata:
  name: myapp
spec:
  deployment:
    strategy: docker-compose
    composeFile: compose.yaml
    service: web
  health:
    type: http
    port: 8080
    path: /health
    timeout: 3s
    interval: 5s
    attempts: 12
  rollback:
    mode: automatic
`

func TestParse_SpecExample(t *testing.T) {
	m, err := Parse([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	h := m.Spec.Health
	if m.Metadata.Name != "myapp" || m.Spec.Deployment.Service != "web" || m.Spec.Deployment.ComposeFile != "compose.yaml" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	if h.Type != "http" || h.Port != 8080 || h.Path != "/health" || h.Timeout != 3*time.Second ||
		h.Interval != 5*time.Second || h.Attempts != 12 {
		t.Fatalf("unexpected health: %+v", h)
	}
	if m.Spec.Rollback.Mode != "automatic" {
		t.Fatalf("rollback = %q", m.Spec.Rollback.Mode)
	}
}

func TestParse_MinimalManifestAndHealthDefaults(t *testing.T) {
	m, err := Parse([]byte(header + "  health:\n    type: tcp\n    port: 5432\n"))
	if err != nil {
		t.Fatal(err)
	}
	h := m.Spec.Health
	if h.Timeout != 3*time.Second || h.Interval != 5*time.Second || h.Attempts != 12 {
		t.Fatalf("defaults not applied: %+v", h)
	}
	if _, err := Parse([]byte(header + "  deployment: {}\n")); err != nil {
		t.Fatalf("manifest without health: %v", err)
	}
}

const header = `apiVersion: supermgmt.dev/v1
kind: Application
metadata:
  name: myapp
spec:
`

func TestManifest_RejectsControlPlaneFields(t *testing.T) {
	for _, field := range []string{
		"image: ghcr.io/o/r", "targets: [prod]", "secrets: {A: b}", "variables: {A: b}",
		"exceptions: {}", "ci: {}", "stateful: true", "backup: {}",
	} {
		t.Run(strings.Fields(field)[0], func(t *testing.T) {
			for name, doc := range map[string]string{
				"spec":       header + "  " + field + "\n",
				"deployment": header + "  deployment:\n    " + field + "\n",
				"health":     header + "  health:\n    type: tcp\n    port: 1\n    " + field + "\n",
			} {
				_, err := Parse([]byte(doc))
				requireInvalid(t, name, err)
				if !strings.Contains(err.Error(), "control plane") {
					t.Fatalf("%s: error should explain the field is control-plane only: %v", name, err)
				}
			}
		})
	}
}

func TestManifest_RejectsHealthURLAndHost(t *testing.T) {
	for name, health := range map[string]string{
		"url field":    "type: http\n    port: 80\n    path: /h\n    url: http://evil/h",
		"host field":   "type: http\n    port: 80\n    path: /h\n    host: 10.0.0.1",
		"url as path":  "type: http\n    port: 80\n    path: http://evil/h",
		"scheme-relat": "type: http\n    port: 80\n    path: //evil/h",
		"query":        "type: http\n    port: 80\n    path: /h?x=1",
		"fragment":     "type: http\n    port: 80\n    path: /h#x",
		"space":        "type: http\n    port: 80\n    path: '/h x'",
		"newline":      "type: http\n    port: 80\n    path: \"/h\\nHost: x\"",
		"backslash":    "type: http\n    port: 80\n    path: '/h\\x'",
		"non-ascii":    "type: http\n    port: 80\n    path: /há",
		"relative":     "type: http\n    port: 80\n    path: health",
		"no path":      "type: http\n    port: 80",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(header + "  health:\n    " + health + "\n"))
			requireInvalid(t, name, err)
		})
	}
}

func TestManifest_RejectsInvalidShapes(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":                 "",
		"unknown top-level":     validManifest + "extra: 1\n",
		"unknown spec field":    header + "  surprise: 1\n",
		"wrong apiVersion":      strings.Replace(validManifest, "supermgmt.dev/v1", "supermgmt.dev/v2", 1),
		"wrong kind":            strings.Replace(validManifest, "kind: Application", "kind: Other", 1),
		"missing name":          strings.Replace(validManifest, "name: myapp", "name: ''", 1),
		"bad strategy":          strings.Replace(validManifest, "docker-compose", "shell", 1),
		"bad rollback mode":     strings.Replace(validManifest, "mode: automatic", "mode: always", 1),
		"bad health type":       header + "  health:\n    type: command-template\n",
		"http without port":     header + "  health:\n    type: http\n    path: /h\n",
		"tcp with path":         header + "  health:\n    type: tcp\n    port: 1\n    path: /h\n",
		"docker-health port":    header + "  health:\n    type: docker-health\n    port: 1\n",
		"timeout too long":      header + "  health:\n    type: tcp\n    port: 1\n    timeout: 5m\n",
		"negative timeout":      header + "  health:\n    type: tcp\n    port: 1\n    timeout: -1s\n",
		"interval too long":     header + "  health:\n    type: tcp\n    port: 1\n    interval: 1h\n",
		"too many attempts":     header + "  health:\n    type: tcp\n    port: 1\n    attempts: 1000\n",
		"two documents":         validManifest + "---\n" + validManifest,
		"anchor":                header + "  health: &h\n    type: tcp\n    port: 1\n",
		"alias":                 header + "  deployment: &d {service: web}\n  rollback: *d\n",
		"port out of range":     header + "  health:\n    type: tcp\n    port: 70000\n",
		"oversized":             validManifest + "# " + strings.Repeat("x", MaxBytes) + "\n",
		"invalid yaml":          "a: [",
		"not a mapping":         "- a\n- b\n",
		"health type not given": header + "  health:\n    port: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(doc))
			requireInvalid(t, name, err)
		})
	}
}

func TestParse_AcceptsDockerHealth(t *testing.T) {
	if _, err := Parse([]byte(header + "  health:\n    type: docker-health\n")); err != nil {
		t.Fatal(err)
	}
}

func requireInvalid(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error", name)
	}
	if smerr.CodeOf(err) != smerr.CodeInvalidArgument {
		t.Fatalf("%s: code = %s, want INVALID_ARGUMENT (%v)", name, smerr.CodeOf(err), err)
	}
}
