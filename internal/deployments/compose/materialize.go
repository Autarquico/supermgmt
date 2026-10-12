package compose

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

var (
	materializeServiceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	materializeEnvName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type materializeKey struct {
	ref     string
	version int64
}

// Materialize turns the frozen public model into the files staging writes on
// the node (spec §20.3 step 9, ADR-0010): the public model plus the
// per-deployment label on every service, and for each service with secrets an
// `env_file` entry (format raw, required) pointing at secrets/<service>.env,
// whose NAME=value lines carry the decrypted values verbatim.
//
// Only services carry the deployment label: volumes and networks outlive
// deployments, and a label that changes on every deploy would make Compose
// reject the existing volume.
func Materialize(f Frozen, deployment domain.ID, values []ResolvedSecret) (Bundle, error) {
	if _, err := domain.ParseID(deployment.String()); err != nil {
		return Bundle{}, materializeFailure("deployment id is invalid")
	}
	doc, services, err := materializeParse(f.Public)
	if err != nil {
		return Bundle{}, err
	}
	contents, err := materializeEnvFiles(f.Secrets, values)
	if err != nil {
		return Bundle{}, err
	}
	for _, name := range materializeSortedKeys(contents) {
		if materializeMapValue(services, name) == nil {
			return Bundle{}, materializeFailure(fmt.Sprintf("secret bound to unknown service %q", name))
		}
	}
	files := make(map[string]audit.Secret, len(contents))
	for i := 0; i+1 < len(services.Content); i += 2 {
		name, svc := services.Content[i].Value, services.Content[i+1]
		if err := materializeLabel(svc, name, deployment); err != nil {
			return Bundle{}, err
		}
		content, ok := contents[name]
		if !ok {
			continue
		}
		if err := materializeWireEnvFile(svc, name, f.Secrets); err != nil {
			return Bundle{}, err
		}
		files[materializeEnvPath(name)] = audit.Secret(content)
	}
	out, err := materializeEncode(doc)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{ComposeYAML: out, EnvFiles: files}, nil
}

func materializeEnvPath(service string) string { return "secrets/" + service + ".env" }

// materializeEnvFiles renders the secrets/<service>.env contents per service.
func materializeEnvFiles(uses []SecretUse, values []ResolvedSecret) (map[string]string, error) {
	byKey := make(map[materializeKey]audit.Secret, len(values))
	for _, v := range values {
		byKey[materializeKey{v.Ref, v.Version}] = v.Value
	}
	perService := map[string][]SecretUse{}
	for _, u := range uses {
		perService[u.Service] = append(perService[u.Service], u)
	}
	files := make(map[string]string, len(perService))
	for service, group := range perService {
		content, err := materializeEnvContent(service, group, byKey)
		if err != nil {
			return nil, err
		}
		files[service] = content
	}
	return files, nil
}

func materializeEnvContent(service string, uses []SecretUse, byKey map[materializeKey]audit.Secret) (string, error) {
	if !materializeServiceName.MatchString(service) {
		return "", materializeFailure(fmt.Sprintf("service name %q is not a safe file name", service))
	}
	sort.Slice(uses, func(i, j int) bool { return uses[i].EnvName < uses[j].EnvName })
	var b strings.Builder
	for i, u := range uses {
		if !materializeEnvName.MatchString(u.EnvName) {
			return "", materializeFailure(fmt.Sprintf("environment name %q of service %q is invalid", u.EnvName, service))
		}
		if i > 0 && uses[i-1].EnvName == u.EnvName {
			return "", materializeFailure(fmt.Sprintf("service %q binds %s twice", service, u.EnvName))
		}
		value, ok := byKey[materializeKey{u.Ref, u.Version}]
		if !ok {
			return "", materializeFailure(fmt.Sprintf("no resolved value for %s of service %q (%s v%d)", u.EnvName, service, u.Ref, u.Version))
		}
		plain := value.Reveal()
		if !materializeEnvSafe(plain) {
			return "", materializeFailure(fmt.Sprintf("value of %s for service %q cannot be written to a raw env file", u.EnvName, service))
		}
		b.WriteString(u.EnvName + "=" + plain + "\n")
	}
	return b.String(), nil
}

// materializeEnvSafe mirrors the secret.write rule for apps/ (ADR-0010).
func materializeEnvSafe(v string) bool {
	return utf8.ValidString(v) && !strings.ContainsAny(v, "\x00\r\n")
}

func materializeParse(public []byte) (doc, services *yaml.Node, err error) {
	doc = &yaml.Node{}
	if err := yaml.Unmarshal(public, doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, materializeFailure("public model is not a YAML mapping")
	}
	services = materializeMapValue(doc.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, nil, materializeFailure("public model has no services")
	}
	return doc, services, nil
}

func materializeLabel(svc *yaml.Node, service string, deployment domain.ID) error {
	labels := materializeMapValue(svc, "labels")
	if labels == nil {
		labels = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		materializeMapSet(svc, "labels", labels)
	}
	if labels.Kind != yaml.MappingNode {
		return materializeFailure(fmt.Sprintf("service %q labels are not a map", service))
	}
	if materializeMapValue(labels, LabelDeployment) != nil {
		return materializeFailure(fmt.Sprintf("service %q already carries %s", service, LabelDeployment))
	}
	materializeMapSet(labels, LabelDeployment, materializeString(deployment.String()))
	materializeSortMapping(labels)
	materializeSortMapping(svc)
	return nil
}

func materializeWireEnvFile(svc *yaml.Node, service string, uses []SecretUse) error {
	if materializeMapValue(svc, "env_file") != nil {
		return materializeFailure(fmt.Sprintf("service %q already has env_file", service))
	}
	if name := materializeShadowed(svc, service, uses); name != "" {
		return materializeFailure(fmt.Sprintf("service %q sets %s both in environment and as a secret", service, name))
	}
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	materializeMapSet(entry, "path", materializeString(materializeEnvPath(service)))
	materializeMapSet(entry, "format", materializeString("raw"))
	materializeMapSet(entry, "required", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	materializeSortMapping(entry)
	materializeMapSet(svc, "env_file", &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{entry}})
	materializeSortMapping(svc)
	return nil
}

// materializeShadowed returns a secret env name that the public environment
// also sets: Compose lets the environment win, so the secret would never reach
// the container. It is refused instead of silently dropped.
func materializeShadowed(svc *yaml.Node, service string, uses []SecretUse) string {
	env := materializeMapValue(svc, "environment")
	if env == nil || env.Kind != yaml.MappingNode {
		return ""
	}
	for _, u := range uses {
		if u.Service == service && materializeMapValue(env, u.EnvName) != nil {
			return u.EnvName
		}
	}
	return ""
}

func materializeEncode(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, materializeFailure("cannot encode materialized model")
	}
	if err := enc.Close(); err != nil {
		return nil, materializeFailure("cannot encode materialized model")
	}
	return buf.Bytes(), nil
}

func materializeFailure(msg string) error {
	return smerr.FromReason(smerr.ReasonStagingFailed, "materialize: "+msg)
}

func materializeString(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

func materializeMapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func materializeMapSet(m *yaml.Node, key string, value *yaml.Node) {
	m.Content = append(m.Content, materializeString(key), value)
}

func materializeSortMapping(m *yaml.Node) {
	pairs := make([][2]*yaml.Node, 0, len(m.Content)/2)
	for i := 0; i+1 < len(m.Content); i += 2 {
		pairs = append(pairs, [2]*yaml.Node{m.Content[i], m.Content[i+1]})
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i][0].Value < pairs[j][0].Value })
	m.Content = m.Content[:0]
	for _, p := range pairs {
		m.Content = append(m.Content, p[0], p[1])
	}
}

func materializeSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
