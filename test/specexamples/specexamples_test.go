// Package specexamples checks that every YAML example in the master spec
// (§8.2, §8.2.1, §8.3, §11.2, §11.6) and in examples/ is accepted by the
// code that is supposed to read it. The blocks are extracted from the spec
// at test time, so editing the spec cannot silently invalidate an example.
package specexamples

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/config"
	"github.com/autarquico/supermgmt/internal/deployments/manifest"
	"github.com/autarquico/supermgmt/internal/policy"
)

const (
	localDoc  = "version: 1\ninstance:\n  mode: local\n"
	serverDoc = "version: 1\ninstance:\n  mode: server\n"
)

const (
	appManifestExample = "app.supermgmt.yaml"
	actionsExample     = "github-actions.yml"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// specYAMLBlocks returns the ```yaml blocks found under the spec heading that
// starts with "## <section> ".
func specYAMLBlocks(t *testing.T, section string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "spec", "SUPERMGMT-SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	var (
		blocks  []string
		current []string
		inHead  bool
		inBlock bool
	)
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case inBlock && strings.HasPrefix(line, "```"):
			blocks = append(blocks, strings.Join(current, "\n")+"\n")
			current, inBlock = nil, false
		case inBlock:
			current = append(current, line)
		case strings.HasPrefix(line, "## "):
			inHead = strings.HasPrefix(line, "## "+section+" ")
		case inHead && strings.HasPrefix(line, "```yaml"):
			inBlock = true
		}
	}
	return blocks
}

func exactlyBlocks(t *testing.T, section string, want int) []string {
	t.Helper()
	blocks := specYAMLBlocks(t, section)
	if len(blocks) != want {
		t.Fatalf("spec §%s: found %d YAML blocks, want %d (heading renamed or block moved?)", section, len(blocks), want)
	}
	return blocks
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadConfig(t *testing.T, content string) error {
	t.Helper()
	_, err := config.Load(writeTemp(t, content), []string{"HOME=" + t.TempDir()})
	return err
}

// asProviderList indents a provider mapping into a one-item `providers:` list.
func asProviderList(block string) string {
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	for i, l := range lines {
		prefix := "    "
		if i == 0 {
			prefix = "  - "
		}
		lines[i] = prefix + l
	}
	return "providers:\n" + strings.Join(lines, "\n") + "\n"
}

// providerConfig wraps a §8.3 provider example in a config whose mode allows it.
func providerConfig(block string) string {
	mode := serverDoc
	if strings.Contains(block, "ssh-agent://") {
		mode = localDoc
	}
	return mode + asProviderList(block)
}

func TestConfigExamplesValidate_SpecMasterConfigExample(t *testing.T) {
	for _, block := range exactlyBlocks(t, "8.2", 1) {
		if err := loadConfig(t, block); err != nil {
			t.Errorf("§8.2 example does not validate: %v", err)
		}
	}
}

func TestConfigExamplesValidate_SpecEnvironmentExample(t *testing.T) {
	for _, block := range exactlyBlocks(t, "8.2.1", 1) {
		if err := loadConfig(t, localDoc+block); err != nil {
			t.Errorf("§8.2.1 example does not validate: %v", err)
		}
	}
}

func TestConfigExamplesValidate_SpecProviderExamples(t *testing.T) {
	for i, block := range exactlyBlocks(t, "8.3", 4) {
		if err := loadConfig(t, providerConfig(block)); err != nil {
			t.Errorf("§8.3 example %d does not validate: %v\n%s", i+1, err, block)
		}
	}
}

func TestPolicyExamplesValidate_SpecDefaultPolicyIsTheBuiltInPolicy(t *testing.T) {
	blocks := exactlyBlocks(t, "11.2", 1)
	fromSpec, err := policy.Parse([]byte(blocks[0]))
	if err != nil {
		t.Fatalf("§11.2 example does not validate: %v", err)
	}
	builtIn, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromSpec.Rules(), builtIn.Rules()) {
		t.Error("the §11.2 default policy differs from the embedded built-in policy")
	}
}

func TestPolicyExamplesValidate_SpecUserPolicyExample(t *testing.T) {
	for _, block := range exactlyBlocks(t, "11.6", 1) {
		if _, err := policy.Parse([]byte(block)); err != nil {
			t.Errorf("§11.6 example does not validate: %v", err)
		}
	}
}

func TestExamplesDirectoryValidates(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "examples", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples/*.yaml found (err %v)", err)
	}
	for _, file := range files {
		if filepath.Base(file) == appManifestExample {
			continue // a repository manifest, checked by TestSpecExamples_AppManifestParses
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			if strings.HasPrefix(filepath.Base(file), "policies") {
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := policy.Parse(raw); err != nil {
					t.Fatalf("does not validate: %v", err)
				}
				return
			}
			if _, err := config.Load(file, []string{"HOME=" + t.TempDir()}); err != nil {
				t.Fatalf("does not validate: %v", err)
			}
		})
	}
}

func TestUnknownFieldInjectedIntoAnExampleFailsWithItsYAMLPath(t *testing.T) {
	t.Run("config_top_level", func(t *testing.T) {
		block := exactlyBlocks(t, "8.2", 1)[0]
		assertErrorMentions(t, loadConfig(t, block+"bogus_key: 1\n"), "bogus_key")
	})
	t.Run("config_nested", func(t *testing.T) {
		block := exactlyBlocks(t, "8.2", 1)[0]
		injected := strings.Replace(block, "\ninstance:\n", "\ninstance:\n  bogus_field: 1\n", 1)
		if injected == block {
			t.Fatal("§8.2 example has no instance: section to inject into")
		}
		assertErrorMentions(t, loadConfig(t, injected), "instance.bogus_field")
	})
	t.Run("config_provider_list_item", func(t *testing.T) {
		block := exactlyBlocks(t, "8.3", 4)[0]
		assertErrorMentions(t, loadConfig(t, providerConfig(block+"bogus_field: 1\n")), "providers[0].bogus_field")
	})
	t.Run("policy_rule", func(t *testing.T) {
		block := exactlyBlocks(t, "11.6", 1)[0]
		injected := strings.Replace(block, "  - name: mcp-read\n", "  - name: mcp-read\n    bogus_field: 1\n", 1)
		if injected == block {
			t.Fatal("§11.6 example has no mcp-read rule to inject into")
		}
		_, err := policy.Parse([]byte(injected))
		assertErrorMentions(t, err, "bogus_field")
	})
}

func assertErrorMentions(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("an unknown field %q was accepted", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error does not name %q: %v", want, err)
	}
}

func readExample(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "examples", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSpecExamples_AppManifestParses(t *testing.T) {
	m, err := manifest.Parse(readExample(t, appManifestExample))
	if err != nil {
		t.Fatalf("examples/%s does not validate: %v", appManifestExample, err)
	}
	if m.Spec.Deployment.Strategy != manifest.StrategyCompose {
		t.Errorf("strategy = %q, want %q", m.Spec.Deployment.Strategy, manifest.StrategyCompose)
	}
}

func TestSpecExamples_AppManifestRejectsControlPlaneFields(t *testing.T) {
	raw := string(readExample(t, appManifestExample)) + "  stateful: true\n"
	if _, err := manifest.Parse([]byte(raw)); err == nil {
		t.Fatal("a manifest carrying control-plane-only fields was accepted")
	}
}

type actionsWorkflow struct {
	On          map[string]any `yaml:"on"`
	Permissions map[string]string
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Uses string `yaml:"uses"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

var pinnedAction = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)

// idTokenJobs are the only jobs of the example that may hold id-token: write
// (spec §28): build signs the attestation, deploy asks for the OIDC token.
var idTokenJobs = []string{"build", "deploy"}

func TestSpecExamples_GitHubActionsPermissions(t *testing.T) {
	var wf actionsWorkflow
	if err := yaml.Unmarshal(readExample(t, actionsExample), &wf); err != nil {
		t.Fatalf("examples/%s is not valid YAML: %v", actionsExample, err)
	}
	if want := (map[string]string{"contents": "read"}); !reflect.DeepEqual(wf.Permissions, want) {
		t.Errorf("workflow permissions = %v, want %v", wf.Permissions, want)
	}
	for _, trigger := range []string{"pull_request", "pull_request_target"} {
		if _, found := wf.On[trigger]; found {
			t.Errorf("trigger %s can never obtain deployment authority", trigger)
		}
	}
	for _, name := range idTokenJobs {
		if wf.Jobs[name].Permissions["id-token"] != "write" {
			t.Errorf("job %s must hold id-token: write", name)
		}
	}
	for name, job := range wf.Jobs {
		if _, holds := job.Permissions["id-token"]; holds && !slices.Contains(idTokenJobs, name) {
			t.Errorf("job %s holds id-token but only %v need it", name, idTokenJobs)
		}
		for _, s := range job.Steps {
			if s.Uses != "" && !pinnedAction.MatchString(s.Uses) {
				t.Errorf("job %s: %q is not pinned to a commit SHA", name, s.Uses)
			}
		}
	}
}
