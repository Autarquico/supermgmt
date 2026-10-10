// Package install_test holds the release and installer checks that are not shell tests:
// the workflow policy that keeps the release signing key out of reach of ordinary CI (ADR-0019).
package install_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const signingSecret = "SM_RELEASE_SIGNING_KEY"

// releaseWorkflows are the only files allowed to use the release environment, with the write
// permissions each one may hold and the triggers it may have.
var releaseWorkflows = map[string]struct {
	writes   map[string]bool
	triggers map[string]bool
}{
	"release.yml":  {writes: set("contents", "id-token", "attestations"), triggers: set("push")},
	"channels.yml": {writes: set("contents"), triggers: set("schedule", "workflow_dispatch")},
}

// unpinnedDebt lists existing workflows that still use tag-pinned actions. Not owned by the
// release pipeline; remove the entry when the file is pinned.
var unpinnedDebt = set("pm-policy.yml")

// releaseScopes are the permission scopes that can publish or attest artifacts; write on them is
// reserved for the release workflows.
var releaseScopes = set("contents", "id-token", "attestations")

var (
	shaPin     = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	digestPin  = regexp.MustCompile(`^docker://.+@sha256:[0-9a-f]{64}$`)
	expression = "${{"
)

type workflow struct {
	On          any            `yaml:"on"`
	Permissions any            `yaml:"permissions"`
	Jobs        map[string]job `yaml:"jobs"`
}

type job struct {
	Environment any    `yaml:"environment"`
	Permissions any    `yaml:"permissions"`
	Steps       []step `yaml:"steps"`
}

type step struct {
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

func set(items ...string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

// violations returns one sentence per policy breach across the given workflow files.
func violations(files map[string]string) []string {
	var out []string
	for _, name := range sortedKeys(files) {
		out = append(out, fileViolations(name, files[name])...)
	}
	return out
}

func fileViolations(name, source string) []string {
	var wf workflow
	if err := yaml.Unmarshal([]byte(source), &wf); err != nil {
		return []string{fmt.Sprintf("%s: not valid YAML: %v", name, err)}
	}
	allowed, isRelease := releaseWorkflows[name]
	triggers := triggersOf(wf.On)
	var out []string
	report := func(format string, args ...any) { out = append(out, name+": "+fmt.Sprintf(format, args...)) }

	if _, ok := triggers["pull_request_target"]; ok {
		report("pull_request_target is not allowed")
	}
	if wf.Permissions == nil {
		report("top-level permissions are required")
	}
	if !isRelease && strings.Contains(source, signingSecret) {
		report("%s is referenced outside the release workflows", signingSecret)
	}
	if isRelease {
		for trigger := range triggers {
			if !allowed.triggers[trigger] {
				report("trigger %q is not allowed", trigger)
			}
		}
		if triggers["push"] != nil && !pushesOnlyTags(triggers["push"]) {
			report("push must be limited to tags")
		}
	}

	for _, scope := range permissionScopes(wf) {
		out = append(out, permissionViolations(name, scope.where, scope.value, allowed.writes, isRelease)...)
	}
	for _, jobName := range sortedKeys(wf.Jobs) {
		j := wf.Jobs[jobName]
		usesRelease := environmentName(j.Environment) == "release"
		if usesRelease && !isRelease {
			report("job %s uses the release environment", jobName)
		}
		if isRelease && usesRelease && j.Permissions == nil {
			report("job %s needs explicit permissions", jobName)
		}
		if isRelease && !usesRelease && jobMentionsSecret(j) {
			report("job %s reads %s without the release environment", jobName, signingSecret)
		}
		for _, s := range j.Steps {
			out = append(out, stepViolations(name, jobName, s, isRelease)...)
		}
	}
	return out
}

type permissionScope struct {
	where string
	value any
}

func permissionScopes(wf workflow) []permissionScope {
	scopes := []permissionScope{{"top level", wf.Permissions}}
	for _, jobName := range sortedKeys(wf.Jobs) {
		scopes = append(scopes, permissionScope{"job " + jobName, wf.Jobs[jobName].Permissions})
	}
	return scopes
}

func permissionViolations(name, where string, value any, writable map[string]bool, isRelease bool) []string {
	if value == nil {
		return nil
	}
	if text, ok := value.(string); ok {
		return []string{fmt.Sprintf("%s: %s: permissions %q are too broad", name, where, text)}
	}
	granted, _ := value.(map[string]any)
	var out []string
	for scope, level := range granted {
		if level != "write" {
			continue
		}
		switch {
		case !isRelease && releaseScopes[scope]:
			out = append(out, fmt.Sprintf("%s: %s: %s: write is only for the release workflows", name, where, scope))
		case isRelease && where == "top level":
			out = append(out, fmt.Sprintf("%s: top level: %s: write belongs on the job", name, scope))
		case isRelease && !writable[scope]:
			out = append(out, fmt.Sprintf("%s: %s: %s: write is not needed by this workflow", name, where, scope))
		}
	}
	return out
}

func stepViolations(file, jobName string, s step, isRelease bool) []string {
	var out []string
	where := fmt.Sprintf("%s: job %s", file, jobName)
	if s.Uses != "" && !isLocal(s.Uses) && !shaPin.MatchString(s.Uses) && !digestPin.MatchString(s.Uses) && !unpinnedDebt[file] {
		out = append(out, fmt.Sprintf("%s: %q is not pinned to a commit SHA", where, s.Uses))
	}
	if isRelease && strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["persist-credentials"] != false {
		out = append(out, where+": checkout must set persist-credentials: false")
	}
	if isRelease && strings.Contains(s.Run, expression) {
		out = append(out, where+": run scripts must take values from env, not from expressions")
	}
	return out
}

func jobMentionsSecret(j job) bool {
	for _, s := range j.Steps {
		for _, value := range s.Env {
			if strings.Contains(value, signingSecret) {
				return true
			}
		}
	}
	return false
}

func environmentName(environment any) string {
	switch v := environment.(type) {
	case string:
		return v
	case map[string]any:
		name, _ := v["name"].(string)
		return name
	}
	return ""
}

func pushesOnlyTags(push any) bool {
	cfg, ok := push.(map[string]any)
	if !ok {
		return false
	}
	_, hasTags := cfg["tags"]
	_, hasBranches := cfg["branches"]
	return hasTags && !hasBranches
}

// triggersOf normalizes the three YAML shapes of `on:` (scalar, list, mapping) to a mapping.
func triggersOf(on any) map[string]any {
	out := map[string]any{}
	switch v := on.(type) {
	case string:
		out[v] = nil
	case []any:
		for _, item := range v {
			if name, ok := item.(string); ok {
				out[name] = nil
			}
		}
	case map[string]any:
		return v
	}
	return out
}

func isLocal(uses string) bool { return strings.HasPrefix(uses, "./") }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func repoWorkflows(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	files := make(map[string]string, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(path)] = string(data)
	}
	return files
}

func TestWorkflowPolicyRepositoryComplies(t *testing.T) {
	files := repoWorkflows(t)
	for name := range releaseWorkflows {
		if _, ok := files[name]; !ok {
			t.Fatalf("%s is missing", name)
		}
	}
	for _, v := range violations(files) {
		t.Error(v)
	}
}

func TestWorkflowPolicyRejectsBreaches(t *testing.T) {
	const pinned = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	tests := []struct {
		name string
		file string
		yaml string
		want string
	}{
		{
			name: "release environment in ci",
			file: "ci.yml",
			yaml: "on: push\npermissions: {contents: read}\njobs:\n  j:\n    environment: release\n    runs-on: x\n    steps: []\n",
			want: "uses the release environment",
		},
		{
			name: "release environment as a mapping",
			file: "ci.yml",
			yaml: "on: push\npermissions: {contents: read}\njobs:\n  j:\n    environment: {name: release}\n    runs-on: x\n    steps: []\n",
			want: "uses the release environment",
		},
		{
			name: "signing secret in ci",
			file: "ci.yml",
			yaml: "on: push\npermissions: {contents: read}\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: echo\n        env: {K: '${{ secrets." + signingSecret + " }}'}\n",
			want: "referenced outside the release workflows",
		},
		{
			name: "missing top-level permissions",
			file: "ci.yml",
			yaml: "on: push\njobs: {}\n",
			want: "top-level permissions are required",
		},
		{
			name: "write-all",
			file: "ci.yml",
			yaml: "on: push\npermissions: write-all\njobs: {}\n",
			want: "too broad",
		},
		{
			name: "id-token write in ci",
			file: "ci.yml",
			yaml: "on: push\npermissions: {contents: read}\njobs:\n  j:\n    permissions: {id-token: write}\n    runs-on: x\n    steps: []\n",
			want: "write is only for the release workflows",
		},
		{
			name: "unpinned action",
			file: "ci.yml",
			yaml: "on: push\npermissions: {contents: read}\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n",
			want: "not pinned to a commit SHA",
		},
		{
			name: "pull_request_target",
			file: "ci.yml",
			yaml: "on: pull_request_target\npermissions: {contents: read}\njobs: {}\n",
			want: "pull_request_target",
		},
		{
			name: "release on a branch push",
			file: "release.yml",
			yaml: "on: {push: {branches: [main]}}\npermissions: {}\njobs: {}\n",
			want: "push must be limited to tags",
		},
		{
			name: "release on pull request",
			file: "release.yml",
			yaml: "on: {push: {tags: ['v*']}, pull_request: {}}\npermissions: {}\njobs: {}\n",
			want: `trigger "pull_request" is not allowed`,
		},
		{
			name: "channels with extra write",
			file: "channels.yml",
			yaml: "on: {workflow_dispatch: {}}\npermissions: {}\njobs:\n  j:\n    environment: release\n    permissions: {contents: write, id-token: write}\n    runs-on: x\n    steps: []\n",
			want: "id-token: write is not needed",
		},
		{
			name: "release job without explicit permissions",
			file: "release.yml",
			yaml: "on: {push: {tags: ['v*']}}\npermissions: {}\njobs:\n  j:\n    environment: release\n    runs-on: x\n    steps: []\n",
			want: "needs explicit permissions",
		},
		{
			name: "write at the top level of a release workflow",
			file: "release.yml",
			yaml: "on: {push: {tags: ['v*']}}\npermissions: {contents: write}\njobs: {}\n",
			want: "write belongs on the job",
		},
		{
			name: "secret read by a job outside the environment",
			file: "release.yml",
			yaml: "on: {push: {tags: ['v*']}}\npermissions: {}\njobs:\n  j:\n    permissions: {contents: read}\n    runs-on: x\n    steps:\n      - run: echo\n        env: {K: '${{ secrets." + signingSecret + " }}'}\n",
			want: "without the release environment",
		},
		{
			name: "expression inside a release run script",
			file: "release.yml",
			yaml: "on: {push: {tags: ['v*']}}\npermissions: {}\njobs:\n  j:\n    environment: release\n    permissions: {contents: write}\n    runs-on: x\n    steps:\n      - run: echo ${{ github.ref_name }}\n",
			want: "run scripts must take values from env",
		},
		{
			name: "checkout keeps credentials in a release workflow",
			file: "release.yml",
			yaml: "on: {push: {tags: ['v*']}}\npermissions: {}\njobs:\n  j:\n    environment: release\n    permissions: {contents: write}\n    runs-on: x\n    steps:\n      - uses: " + pinned + "\n",
			want: "persist-credentials: false",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := violations(map[string]string{tt.file: tt.yaml})
			for _, v := range got {
				if strings.Contains(v, tt.want) {
					return
				}
			}
			t.Fatalf("want a violation containing %q, got %q", tt.want, got)
		})
	}
}

func TestWorkflowPolicyAcceptsACompliantReleaseWorkflow(t *testing.T) {
	const compliant = `
on: {push: {tags: ['v*']}}
permissions: {}
jobs:
  release:
    environment: release
    permissions: {contents: write, id-token: write, attestations: write}
    runs-on: x
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with: {persist-credentials: false}
      - run: sign
        env: {SM_RELEASE_SIGNING_KEY: '${{ secrets.SM_RELEASE_SIGNING_KEY }}'}
`
	if got := violations(map[string]string{"release.yml": compliant}); len(got) != 0 {
		t.Fatalf("unexpected violations: %q", got)
	}
}
