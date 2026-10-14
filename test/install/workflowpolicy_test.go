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

// nightlyWorkflow runs the slow gates (ADR-0034): scheduled or dispatched, read-only, no environment.
const nightlyWorkflow = "nightly.yml"

var nightlyTriggers = set("schedule", "workflow_dispatch")

// pagesWorkflow publishes the website: only after a successful release run or by hand, built from a release
// tag, with write access confined to a deploy job that runs no code of ours.
const (
	pagesWorkflow    = "pages.yml"
	pagesEnvironment = "github-pages"
	tagRefPrefix     = "refs/tags/"
)

var (
	pagesTriggers = set("workflow_run", "workflow_dispatch")
	pagesWrites   = set("pages", "id-token")
)

// unpinnedDebt lists existing workflows that still use tag-pinned actions. Not owned by the
// release pipeline; remove the entry when the file is pinned.
var unpinnedDebt = set("pm-policy.yml")

// releaseScopes are the permission scopes that can publish or attest artifacts; write on them is
// reserved for the release workflows (and, for pages and id-token, the Pages workflow).
var releaseScopes = set("contents", "id-token", "attestations", "pages")

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
	Name     string `yaml:"name"`
	If       string `yaml:"if"`
	Needs    any    `yaml:"needs"`
	Strategy struct {
		Matrix yaml.Node `yaml:"matrix"`
	} `yaml:"strategy"`
	Environment any               `yaml:"environment"`
	Permissions any               `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Steps       []step            `yaml:"steps"`
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
	writes, hasWriteAllowance := writeAllowance(name)
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

	if name == nightlyWorkflow {
		out = append(out, nightlyViolations(name, wf, triggers)...)
	}
	if name == pagesWorkflow {
		out = append(out, pagesViolations(name, wf, triggers)...)
	}

	for _, scope := range permissionScopes(wf) {
		out = append(out, permissionViolations(name, scope.where, scope.value, writes, hasWriteAllowance)...)
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
		if isRelease && runsGoreleaser(j) {
			out = append(out, buildJobViolations(name, jobName, j)...)
		}
		for _, s := range j.Steps {
			out = append(out, stepViolations(name, jobName, s, isRelease)...)
		}
	}
	return out
}

// writeAllowance returns the write scopes a workflow may hold on its jobs; ok is false for
// workflows that may hold none of the publishing scopes.
func writeAllowance(name string) (scopes map[string]bool, ok bool) {
	if release, isRelease := releaseWorkflows[name]; isRelease {
		return release.writes, true
	}
	if name == pagesWorkflow {
		return pagesWrites, true
	}
	return nil, false
}

// pagesViolations keeps the site's build read-only and tag-bound, and its deploy job free of code.
func pagesViolations(name string, wf workflow, triggers map[string]any) []string {
	var out []string
	for _, trigger := range sortedKeys(triggers) {
		if !pagesTriggers[trigger] {
			out = append(out, fmt.Sprintf("%s: trigger %q is not allowed", name, trigger))
		}
	}
	run, followsRelease := triggers["workflow_run"]
	if followsRelease && !completesReleaseRun(run) {
		out = append(out, name+": the workflow_run trigger must be limited to workflows: [release] and types: [completed]")
	}
	for _, jobName := range sortedKeys(wf.Jobs) {
		j := wf.Jobs[jobName]
		granted, _ := j.Permissions.(map[string]any)
		if hasWrite(granted) {
			out = append(out, deployJobViolations(name, jobName, j)...)
			continue
		}
		out = append(out, pagesBuildViolations(name, jobName, j, followsRelease)...)
	}
	return out
}

func completesReleaseRun(run any) bool {
	cfg, ok := run.(map[string]any)
	if !ok {
		return false
	}
	workflows, _ := cfg["workflows"].([]any)
	types, _ := cfg["types"].([]any)
	return len(workflows) == 1 && workflows[0] == "release" && len(types) == 1 && types[0] == "completed"
}

// deployJobViolations: the job that holds pages/id-token write publishes an artifact and runs nothing else.
func deployJobViolations(file, jobName string, j job) []string {
	where := fmt.Sprintf("%s: job %s holds write access", file, jobName)
	var out []string
	if environmentName(j.Environment) != pagesEnvironment {
		out = append(out, fmt.Sprintf("%s and must use the %s environment", where, pagesEnvironment))
	}
	if len(needsOf(j.Needs)) == 0 {
		out = append(out, where+" and must wait for the build with needs")
	}
	if len(j.Env) != 0 {
		out = append(out, where+" and must not set env")
	}
	for _, s := range j.Steps {
		switch {
		case s.Run != "":
			out = append(out, where+" and must not run scripts")
		case strings.HasPrefix(s.Uses, "actions/checkout@"):
			out = append(out, where+" and must not check out the repository")
		case !strings.HasPrefix(s.Uses, "actions/deploy-pages@"):
			out = append(out, fmt.Sprintf("%s and may only use actions/deploy-pages, not %q", where, s.Uses))
		case len(s.Env) != 0:
			out = append(out, where+" and must not set env on a step")
		}
	}
	return out
}

// pagesBuildViolations: jobs without write access are read-only, outside the environment, and build
// from a release tag with no stored credentials.
func pagesBuildViolations(file, jobName string, j job, followsRelease bool) []string {
	where := fmt.Sprintf("%s: job %s", file, jobName)
	var out []string
	if followsRelease && !strings.Contains(j.If, "workflow_run.conclusion == 'success'") {
		out = append(out, where+" must run only when the release run concluded with success")
	}
	if j.Permissions == nil {
		out = append(out, where+" must declare read-only permissions")
	}
	if environmentName(j.Environment) != "" {
		out = append(out, where+" builds and must not use an environment")
	}
	for _, s := range j.Steps {
		if strings.Contains(s.Run, expression) {
			out = append(out, where+": run scripts must take values from env, not from expressions")
		}
		if !strings.HasPrefix(s.Uses, "actions/checkout@") {
			continue
		}
		if s.With["persist-credentials"] != false {
			out = append(out, where+": checkout must set persist-credentials: false")
		}
		if ref, _ := s.With["ref"].(string); !strings.HasPrefix(ref, tagRefPrefix) {
			out = append(out, fmt.Sprintf("%s: checkout must pin ref to %s<tag>, not %q", where, tagRefPrefix, ref))
		}
	}
	return out
}

// nightlyViolations keeps the nightly gates from running on untrusted triggers or holding write access.
func nightlyViolations(name string, wf workflow, triggers map[string]any) []string {
	var out []string
	for _, trigger := range sortedKeys(triggers) {
		if !nightlyTriggers[trigger] {
			out = append(out, fmt.Sprintf("%s: trigger %q is not allowed", name, trigger))
		}
	}
	for _, scope := range permissionScopes(wf) {
		if granted, _ := scope.value.(map[string]any); hasWrite(granted) {
			out = append(out, fmt.Sprintf("%s: %s: nightly must stay read-only", name, scope.where))
		}
	}
	for _, jobName := range sortedKeys(wf.Jobs) {
		if environmentName(wf.Jobs[jobName].Environment) != "" {
			out = append(out, fmt.Sprintf("%s: job %s must not use an environment", name, jobName))
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

func permissionViolations(name, where string, value any, writable map[string]bool, hasAllowance bool) []string {
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
		case !hasAllowance && releaseScopes[scope]:
			out = append(out, fmt.Sprintf("%s: %s: %s: write is only for the release and pages workflows", name, where, scope))
		case hasAllowance && where == "top level":
			out = append(out, fmt.Sprintf("%s: top level: %s: write belongs on the job", name, scope))
		case hasAllowance && !writable[scope]:
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

// runsGoreleaser reports whether the job executes the release build, which runs third-party code.
func runsGoreleaser(j job) bool {
	for _, s := range j.Steps {
		if strings.HasPrefix(s.Uses, "goreleaser/") || strings.Contains(s.Run, "goreleaser") {
			return true
		}
	}
	return false
}

// buildJobViolations keeps everything that could sign or publish away from the job that builds.
func buildJobViolations(file, jobName string, j job) []string {
	where := fmt.Sprintf("%s: job %s runs goreleaser", file, jobName)
	var out []string
	if environmentName(j.Environment) != "" {
		out = append(out, where+" and must not use an environment")
	}
	if jobMentionsSecret(j) {
		out = append(out, fmt.Sprintf("%s and must not see %s", where, signingSecret))
	}
	if granted, _ := j.Permissions.(map[string]any); j.Permissions == nil || hasWrite(granted) {
		out = append(out, where+" and must declare read-only permissions")
	}
	return out
}

func hasWrite(granted map[string]any) bool {
	for _, level := range granted {
		if level == "write" {
			return true
		}
	}
	return false
}

func jobMentionsSecret(j job) bool {
	for _, value := range j.Env {
		if strings.Contains(value, signingSecret) {
			return true
		}
	}
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
			want: "write is only for the release and pages workflows",
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
		{
			name: "nightly on pull request",
			file: "nightly.yml",
			yaml: "on: {schedule: [{cron: '0 0 * * *'}], pull_request: {}}\npermissions: {contents: read}\njobs: {}\n",
			want: `trigger "pull_request" is not allowed`,
		},
		{
			name: "nightly job with write access",
			file: "nightly.yml",
			yaml: "on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  j:\n    permissions: {issues: write}\n    runs-on: x\n    steps: []\n",
			want: "nightly must stay read-only",
		},
		{
			name: "nightly job in an environment",
			file: "nightly.yml",
			yaml: "on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  j:\n    environment: staging\n    runs-on: x\n    steps: []\n",
			want: "must not use an environment",
		},
		{
			name: "unpinned action in nightly",
			file: "nightly.yml",
			yaml: "on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: actions/upload-artifact@v4\n",
			want: "not pinned to a commit SHA",
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

func TestWorkflowPolicyKeepsTheSigningKeyAwayFromTheBuild(t *testing.T) {
	const header = "on: {push: {tags: ['v*']}}\npermissions: {}\njobs:\n  build:\n"
	const secret = "'${{ secrets." + signingSecret + " }}'"
	tests := []struct {
		name string
		job  string
		want string
	}{
		{"key in a build step", "    permissions: {contents: read}\n    runs-on: x\n    steps:\n      - uses: goreleaser/goreleaser-action@3d3c42e5aac5ba805825da76410c181273ba90b1\n        env: {K: " + secret + "}\n", "must not see " + signingSecret},
		{"key in the job env", "    permissions: {contents: read}\n    env: {K: " + secret + "}\n    runs-on: x\n    steps:\n      - run: goreleaser release\n", "must not see " + signingSecret},
		{"build inside the release environment", "    environment: release\n    permissions: {contents: read}\n    runs-on: x\n    steps:\n      - run: goreleaser release\n", "must not use an environment"},
		{"build with write permissions", "    permissions: {contents: write}\n    runs-on: x\n    steps:\n      - run: goreleaser release\n", "read-only permissions"},
		{"build without explicit permissions", "    runs-on: x\n    steps:\n      - run: goreleaser release\n", "read-only permissions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := violations(map[string]string{"release.yml": header + tt.job})
			for _, v := range got {
				if strings.Contains(v, tt.want) {
					return
				}
			}
			t.Fatalf("want a violation containing %q, got %q", tt.want, got)
		})
	}
}

func TestReleaseWorkflowSignsOnlyOutsideTheBuildJob(t *testing.T) {
	var wf workflow
	if err := yaml.Unmarshal([]byte(repoWorkflows(t)["release.yml"]), &wf); err != nil {
		t.Fatal(err)
	}
	signer := wf.Jobs["sign-publish"]
	if environmentName(signer.Environment) != "release" || !jobMentionsSecret(signer) || runsGoreleaser(signer) {
		t.Fatal("sign-publish must be the release-environment job that holds the key and never runs goreleaser")
	}
	if builder := wf.Jobs["build"]; !runsGoreleaser(builder) || jobMentionsSecret(builder) {
		t.Fatal("build must be the job that runs goreleaser, without the key")
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

// ---- release gate (ADR-0034, Q17) ----

const (
	ciWorkflow       = "ci.yml"
	releaseWorkflow  = "release.yml"
	gatesJob         = "gates"
	nightlyAggregate = "nightly"
	requiredChecks   = "../../packaging/release/required-checks.txt"
	hostLifecycleTag = "hostlifecycle"
)

// hostTargets are the only Make targets allowed to compile the host-mutating tests (ADR-0036).
var hostTargets = set("e2e-lifecycle-vm", "e2e-lifecycle-macos")

func parseWorkflow(t *testing.T, source string) workflow {
	t.Helper()
	var wf workflow
	if err := yaml.Unmarshal([]byte(source), &wf); err != nil {
		t.Fatalf("not valid YAML: %v", err)
	}
	return wf
}

// needsOf normalizes `needs:` (scalar or list) to job ids.
func needsOf(needs any) []string {
	switch v := needs.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			if name, ok := item.(string); ok {
				out = append(out, name)
			}
		}
		return out
	}
	return nil
}

// reaches reports whether job `from` depends, directly or through other jobs, on job `target`.
func reaches(jobs map[string]job, from, target string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(id string) bool {
		for _, dep := range needsOf(jobs[id].Needs) {
			if dep == target || (!seen[dep] && walk(dep)) {
				return true
			}
			seen[dep] = true
		}
		return false
	}
	return walk(from)
}

func readsChecks(permissions any) bool {
	granted, _ := permissions.(map[string]any)
	return granted["checks"] == "read"
}

func TestWorkflowPolicy_ReleaseNeedsGates(t *testing.T) {
	wf := parseWorkflow(t, repoWorkflows(t)[releaseWorkflow])

	gates, ok := wf.Jobs[gatesJob]
	if !ok {
		t.Fatalf("%s has no %s job", releaseWorkflow, gatesJob)
	}
	if granted, _ := gates.Permissions.(map[string]any); granted["checks"] != "read" || hasWrite(granted) {
		t.Errorf("%s must declare checks: read and nothing writable, got %v", gatesJob, gates.Permissions)
	}
	if environmentName(gates.Environment) != "" || jobMentionsSecret(gates) || runsGoreleaser(gates) {
		t.Errorf("%s must hold no environment, no signing key and build nothing", gatesJob)
	}
	if len(needsOf(gates.Needs)) != 0 {
		t.Errorf("%s must not wait for other jobs, got %v", gatesJob, needsOf(gates.Needs))
	}
	for _, producer := range []string{"build", "sign-publish"} {
		if !reaches(wf.Jobs, producer, gatesJob) {
			t.Errorf("%s must depend on %s, directly or through other jobs", producer, gatesJob)
		}
	}
	if !slicesContain(needsOf(wf.Jobs["build"].Needs), gatesJob) {
		t.Errorf("build must list %s in needs so nothing is built before the gate", gatesJob)
	}
	if !strings.Contains(runScripts(gates), "require-checks.sh packaging/release/required-checks.txt") {
		t.Errorf("%s must run require-checks.sh over packaging/release/required-checks.txt", gatesJob)
	}
}

func TestWorkflowPolicy_OnlyGatesReadsChecks(t *testing.T) {
	for name, source := range repoWorkflows(t) {
		wf := parseWorkflow(t, source)
		if readsChecks(wf.Permissions) {
			t.Errorf("%s: checks: read at the top level", name)
		}
		for _, id := range sortedKeys(wf.Jobs) {
			allowed := name == releaseWorkflow && id == gatesJob
			if readsChecks(wf.Jobs[id].Permissions) && !allowed {
				t.Errorf("%s: job %s reads checks; only %s/%s may", name, id, releaseWorkflow, gatesJob)
			}
		}
	}
}

func TestWorkflowPolicy_SignPublishVerifiesSuppliesBeforePublishing(t *testing.T) {
	wf := parseWorkflow(t, repoWorkflows(t)[releaseWorkflow])
	steps := wf.Jobs["sign-publish"].Steps
	position := func(fragment string) int {
		for i, s := range steps {
			if strings.Contains(s.Run, fragment) {
				return i
			}
		}
		return -1
	}
	publish := position("gh release create")
	for _, fragment := range []string{"check.sh dist install.sh", "verify-provenance.sh"} {
		if at := position(fragment); at < 0 || at > publish {
			t.Errorf("sign-publish must run %s before publish (at %d, publish at %d)", fragment, at, publish)
		}
	}
}

func runScripts(j job) string {
	var out strings.Builder
	for _, s := range j.Steps {
		out.WriteString(s.Run)
		out.WriteString("\n")
	}
	return out.String()
}

func slicesContain(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// checkNames returns the check-run names GitHub reports for a workflow's jobs: the job name (or id)
// and, for a matrix job, the matrix values in declaration order, one name per leg.
func checkNames(wf workflow) ([]string, error) {
	var names []string
	for _, id := range sortedKeys(wf.Jobs) {
		j := wf.Jobs[id]
		if strings.Contains(j.Name, expression) {
			return nil, fmt.Errorf("job %s: a job name with an expression cannot be checked against required-checks.txt", id)
		}
		base := id
		if j.Name != "" {
			base = j.Name
		}
		legs, err := matrixLegs(j.Strategy.Matrix)
		if err != nil {
			return nil, fmt.Errorf("job %s: %w", id, err)
		}
		if legs == nil {
			names = append(names, base)
			continue
		}
		for _, leg := range legs {
			names = append(names, base+" ("+strings.Join(leg, ", ")+")")
		}
	}
	return names, nil
}

// matrixLegs expands a plain list-valued matrix (no include/exclude) into its combinations.
func matrixLegs(matrix yaml.Node) ([][]string, error) {
	if matrix.Kind == 0 {
		return nil, nil
	}
	if matrix.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("matrix is not a mapping")
	}
	legs := [][]string{{}}
	for i := 0; i+1 < len(matrix.Content); i += 2 {
		key, values := matrix.Content[i].Value, matrix.Content[i+1]
		if key == "include" || key == "exclude" {
			return nil, fmt.Errorf("matrix %s is not supported by the required-checks drift test", key)
		}
		if values.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("matrix %s is not a plain list", key)
		}
		var next [][]string
		for _, leg := range legs {
			for _, value := range values.Content {
				next = append(next, append(append([]string{}, leg...), value.Value))
			}
		}
		legs = next
	}
	return legs, nil
}

func readRequiredChecks(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(requiredChecks)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			names = append(names, line)
		}
	}
	return names
}

// diffNames describes how got deviates from want, both treated as sets; duplicates in got are reported.
func diffNames(got, want []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, name := range got {
		if seen[name] {
			out = append(out, "listed twice: "+name)
		}
		seen[name] = true
	}
	wanted := set(want...)
	for _, name := range sortedKeys(wanted) {
		if !seen[name] {
			out = append(out, "missing: "+name)
		}
	}
	for _, name := range sortedKeys(seen) {
		if !wanted[name] {
			out = append(out, "unknown: "+name)
		}
	}
	return out
}

func TestWorkflowPolicy_RequiredChecksMatchCI(t *testing.T) {
	files := repoWorkflows(t)
	want, err := checkNames(parseWorkflow(t, files[ciWorkflow]))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseWorkflow(t, files[nightlyWorkflow]).Jobs[nightlyAggregate]; !ok {
		t.Fatalf("%s has no %s job for the release gate to require", nightlyWorkflow, nightlyAggregate)
	}
	want = append(want, nightlyAggregate)
	for _, drift := range diffNames(readRequiredChecks(t), want) {
		t.Errorf("packaging/release/required-checks.txt: %s", drift)
	}
}

func TestWorkflowPolicy_NightlyAggregateWaitsForEveryOtherJob(t *testing.T) {
	wf := parseWorkflow(t, repoWorkflows(t)[nightlyWorkflow])
	aggregate := wf.Jobs[nightlyAggregate]
	needs := set(needsOf(aggregate.Needs)...)
	for _, id := range sortedKeys(wf.Jobs) {
		if id != nightlyAggregate && !needs[id] {
			t.Errorf("%s does not wait for %s, so a red %s would not stop the release", nightlyAggregate, id, id)
		}
	}
}

func TestCheckNames_ExpandsMatricesTheWayGitHubNamesThem(t *testing.T) {
	const source = `
jobs:
  plain: {runs-on: x}
  named: {name: custom, runs-on: x}
  grid:
    strategy:
      matrix:
        runner: [a, b]
        mode: [server, client]
    runs-on: x
`
	got, err := checkNames(parseWorkflow(t, source))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"custom", "grid (a, server)", "grid (a, client)", "grid (b, server)", "grid (b, client)", "plain"}
	if drift := diffNames(got, want); len(drift) != 0 {
		t.Fatalf("names differ from GitHub's: %q\ngot %q", drift, got)
	}
}

func TestCheckNames_RefusesWhatItCannotExpand(t *testing.T) {
	tests := map[string]string{
		"include":         "jobs:\n  j:\n    strategy: {matrix: {os: [a], include: [{os: b}]}}\n    runs-on: x\n",
		"exclude":         "jobs:\n  j:\n    strategy: {matrix: {os: [a], exclude: [{os: a}]}}\n    runs-on: x\n",
		"expression list": "jobs:\n  j:\n    strategy: {matrix: {os: '${{ fromJSON(needs.x.outputs.os) }}'}}\n    runs-on: x\n",
		"templated name":  "jobs:\n  j:\n    name: 'j ${{ matrix.os }}'\n    runs-on: x\n",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := checkNames(parseWorkflow(t, source)); err == nil {
				t.Fatal("want an error: the drift test must not silently skip legs")
			}
		})
	}
}

func TestDiffNames_ReportsDriftBothWays(t *testing.T) {
	got := diffNames([]string{"a", "b", "b", "stale"}, []string{"a", "b", "new"})
	want := []string{"listed twice: b", "missing: new", "unknown: stale"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// ---- host-mutating tests stay out of every generic target (ADR-0036) ----

type makeRule struct {
	prereqs []string
	lines   []string // the rule line and its recipe lines
}

// makeRules splits a Makefile into rules; recipe lines start with a tab.
func makeRules(source string) map[string]*makeRule {
	rules := map[string]*makeRule{}
	var current *makeRule
	for _, line := range strings.Split(source, "\n") {
		switch {
		case strings.HasPrefix(line, "\t") && current != nil:
			current.lines = append(current.lines, line)
		case ruleLine.MatchString(line):
			m := ruleLine.FindStringSubmatch(line)
			current = &makeRule{prereqs: strings.Fields(strings.SplitN(m[2], "##", 2)[0]), lines: []string{line}}
			rules[m[1]] = current
		default:
			current = nil
		}
	}
	return rules
}

var ruleLine = regexp.MustCompile(`^([a-z0-9][a-z0-9-]*):([^=].*|)$`)

// hostTagViolations lists every place the host-mutating tag appears outside the host targets, and
// every generic target that runs a host target.
func hostTagViolations(makefile string, workflows map[string]string) []string {
	var out []string
	owner := ""
	for _, line := range strings.Split(makefile, "\n") {
		switch {
		case strings.HasPrefix(line, "\t") && owner != "":
		case ruleLine.MatchString(line):
			owner = ruleLine.FindStringSubmatch(line)[1]
		default:
			owner = ""
		}
		switch {
		case !strings.Contains(line, hostLifecycleTag) || hostTargets[owner]:
		case owner == "":
			out = append(out, "Makefile: "+hostLifecycleTag+" outside a recipe: "+strings.TrimSpace(line))
		default:
			out = append(out, fmt.Sprintf("Makefile: target %s mentions %s", owner, hostLifecycleTag))
		}
	}
	rules := makeRules(makefile)
	for _, name := range sortedKeys(rules) {
		for _, host := range sortedKeys(hostTargets) {
			if !hostTargets[name] && closureHas(rules, name, host) {
				out = append(out, fmt.Sprintf("Makefile: target %s runs %s", name, host))
			}
		}
	}
	for _, file := range sortedKeys(workflows) {
		if strings.Contains(workflows[file], hostLifecycleTag) {
			out = append(out, file+": mentions "+hostLifecycleTag+"; workflows call the Make targets")
		}
	}
	return out
}

// closureHas reports whether target is among the prerequisites of from, transitively.
func closureHas(rules map[string]*makeRule, from, target string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(name string) bool {
		rule := rules[name]
		if rule == nil {
			return false
		}
		for _, dep := range rule.prereqs {
			if dep == target || (!seen[dep] && walk(dep)) {
				return true
			}
			seen[dep] = true
		}
		return false
	}
	return walk(from)
}

func TestWorkflowPolicy_HostLifecycleTagStaysInTheHostTargets(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range hostTagViolations(string(makefile), repoWorkflows(t)) {
		t.Error(v)
	}
	rules := makeRules(string(makefile))
	for _, name := range sortedKeys(hostTargets) {
		rule := rules[name]
		if rule == nil || !strings.Contains(strings.Join(rule.lines, "\n"), hostLifecycleTag) {
			t.Errorf("Makefile: host target %s must exist and compile the %s tag", name, hostLifecycleTag)
		}
	}
}

func TestWorkflowPolicy_MakeE2EHasNoHostTarget(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	rules := makeRules(string(makefile))
	if rules["e2e"] == nil {
		t.Fatal("Makefile has no e2e target")
	}
	for _, host := range sortedKeys(hostTargets) {
		if closureHas(rules, "e2e", host) {
			t.Errorf("make e2e reaches %s", host)
		}
	}
}

func TestHostTagViolations_CatchesALeakIntoGenericTargets(t *testing.T) {
	tests := []struct {
		name      string
		makefile  string
		workflows map[string]string
		want      string
	}{
		{"clean", "e2e: e2e-server\ne2e-server:\n\tgo test -tags e2e ./x\ne2e-lifecycle-vm:\n\tgo test -tags 'e2e hostlifecycle' ./x\n", nil, ""},
		{"tag in a generic recipe", "e2e-server:\n\tgo test -tags 'e2e hostlifecycle' ./x\n", nil, "target e2e-server mentions"},
		{"tag in a variable", "E2E_TAGS := e2e hostlifecycle\ne2e-server:\n\tgo test ./x\n", nil, "outside a recipe"},
		{"e2e depends on a host target", "e2e: e2e-lifecycle-vm\ne2e-lifecycle-vm:\n\tgo test -tags hostlifecycle ./x\n", nil, "target e2e runs e2e-lifecycle-vm"},
		{"transitive dependency", "e2e: e2e-all\ne2e-all: e2e-lifecycle-macos\ne2e-lifecycle-macos:\n\tgo test -tags hostlifecycle ./x\n", nil, "target e2e-all runs e2e-lifecycle-macos"},
		{"workflow with the tag", "e2e-server:\n\techo\n", map[string]string{"ci.yml": "run: go test -tags hostlifecycle ./..."}, "ci.yml: mentions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostTagViolations(tt.makefile, tt.workflows)
			if tt.want == "" && len(got) != 0 {
				t.Fatalf("unexpected violations: %q", got)
			}
			if tt.want != "" && !strings.Contains(strings.Join(got, "\n"), tt.want) {
				t.Fatalf("want a violation containing %q, got %q", tt.want, got)
			}
		})
	}
}

func TestWorkflowPolicy_ReleaseGateRejectsABuildThatDoesNotWaitForIt(t *testing.T) {
	const source = `
jobs:
  gates: {runs-on: x}
  build: {runs-on: x}
  sign-publish: {needs: build, runs-on: x}
`
	wf := parseWorkflow(t, source)
	if reaches(wf.Jobs, "sign-publish", gatesJob) {
		t.Fatal("sign-publish reaches gates without build needing it")
	}
	const chained = `
jobs:
  gates: {runs-on: x}
  build: {needs: gates, runs-on: x}
  sign-publish: {needs: [build], runs-on: x}
`
	if !reaches(parseWorkflow(t, chained).Jobs, "sign-publish", gatesJob) {
		t.Fatal("sign-publish must reach gates through build")
	}
}

// ---- Pages workflow: the site follows releases, built read-only, published by a code-free job ----

const compliantPages = `
on:
  workflow_run: {workflows: [release], types: [completed]}
  workflow_dispatch:
permissions: {contents: read}
jobs:
  build:
    if: github.event_name == 'workflow_dispatch' || github.event.workflow_run.conclusion == 'success'
    runs-on: x
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: refs/tags/${{ steps.tag.outputs.tag }}
          persist-credentials: false
      - run: make site-check
  deploy:
    needs: build
    runs-on: x
    permissions: {pages: write, id-token: write}
    environment: {name: github-pages}
    steps:
      - uses: actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346
`

func replaceOnce(old, replacement string) func(string) string {
	return func(s string) string { return strings.Replace(s, old, replacement, 1) }
}

func appendSteps(steps string) func(string) string {
	return func(s string) string { return s + steps }
}

func TestWorkflowPolicy_PagesAcceptsABuildFromATagAndACodeFreeDeploy(t *testing.T) {
	if got := violations(map[string]string{pagesWorkflow: compliantPages}); len(got) != 0 {
		t.Fatalf("unexpected violations: %q", got)
	}
}

func TestWorkflowPolicy_PagesRejectsBreaches(t *testing.T) {
	const (
		buildHead   = "build:\n    if: github.event_name == 'workflow_dispatch' || github.event.workflow_run.conclusion == 'success'\n    runs-on: x\n    permissions: {contents: read}"
		checkoutSHA = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	)
	tests := []struct {
		name   string
		file   string
		change func(string) string
		want   string
	}{
		{"deploy from a branch", "", replaceOnce("ref: refs/tags/${{ steps.tag.outputs.tag }}", "ref: main"), "checkout must pin ref to refs/tags/"},
		{"checkout without a ref follows the triggering branch", "", replaceOnce("          ref: refs/tags/${{ steps.tag.outputs.tag }}\n", ""), "checkout must pin ref to refs/tags/"},
		{"credentials persisted in the build", "", replaceOnce("persist-credentials: false", "persist-credentials: true"), "checkout must set persist-credentials: false"},
		{"push trigger", "", replaceOnce("workflow_dispatch:", "workflow_dispatch:\n  push: {branches: [main]}"), `trigger "push" is not allowed`},
		{"pull request trigger", "", replaceOnce("workflow_dispatch:", "workflow_dispatch:\n  pull_request:"), `trigger "pull_request" is not allowed`},
		{"workflow_run from another workflow", "", replaceOnce("workflows: [release]", "workflows: [ci]"), "limited to workflows: [release] and types: [completed]"},
		{"workflow_run beyond completed", "", replaceOnce("types: [completed]", "types: [completed, requested]"), "limited to workflows: [release] and types: [completed]"},
		{"release trigger", "", replaceOnce("workflow_dispatch:", "workflow_dispatch:\n  release: {types: [published]}"), `trigger "release" is not allowed`},
		{"build without the conclusion check", "", replaceOnce("github.event.workflow_run.conclusion == 'success'", "true"), "must run only when the release run concluded with success"},
		{"build without any condition", "", replaceOnce("    if: github.event_name == 'workflow_dispatch' || github.event.workflow_run.conclusion == 'success'\n", ""), "must run only when the release run concluded with success"},
		{"pages write at the top level", "", replaceOnce("permissions: {contents: read}\njobs:", "permissions: {pages: write}\njobs:"), "top level: pages: write belongs on the job"},
		{"contents write on the deploy job", "", replaceOnce("{pages: write, id-token: write}", "{pages: write, id-token: write, contents: write}"), "contents: write is not needed by this workflow"},
		{"build job in an environment", "", replaceOnce(buildHead, buildHead+"\n    environment: staging"), "job build builds and must not use an environment"},
		{"id-token write on the build job", "", replaceOnce("permissions: {contents: read}\n    steps", "permissions: {contents: read, id-token: write}\n    steps"), "job build holds write access and must use the github-pages environment"},
		{"deploy without needs", "", replaceOnce("    needs: build\n", ""), "must wait for the build with needs"},
		{"deploy outside the pages environment", "", replaceOnce("environment: {name: github-pages}", "environment: {name: staging}"), "must use the github-pages environment"},
		{"deploy job runs a script", "", appendSteps("      - run: npm ci\n"), "must not run scripts"},
		{"deploy job checks out the repository", "", appendSteps("      - uses: " + checkoutSHA + "\n"), "must not check out the repository"},
		{"deploy job uses another action", "", appendSteps("      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1\n"), "may only use actions/deploy-pages"},
		{"build job has no permissions block", "", replaceOnce("    permissions: {contents: read}\n    steps", "    steps"), "job build must declare read-only permissions"},
		{"expression in a build script", "", replaceOnce("run: make site-check", "run: echo ${{ github.event.workflow_run.name }}"), "run scripts must take values from env"},
		{"pages write in another workflow", "ci.yml", func(string) string {
			return "on: push\npermissions: {contents: read}\njobs:\n  j:\n    permissions: {pages: write}\n    runs-on: x\n    steps: []\n"
		}, "pages: write is only for the release and pages workflows"},
		{"id-token write in another workflow", "ci.yml", func(string) string {
			return "on: push\npermissions: {contents: read}\njobs:\n  j:\n    permissions: {id-token: write}\n    runs-on: x\n    steps: []\n"
		}, "id-token: write is only for the release and pages workflows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := tt.file
			if file == "" {
				file = pagesWorkflow
			}
			source := tt.change(compliantPages)
			if source == compliantPages {
				t.Fatal("the fixture change did not apply")
			}
			got := violations(map[string]string{file: source})
			for _, v := range got {
				if strings.Contains(v, tt.want) {
					return
				}
			}
			t.Fatalf("want a violation containing %q, got %q", tt.want, got)
		})
	}
}
