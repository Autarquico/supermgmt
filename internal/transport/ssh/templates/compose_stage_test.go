package templates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testDeployment = "0190a5e2-7c41-7b9e-9f0e-3d2c1b0a9f88"

func deployArgs(root string) map[string]string {
	return map[string]string{"root": root, "project": "sm-shop-prod", "deployment": testDeployment}
}

// script is a fixed script run the way a rendered template runs it.
type script struct {
	interpreter string
	text        string
	args        []string
	stdin       []byte
	pathShims   map[string]string // command name -> sh body, put first in PATH
	env         []string
}

type scriptResult struct {
	stdout, stderr string
	err            error
}

func (s script) run(t *testing.T) scriptResult {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), s.interpreter, append([]string{"-c", s.text, s.interpreter}, s.args...)...)
	shims := t.TempDir()
	for name, body := range s.pathShims {
		if err := os.WriteFile(filepath.Join(shims, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd.Env = append(append(os.Environ(), s.env...), "PATH="+shims+":"+os.Getenv("PATH"))
	cmd.Stdin = bytes.NewReader(s.stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return scriptResult{stdout.String(), stderr.String(), err}
}

func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

// sha256Shim provides sha256sum on hosts that only have shasum (macOS).
func sha256Shim() map[string]string {
	if _, err := exec.LookPath("sha256sum"); err == nil {
		return nil
	}
	return map[string]string{"sha256sum": "exec shasum -a 256"}
}

func mustEncode(t *testing.T, files ...StagedFile) []byte {
	t.Helper()
	b, err := EncodeMaterialization(files)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncodeMaterializationFramesFilesAndRefusesWhatTheNodeRefuses(t *testing.T) {
	got := mustEncode(t, StagedFile{"compose.yaml", []byte("a: 1\n")}, StagedFile{"secrets/api.env", []byte("K=v")})
	if want := "5 compose.yaml\na: 1\n3 secrets/api.env\nK=v"; string(got) != want {
		t.Errorf("framed = %q, want %q", got, want)
	}
	yaml := StagedFile{"compose.yaml", []byte("x")}
	tests := map[string][]StagedFile{
		"no compose.yaml":     {{"secrets/api.env", nil}},
		"duplicate":           {yaml, yaml},
		"traversal":           {yaml, {"secrets/../x.env", nil}},
		"outside secrets":     {yaml, {"evil.sh", nil}},
		"nested secret":       {yaml, {"secrets/a/b.env", nil}},
		"empty service name":  {yaml, {"secrets/.env", nil}},
		"newline in the name": {yaml, {"secrets/a\nb.env", nil}},
		"oversize":            {{"compose.yaml", make([]byte, MaterializeLimit+1)}},
	}
	for name, files := range tests {
		if _, err := EncodeMaterialization(files); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func materialize(t *testing.T, root string, stdin []byte) scriptResult {
	t.Helper()
	return script{
		interpreter: "sh", text: materializeScript, stdin: stdin,
		args: []string{root, "sm-shop-prod", testDeployment},
	}.run(t)
}

func physicalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMaterializeWritesTheDirectoryWithExactBytesAndModes(t *testing.T) {
	root := physicalTempDir(t)
	secret := "K=$HOME ${C} $$ 'q' \"d\" # x =y \\n  \n"
	in := mustEncode(t,
		StagedFile{"compose.yaml", []byte("services:\n  api: {}\n")},
		StagedFile{"secrets/api.env", []byte(secret)},
		StagedFile{"secrets/empty.env", nil},
	)
	if res := materialize(t, root, in); res.err != nil {
		t.Fatalf("%v: %s", res.err, res.stderr)
	}
	dir := filepath.Join(root, "sm-shop-prod", testDeployment)
	for rel, want := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		"compose.yaml":      {"services:\n  api: {}\n", 0o640},
		"secrets/api.env":   {secret, 0o600},
		"secrets/empty.env": {"", 0o600},
	} {
		got, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil || string(got) != want.content {
			t.Errorf("%s = %q (%v), want %q", rel, got, err, want.content)
		}
		if info, _ := os.Stat(filepath.Join(dir, rel)); info.Mode().Perm() != want.mode {
			t.Errorf("%s mode = %v, want %v", rel, info.Mode().Perm(), want.mode)
		}
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(root, "sm-shop-prod"): 0o750, dir: 0o750, filepath.Join(dir, "secrets"): 0o700,
	} {
		if info, _ := os.Stat(path); info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", path, info.Mode().Perm(), want)
		}
	}
}

func TestMaterializeRefusesAnExistingDeploymentDirectory(t *testing.T) {
	root := physicalTempDir(t)
	in := mustEncode(t, StagedFile{"compose.yaml", []byte("first")})
	if res := materialize(t, root, in); res.err != nil {
		t.Fatal(res.stderr)
	}
	again := mustEncode(t, StagedFile{"compose.yaml", []byte("second")})
	if res := materialize(t, root, again); res.err == nil {
		t.Fatal("materialize reused an existing directory")
	}
	got, _ := os.ReadFile(filepath.Join(root, "sm-shop-prod", testDeployment, "compose.yaml"))
	if string(got) != "first" {
		t.Errorf("compose.yaml = %q, the first deployment was overwritten", got)
	}
}

func TestMaterializeFollowsNoSymlink(t *testing.T) {
	in := mustEncode(t, StagedFile{"compose.yaml", []byte("x")}, StagedFile{"secrets/api.env", []byte("S=1")})
	tests := map[string]func(t *testing.T, root, outside string){
		"project directory is a symlink": func(t *testing.T, root, outside string) {
			mustSymlink(t, outside, filepath.Join(root, "sm-shop-prod"))
		},
		"deployment directory is a symlink": func(t *testing.T, root, outside string) {
			mustMkdir(t, filepath.Join(root, "sm-shop-prod"))
			mustSymlink(t, outside, filepath.Join(root, "sm-shop-prod", testDeployment))
		},
		"deployment directory is a dangling symlink": func(t *testing.T, root, _ string) {
			mustMkdir(t, filepath.Join(root, "sm-shop-prod"))
			mustSymlink(t, filepath.Join(root, "nowhere"), filepath.Join(root, "sm-shop-prod", testDeployment))
		},
		"deploy root is a symlink": func(t *testing.T, root, outside string) {
			if err := os.Remove(root); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, outside, root)
		},
	}
	for name, plant := range tests {
		t.Run(name, func(t *testing.T) {
			root, outside := physicalTempDir(t), physicalTempDir(t)
			plant(t, root, outside)
			if res := materialize(t, root, in); res.err == nil {
				t.Fatal("materialize followed a symlink")
			}
			if entries, _ := os.ReadDir(outside); len(entries) != 0 {
				t.Errorf("files were written outside the deploy root: %v", entries)
			}
		})
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}
}

func TestMaterializeScriptRejectsStreamsTheEncoderWouldNotProduce(t *testing.T) {
	tests := map[string]string{
		"traversal":        "1 secrets/../x.env\nx",
		"outside secrets":  "1 evil.sh\nx",
		"absolute path":    "1 /etc/cron.d/x\nx",
		"hidden env file":  "1 secrets/.env\nx",
		"dash env file":    "1 secrets/-x.env\nx",
		"non numeric size": "abc compose.yaml\nx",
		"negative size":    "-1 compose.yaml\nx",
		"huge size":        "99999999 compose.yaml\nx",
		"truncated body":   "10 compose.yaml\nshort",
		"no compose.yaml":  "1 secrets/a.env\nx",
		"empty stream":     "",
	}
	for name, stream := range tests {
		t.Run(name, func(t *testing.T) {
			root := physicalTempDir(t)
			if res := materialize(t, root, []byte(stream)); res.err == nil {
				t.Fatalf("accepted %q", stream)
			}
			if _, err := os.Stat(filepath.Join(root, "x.env")); err == nil {
				t.Error("a file escaped the deployment directory")
			}
		})
	}
}

const verifyConfig = `{"name":"shop","services":{
 "api":{"image":"r/api@sha256:aa","command":["run"],"environment":{"TOKEN":"p$$ss ${W}$$","EMPTY":"","MODE":"prod"}},
 "worker":{"image":"r/w@sha256:bb"},
 "db":{"image":"r/db@sha256:cc","environment":{"NOVALUE":null}}}}`

func runVerify(t *testing.T, cfg string, dockerBody string) scriptResult {
	t.Helper()
	requireTools(t, "bash", "jq", "base64")
	cfgPath := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	shims := sha256Shim()
	if shims == nil {
		shims = map[string]string{}
	}
	shims["docker"] = dockerBody
	return script{
		interpreter: "bash", text: verifyScript, pathShims: shims, env: []string{"CFG=" + cfgPath},
		args: []string{"/srv/supermgmt", "sm-shop-prod", testDeployment},
	}.run(t)
}

func TestVerifyPrintsTheMaskedModelAndTheResolvedHashSetOnly(t *testing.T) {
	res := runVerify(t, verifyConfig, `cat "$CFG"`)
	if res.err != nil {
		t.Fatalf("%v: %s", res.err, res.stderr)
	}
	var out struct {
		Model struct {
			Services map[string]struct {
				Image       string
				Command     []string
				Environment map[string]*string
			}
		}
		Set []struct {
			Service string  `json:"service"`
			Env     string  `json:"env_name"`
			SHA256  *string `json:"sha256"`
		}
	}
	if err := json.Unmarshal([]byte(res.stdout), &out); err != nil {
		t.Fatalf("output is not one JSON document: %v\n%s", err, res.stdout)
	}
	// "p$$ss ${W}$$" in `config` output is the value `p$ss ${W}$`.
	want := map[string]string{
		"api/TOKEN": sha256Hex(`p$ss ${W}$`), "api/EMPTY": sha256Hex(""), "api/MODE": sha256Hex("prod"),
	}
	got := map[string]string{}
	for _, e := range out.Set {
		if e.SHA256 == nil {
			got[e.Service+"/"+e.Env] = "null"
		} else {
			got[e.Service+"/"+e.Env] = *e.SHA256
		}
	}
	want["db/NOVALUE"] = "null"
	if len(got) != len(want) {
		t.Fatalf("set = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("set[%s] = %s, want %s", k, got[k], v)
		}
	}
	api := out.Model.Services["api"]
	if tok := api.Environment["TOKEN"]; tok == nil || *tok != "sha256:"+want["api/TOKEN"] {
		t.Errorf("masked TOKEN = %v", tok)
	}
	if api.Image != "r/api@sha256:aa" || len(api.Command) != 1 || api.Command[0] != "run" {
		t.Errorf("non-environment fields changed: %+v", api)
	}
	if _, invented := out.Model.Services["worker"]; !invented || out.Model.Services["worker"].Environment != nil {
		t.Errorf("service without environment: %+v", out.Model.Services["worker"])
	}
	for _, plaintext := range []string{"p$ss", "p$$ss", "${W}", "prod"} {
		if strings.Contains(res.stdout, plaintext) {
			t.Errorf("output contains the value %q", plaintext)
		}
	}
}

func TestVerifyFailureNeverEchoesComposeDiagnostics(t *testing.T) {
	res := runVerify(t, verifyConfig, `echo "invalid env line: TOKEN=hunter2" >&2; exit 1`)
	if res.err == nil {
		t.Fatal("verify succeeded although compose failed")
	}
	if strings.Contains(res.stdout+res.stderr, "hunter2") {
		t.Errorf("a value reached the output: %q %q", res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Errorf("stdout = %q, want empty", res.stdout)
	}
}

func TestVerifyRefusesAConfigItCannotRead(t *testing.T) {
	if res := runVerify(t, "not json", `cat "$CFG"`); res.err == nil {
		t.Fatal("verify succeeded on a config that is not JSON")
	}
}

func TestVerifyRunsOnlyUnderTheFixedEnvironment(t *testing.T) {
	c, err := Render("compose.verify", deployArgs("/srv/supermgmt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Line, "env -i PATH=/usr/local/bin:/usr/bin:/bin bash -c '") {
		t.Errorf("line does not start with env -i and the fixed PATH: %.80s", c.Line)
	}
	if !strings.HasSuffix(c.Line, " bash '/srv/supermgmt' 'sm-shop-prod' '"+testDeployment+"'") {
		t.Errorf("line does not end with the quoted directory arguments: %s", c.Line[max(0, len(c.Line)-90):])
	}
	if strings.Contains(c.Line, "--no-env-resolution") {
		t.Error("verify must resolve the environment")
	}
}

const (
	singleManifest = `{"Ref":"r/a@sha256:x","Descriptor":{"platform":{"architecture":"arm64","os":"linux"}},"SchemaV2Manifest":{"config":{"size":477},"layers":[{"size":1977510}]}}`
	otherPlatform  = `{"Descriptor":{"platform":{"architecture":"amd64","os":"linux"}},"SchemaV2Manifest":{"config":{"size":1},"layers":[{"size":2}]}}`
)

func imageSize(t *testing.T, manifest string, dockerFails bool) scriptResult {
	t.Helper()
	requireTools(t, "bash", "jq")
	docker := `case "$*" in
*Server.Os*) echo linux;;
*Server.Arch*) echo arm64;;
*"manifest inspect"*) if [ -n "$FAIL" ]; then echo "no such manifest" >&2; exit 1; fi; printf '%s' "$MANIFEST";;
esac`
	env := []string{"MANIFEST=" + manifest}
	if dockerFails {
		env = append(env, "FAIL=1")
	}
	return script{
		interpreter: "bash", text: strings.NewReplacer(
			"@OS@", goTemplateArg("{{.Server.Os}}"), "@ARCH@", goTemplateArg("{{.Server.Arch}}"),
		).Replace(imageSizeScript),
		pathShims: map[string]string{"docker": docker}, env: env, args: []string{"r/a@sha256:" + strings.Repeat("a", 64)},
	}.run(t)
}

func TestImageSizeSumsConfigAndLayersOfTheNodePlatform(t *testing.T) {
	for name, manifest := range map[string]string{
		"single manifest":   singleManifest,
		"index of two":      "[" + otherPlatform + "," + singleManifest + "]",
		"layerless config":  `{"Descriptor":{"platform":{"architecture":"arm64","os":"linux"}},"SchemaV2Manifest":{"config":{"size":477},"layers":[]}}`,
		"OCI manifest form": `{"Descriptor":{"platform":{"architecture":"arm64","os":"linux"}},"OCIManifest":{"config":{"size":477},"layers":[{"size":1977510}]}}`,
	} {
		res := imageSize(t, manifest, false)
		if res.err != nil {
			t.Errorf("%s: %v %s", name, res.err, res.stderr)
			continue
		}
		n, err := ParseImageSize([]byte(res.stdout))
		want := int64(477 + 1977510)
		if name == "layerless config" {
			want = 477
		}
		if err != nil || n != want {
			t.Errorf("%s: size = %d (%v), want %d", name, n, err, want)
		}
	}
}

func TestImageSizeFailsClosedWhenItCannotBeEstablished(t *testing.T) {
	tests := map[string]struct {
		manifest string
		fails    bool
	}{
		"registry error":              {singleManifest, true},
		"no platform match":           {"[" + otherPlatform + "]", false},
		"two entries of one platform": {"[" + singleManifest + "," + singleManifest + "]", false},
		"not JSON":                    {"garbage", false},
	}
	for name, tc := range tests {
		if res := imageSize(t, tc.manifest, tc.fails); res.err == nil {
			t.Errorf("%s: succeeded with %q", name, res.stdout)
		}
	}
}

func TestParseImageSizeIsStrict(t *testing.T) {
	for _, bad := range []string{"", "abc", "-1", "01", "1.5", "1 2", "1\n2"} {
		if _, err := ParseImageSize([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if n, err := ParseImageSize([]byte("1977987\n")); err != nil || n != 1977987 {
		t.Errorf("got %d, %v", n, err)
	}
}

func dump(t *testing.T, dir, dockerBody string) scriptResult {
	t.Helper()
	return script{
		interpreter: "sh", text: postgresDumpScript(dir), args: []string{"db", "app"},
		pathShims: map[string]string{"docker": dockerBody},
	}.run(t)
}

func TestPostgresDumpPrintsTheArtifactPathAsItsLastLine(t *testing.T) {
	dir := filepath.Join(physicalTempDir(t), "db-backups")
	res := dump(t, dir, `echo "pg_dump: warning" >&2; printf DUMPDATA`)
	if res.err != nil {
		t.Fatalf("%v: %s", res.err, res.stderr)
	}
	lines := strings.Split(strings.TrimSuffix(res.stdout, "\n"), "\n")
	path := lines[len(lines)-1]
	if filepath.Dir(path) != dir || !strings.HasPrefix(filepath.Base(path), "app-") || !strings.HasSuffix(path, ".dump") {
		t.Fatalf("artifact path = %q", path)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "DUMPDATA" {
		t.Errorf("artifact = %q (%v)", got, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("artifact mode = %v", info.Mode().Perm())
	}
}

func TestPostgresDumpFailureLeavesNoArtifactAndKeepsTheExitStatus(t *testing.T) {
	dir := filepath.Join(physicalTempDir(t), "db-backups")
	res := dump(t, dir, `printf PARTIAL; exit 7`)
	var exit *exec.ExitError
	if !errors.As(res.err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("err = %v, want exit status 7", res.err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a partial artifact was left behind: %v", entries)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestPostgresDumpRefusesASymlinkedBackupDirectory(t *testing.T) {
	base, outside := physicalTempDir(t), physicalTempDir(t)
	mustSymlink(t, outside, filepath.Join(base, "db-backups"))
	if res := dump(t, filepath.Join(base, "db-backups"), `printf X`); res.err == nil {
		t.Fatal("dump followed a symlinked backup directory")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("files written outside: %v", entries)
	}
}

func TestBackupPathsAreAcceptedOnlyInsideTheBackupDirectory(t *testing.T) {
	ok := BackupDir + "/app-20260101T000000Z-123.dump"
	if got, err := ParseBackupPath([]byte("pg_dump: noise\n" + ok + "\n")); err != nil || got != ok {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{
		"", "relative/app.dump", "/etc/passwd", BackupDir + "/../x.dump", BackupDir + "/sub/app.dump",
		BackupDir + "/app.sql", BackupDir + "/.dump", BackupDir + "x/app.dump", BackupDir + "/a b.dump",
	} {
		if _, err := ParseBackupPath([]byte("noise\n" + bad + "\n")); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestStageTemplatesRenderTheirGoldenLines(t *testing.T) {
	image := "ghcr.io/acme/api@sha256:" + strings.Repeat("a", 64)
	reads := map[string]struct {
		args map[string]string
		line string
	}{
		"compose.disk_free":          {map[string]string{"path": "/srv/supermgmt"}, "df -PB1 '/srv/supermgmt'"},
		"compose.docker_root":        {nil, `docker info --format "$(printf '\173\173.DockerRootDir\175\175')"`},
		"compose.image_inspect":      {map[string]string{"image": image}, "docker image inspect '" + image + "'"},
		"compose.listeners":          {nil, "ss -H -ltn && ss -H -lun"},
		"compose.project_containers": {map[string]string{"project": "sm-shop-prod"}, `ids=$(docker ps -aq --no-trunc --filter label=com.docker.compose.project='sm-shop-prod') && { [ -z "$ids" ] || docker inspect --type container $ids; }`},
	}
	for name, tc := range reads {
		c, err := Render(name, tc.args)
		if err != nil || c.Line != tc.line || c.Mutating {
			t.Errorf("%s: %q (%v), want %q", name, c.Line, err, tc.line)
		}
	}
	c, err := RenderMutatingInput("compose.pull", "m1", map[string]string{"image": image}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	want := ": > /var/lib/supermgmt/markers/m1 && { timeout --kill-after=10s 900s docker pull --quiet '" + image + "'; rc=$?; " +
		`printf '%d\n' "$rc" > /var/lib/supermgmt/markers/m1.done.tmp && mv -f /var/lib/supermgmt/markers/m1.done.tmp /var/lib/supermgmt/markers/m1.done; exit "$rc"; }`
	if c.Line != want {
		t.Errorf("compose.pull\n got %s\nwant %s", c.Line, want)
	}
}

func TestMaterializeKeepsSecretsOffTheCommandLineAndFlagsThemSensitive(t *testing.T) {
	stdin := mustEncode(t, StagedFile{"compose.yaml", []byte("x")}, StagedFile{"secrets/api.env", []byte("TOKEN=hunter2")})
	c, err := RenderMutatingInput("compose.materialize", "m1", deployArgs("/srv/supermgmt"), stdin, "")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Sensitive || !c.Mutating || !bytes.Equal(c.Stdin, stdin) {
		t.Errorf("command = %+v", c)
	}
	if strings.Contains(c.Line, "hunter2") || strings.Contains(c.Line, "TOKEN") {
		t.Errorf("secret content reached the command line: %s", c.Line)
	}
	if strings.Contains(c.Line, "flock") {
		t.Error("materialize runs in a fresh directory and takes no project lock")
	}
}

func projectResources(t *testing.T, dockerBody string) scriptResult {
	t.Helper()
	requireTools(t, "bash")
	return script{
		interpreter: "bash", text: strings.ReplaceAll(projectResourcesScript, "@JSON@", "JSON"),
		pathShims: map[string]string{"docker": dockerBody}, args: []string{"sm-shop-prod"},
	}.run(t)
}

func TestProjectResourcesListsLabelledAndPrefixedVolumesAndNetworks(t *testing.T) {
	docker := `case "$1 $2" in
"volume ls") case "$*" in
  *label=com.docker.compose.project=sm-shop-prod*) echo sm-shop-prod_data; echo custom-name;;
  *name=sm-shop-prod_*) echo sm-shop-prod_data; echo sm-shop-prod_cache;;
  esac;;
"network ls") case "$*" in *name=sm-shop-prod_*) echo net1;; esac;;
*" inspect") kind=$1; shift 2; echo "$kind inspected: $*";;
esac`
	res := projectResources(t, docker)
	if res.err != nil {
		t.Fatalf("%v %s", res.err, res.stderr)
	}
	want := "volume inspected: --format volume JSON custom-name sm-shop-prod_cache sm-shop-prod_data\n" +
		"network inspected: --format network JSON net1\n"
	if res.stdout != want {
		t.Errorf("stdout =\n%s\nwant\n%s", res.stdout, want)
	}
}

func TestProjectResourcesPrintsNothingWhenThereAreNone(t *testing.T) {
	res := projectResources(t, `exit 0`)
	if res.err != nil || res.stdout != "" {
		t.Errorf("stdout = %q, err = %v", res.stdout, res.err)
	}
}

func TestProjectResourcesFailsWhenDockerFails(t *testing.T) {
	if res := projectResources(t, `echo boom >&2; exit 1`); res.err == nil {
		t.Errorf("succeeded with %q", res.stdout)
	}
}

func TestProjectResourcesRendersWithoutLiteralBracesAndRefusesBadProjects(t *testing.T) {
	c, err := Render("compose.project_resources", map[string]string{"project": "sm-shop-prod"})
	if err != nil || c.Mutating || !strings.Contains(c.Line, `\173\173json .\175\175`) || !strings.HasSuffix(c.Line, " bash 'sm-shop-prod'") {
		t.Errorf("line = %q (%v)", c.Line, err)
	}
	if _, err := Render("compose.project_resources", map[string]string{"project": "x; rm -rf /"}); err == nil {
		t.Error("an invalid project name rendered")
	}
}
