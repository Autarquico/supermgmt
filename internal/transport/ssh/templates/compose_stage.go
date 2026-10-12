package templates

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FixedPath is the PATH every deployment command runs with (`env -i`): the
// result of a command never depends on the login environment of the node
// user (spec §20.3 step 10).
const FixedPath = "/usr/local/bin:/usr/bin:/bin"

const composeEnv = "env -i PATH=" + FixedPath + " "

// deployDirectory is <deploy_root>/<project>/<deployment_id> built from three
// separately validated parameters (spec §20.3 step 9).
const deployDirectory = "{{root}}/{{project}}/{{deployment}}"

// BackupDir is the node directory postgres-dump writes to; the artifact path
// it prints always lies directly inside it (ADR-0029).
const BackupDir = HomeDir + "/db-backups"

var (
	projectPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	deploymentPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	imagePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}$`)
	pathPattern       = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)
	databasePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
	backupPathPattern = regexp.MustCompile(`^` + regexp.QuoteMeta(BackupDir) + `/[A-Za-z0-9][A-Za-z0-9._-]*\.dump$`)
	serviceFilePart   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
)

// ValidateCleanPath accepts a clean absolute path of safe characters: no
// ".", ".." or empty element, so it names exactly one location.
func ValidateCleanPath(s string) error {
	if len(s) > 255 || !pathPattern.MatchString(s) || path.Clean(s) != s {
		return fmt.Errorf("not a clean absolute path of [A-Za-z0-9._/-]")
	}
	return nil
}

// ValidateDeployRoot accepts a node.setup deploy_root: a clean absolute path
// other than "/" (ADR-0030).
func ValidateDeployRoot(s string) error {
	if err := ValidateCleanPath(s); err != nil {
		return err
	}
	if s == "/" {
		return fmt.Errorf("the filesystem root is not a deploy root")
	}
	return nil
}

// ValidateBackupPath accepts the artifact path a postgres-dump prints: a
// .dump file directly inside BackupDir.
func ValidateBackupPath(s string) error {
	if !backupPathPattern.MatchString(s) || strings.Contains(s, "..") {
		return fmt.Errorf("not a backup artifact inside %s", BackupDir)
	}
	return nil
}

var (
	paramRoot       = Param{Name: "root", Validate: ValidateDeployRoot}
	paramProject    = Param{Name: "project", Validate: Matching(projectPattern)}
	paramDeployment = Param{Name: "deployment", Validate: Matching(deploymentPattern)}
	paramImage      = Param{Name: "image", Validate: Matching(imagePattern)}
	paramDiskPath   = Param{Name: "path", Validate: ValidateCleanPath}
	paramDatabase   = Param{Name: "database", Validate: Matching(databasePattern)}

	deployDirectoryParams = []Param{paramRoot, paramProject, paramDeployment}
)

// goTemplateArg renders a Docker --format argument. Catalog bodies reserve
// "{{" for parameters, so the braces are written as printf octal escapes.
func goTemplateArg(tmpl string) string {
	escaped := strings.NewReplacer("{{", `\173\173`, "}}", `\175\175`).Replace(tmpl)
	return `"$(printf '` + escaped + `')"`
}

// shellScript is a fixed script run by `sh -c`; its arguments are the
// template's parameters, passed as $1, $2, ... so no value is ever parsed as
// shell text.
func shellScript(interpreter, script string, params ...string) string {
	body := interpreter + " -c " + Quote(script) + " " + interpreter
	for _, p := range params {
		body += " {{" + p + "}}"
	}
	return body
}

// MaterializeLimit is the largest single file a materialization carries.
const MaterializeLimit = 1 << 20

// StagedFile is one file of a materialized deployment directory: the
// compose.yaml or secrets/<service>.env (spec §20.3 step 9).
type StagedFile struct {
	Path    string
	Content []byte
}

// EncodeMaterialization frames files for the compose.materialize template:
// per file one header line "<size> <path>\n" followed by exactly size bytes.
// The node script re-validates every path and decides every mode; the
// encoder refuses what the script would refuse.
func EncodeMaterialization(files []StagedFile) ([]byte, error) {
	var out bytes.Buffer
	seen := map[string]bool{}
	for _, f := range files {
		if err := validateStagedPath(f.Path); err != nil {
			return nil, fmt.Errorf("staged file %q: %w", f.Path, err)
		}
		if seen[f.Path] {
			return nil, fmt.Errorf("staged file %q: duplicated", f.Path)
		}
		seen[f.Path] = true
		if len(f.Content) > MaterializeLimit {
			return nil, fmt.Errorf("staged file %q: larger than %d bytes", f.Path, MaterializeLimit)
		}
		fmt.Fprintf(&out, "%d %s\n", len(f.Content), f.Path)
		out.Write(f.Content)
	}
	if !seen["compose.yaml"] {
		return nil, fmt.Errorf("compose.yaml is missing")
	}
	return out.Bytes(), nil
}

func validateStagedPath(p string) error {
	if p == "compose.yaml" {
		return nil
	}
	name, ok := strings.CutPrefix(p, "secrets/")
	name, isEnv := strings.CutSuffix(name, ".env")
	if !ok || !isEnv || !serviceFilePart.MatchString(name) {
		return fmt.Errorf("only compose.yaml and secrets/<service>.env are allowed")
	}
	return nil
}

// materializeScript reads each body with dd bs=1: unlike head -c, it never
// reads past the requested bytes on any implementation, and the stream holds
// the next header right behind the body.
//
// It creates the deployment directory (it must not exist) and
// writes the framed files into it. Every path component below the deploy root
// is checked for symlinks, files are created with O_EXCL (noclobber), and the
// byte count of each file is verified.
const materializeScript = `
umask 077
fail() { echo "compose.materialize: $1" >&2; exit 1; }
root=$1; project=$root/$2; dir=$project/$3
[ -d "$root" ] && [ ! -L "$root" ] || fail "deploy root is not a plain directory"
if [ ! -e "$project" ] && [ ! -L "$project" ]; then mkdir -m 0750 -- "$project" || fail "cannot create the project directory"; fi
[ -d "$project" ] && [ ! -L "$project" ] || fail "project directory is not a plain directory"
mkdir -m 0750 -- "$dir" || fail "deployment directory exists or cannot be created"
mkdir -m 0700 -- "$dir/secrets" || fail "cannot create secrets directory"
while read -r size rel; do
  case $size in ''|*[!0-9]*) fail "bad size";; esac
  [ "${#size}" -le 7 ] || fail "bad size"
  case $rel in
    compose.yaml) mode=0640;;
    secrets/*.env)
      name=${rel#secrets/}; name=${name%.env}
      case $name in ''|-*|.*|*[!A-Za-z0-9_.-]*) fail "bad file name";; esac
      mode=0600;;
    *) fail "bad file name";;
  esac
  file=$dir/$rel
  ( set -C; dd bs=1 count="$size" 2>/dev/null > "$file" ) || fail "cannot create $rel"
  [ "$(wc -c < "$file" | tr -d ' ')" = "$size" ] || fail "truncated input for $rel"
  chmod "$mode" "$file" || fail "cannot set the mode of $rel"
done
[ -f "$dir/compose.yaml" ] || fail "compose.yaml was not provided"
`

// The jq programs of the resolved-environment check (ADR-0010). jq has no
// sha256, so a bash loop hashes each base64-decoded value.
const (
	jqEnvRows = `.services | to_entries[] | .key as $s | (.value.environment // {}) | to_entries[]
 | [$s, .key, (if .value == null then "n" else "s" end), ((.value // "") | gsub("\\$\\$"; "$") | @base64)] | @tsv`

	jqHashSet = `[inputs | select(length > 0) | split("\t")
 | {service: .[0], env_name: .[1], sha256: (if .[2] == "null" then null else .[2] end)}]`

	jqMaskModel = `($h | map({key: (.service + "/" + .env_name), value: .sha256}) | from_entries) as $m
 | .services |= with_entries(.key as $s
     | if .value.environment
       then .value.environment |= with_entries(.value = (if .value == null then null else "sha256:" + $m[$s + "/" + .key] end))
       else . end)`
)

// verifyScript prints one line {"model": <masked model>, "set": [{service,
// env_name, sha256}]} and nothing else: values never leave the node, and
// compose's own diagnostics are discarded because they may quote them.
const verifyScript = `set -euo pipefail
dir="$1/$2/$3"
fail() { echo "compose.verify: $1" >&2; exit 1; }
cfg=$(docker compose -f "$dir/compose.yaml" -p "$2" --project-directory "$dir" config --format json 2>/dev/null) || fail "docker compose config failed"
rows=$(printf '%s' "$cfg" | jq -r '` + jqEnvRows + `') || fail "cannot read the environment"
hashes=$(printf '%s\n' "$rows" | while IFS=$'\t' read -r s n k b; do
  [ -n "$s" ] || continue
  if [ "$k" = n ]; then h=null; else h=$(printf %s "$b" | base64 -d | sha256sum | cut -d' ' -f1); fi
  printf '%s\t%s\t%s\n' "$s" "$n" "$h"
done) || fail "cannot hash the environment"
set_json=$(printf '%s\n' "$hashes" | jq -Rn -c '` + jqHashSet + `') || fail "cannot build the hash set"
printf '%s' "$cfg" | jq -c --argjson h "$set_json" '{model: (` + jqMaskModel + `), set: $h}' || fail "cannot mask the model"
`

// imageSizeScript prints the bytes (config + layers) of the manifest for the
// node's platform; it fails when that cannot be established (fail closed).
const imageSizeScript = `set -euo pipefail
os=$(docker version --format ` + `@OS@` + `)
arch=$(docker version --format ` + `@ARCH@` + `)
docker manifest inspect --verbose "$1" | jq -e --arg os "$os" --arg arch "$arch" '
  (if type == "array" then . else [.] end)
  | map(select(.Descriptor.platform.os == $os and .Descriptor.platform.architecture == $arch))
  | if length == 1 then .[0] | (.SchemaV2Manifest // .OCIManifest) | (.config.size + ([.layers[].size] | add // 0)) else error("no unique platform match") end'
`

func imageSizeBody() string {
	script := strings.NewReplacer(
		"@OS@", goTemplateArg("{{.Server.Os}}"),
		"@ARCH@", goTemplateArg("{{.Server.Arch}}"),
	).Replace(imageSizeScript)
	return shellScript("bash", script, "image")
}

// postgresDumpScript dumps one database of a running container into dir and
// prints the artifact path as its last line (spec §19.1).
func postgresDumpScript(dir string) string {
	return strings.ReplaceAll(`set -eu
umask 077
dir=@DIR@
fail() { echo "postgres-dump: $1" >&2; exit 1; }
[ ! -L "$dir" ] || fail "backup directory is a symlink"
mkdir -p -m 0700 -- "$dir"
file="$dir/$2-$(date -u +%Y%m%dT%H%M%SZ)-$$.dump"
set -C
rc=0
docker exec "$1" sh -c 'exec pg_dump --format=custom --username="${POSTGRES_USER:-postgres}" --dbname="$1"' sh "$2" > "$file" || rc=$?
if [ "$rc" -ne 0 ]; then rm -f -- "$file"; exit "$rc"; fi
printf '%s\n' "$file"
`, "@DIR@", Quote(dir))
}

const (
	stageDeadline       = time.Minute
	pullDeadline        = 15 * time.Minute
	backupDeadlineLimit = time.Hour
)

// composeStageTemplates holds the preflight reads, the staging steps and the
// pre-deploy backup of a deployment (spec §20.2, §20.3, ADR-0029).
var composeStageTemplates = []Template{
	{
		Name: "compose.docker_root", MaxBytes: 4 << 10, MaxLines: 5,
		Body: "docker info --format " + goTemplateArg("{{.DockerRootDir}}"),
	},
	{
		Name: "compose.disk_free", Params: []Param{paramDiskPath}, MaxBytes: 4 << 10, MaxLines: 5,
		Body: "df -PB1 {{path}}",
	},
	{
		Name: "compose.image_size", Params: []Param{paramImage}, MaxBytes: 4 << 10, MaxLines: 5,
		Body: imageSizeBody(),
	},
	{
		Name: "compose.image_inspect", Params: []Param{paramImage}, MaxBytes: 1 << 20,
		Body: "docker image inspect {{image}}",
	},
	{
		Name: "compose.project_containers", Params: []Param{paramProject}, MaxBytes: 8 << 20,
		Body: `ids=$(docker ps -aq --no-trunc --filter label=com.docker.compose.project={{project}}) && { [ -z "$ids" ] || docker inspect --type container $ids; }`,
	},
	{
		Name: "compose.listeners", MaxBytes: 1 << 20, MaxLines: 20000,
		Body: "ss -H -ltn",
	},
	{
		Name: "compose.pull", Params: []Param{paramImage}, Mutating: true, Deadline: pullDeadline,
		MaxBytes: 64 << 10, MaxLines: 500,
		Body: "docker pull --quiet {{image}}",
	},
	{
		Name: "compose.materialize", Params: deployDirectoryParams, Mutating: true, Sensitive: true,
		Deadline: stageDeadline, MaxBytes: 4 << 10, MaxLines: 20,
		Body: shellScript("sh", materializeScript, "root", "project", "deployment"),
	},
	{
		Name: "compose.verify", Params: deployDirectoryParams, MaxBytes: 8 << 20, MaxLines: 5,
		Body: composeEnv + shellScript("bash", verifyScript, "root", "project", "deployment"),
	},
	{
		// The policy timeout is enforced by the caller; the node-side deadline is
		// only the outer bound.
		Name: "postgres-dump", Params: []Param{{Name: "container", Validate: ValidateContainer}, paramDatabase},
		Mutating: true, Deadline: backupDeadlineLimit, MaxBytes: 64 << 10, MaxLines: 100,
		Body: shellScript("sh", postgresDumpScript(BackupDir), "container", "database"),
	},
}

// ParseImageSize parses the output of compose.image_size: one decimal number.
func ParseImageSize(stdout []byte) (int64, error) {
	line := strings.TrimSuffix(string(stdout), "\n")
	n, err := strconv.ParseInt(line, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != line {
		return 0, fmt.Errorf("unrecognized image size %q", line)
	}
	return n, nil
}

// ParseBackupPath returns the artifact path on the last stdout line of a
// postgres-dump, refusing anything outside BackupDir.
func ParseBackupPath(stdout []byte) (string, error) {
	lines := strings.Split(strings.TrimSuffix(string(stdout), "\n"), "\n")
	last := lines[len(lines)-1]
	if err := ValidateBackupPath(last); err != nil {
		return "", fmt.Errorf("backup path: %w", err)
	}
	return last, nil
}
