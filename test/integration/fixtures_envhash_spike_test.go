//go:build fixtures

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// Spike for ADR-0010 (resolved-environment hash check, Q12) and ADR-0029
// (image-size source, Q14). The shell/jq pipeline below is the candidate body
// of the `compose.verify` and `compose.image_size` templates; values are
// hashed on the node and only hashes plus the masked model leave it.

// jqEnvRows prints one `service<TAB>name<TAB>kind<TAB>base64(value)` row per
// environment entry of `config --format json`. kind is `n` for a name with no
// value (unresolved), `s` otherwise. `config` escapes every `$` as `$$`; the
// gsub undoes it so the hash is over the value Compose hands the container.
const jqEnvRows = `.services | to_entries[] | .key as $s | (.value.environment // {}) | to_entries[]
 | [$s, .key, (if .value == null then "n" else "s" end), ((.value // "") | gsub("\\$\\$"; "$") | @base64)] | @tsv`

// jqHashSet turns `service<TAB>name<TAB>sha256|null` lines into the hash set.
const jqHashSet = `[inputs | select(length > 0) | split("\t")
 | {service: .[0], env_name: .[1], sha256: (if .[2] == "null" then null else .[2] end)}]`

// jqMaskModel replaces every environment value of the model by sha256:<hex>.
const jqMaskModel = `($h | map({key: (.service + "/" + .env_name), value: .sha256}) | from_entries) as $m
 | .services |= with_entries(.key as $s
     | if .value.environment
       then .value.environment |= with_entries(.value = (if .value == null then null else "sha256:" + $m[$s + "/" + .key] end))
       else . end)`

// verifyScript is the node-side program: resolve with environment resolution
// under `env -i` (done by the caller), hash, mask. Output: {"model","set"}.
const verifyScript = `set -euo pipefail
cfg=$(docker compose -f "$1/compose.yaml" -p spike --project-directory "$1" config --format json)
rows=$(printf '%s' "$cfg" | jq -r '` + jqEnvRows + `')
hashes=$(printf '%s\n' "$rows" | while IFS=$'\t' read -r s n k b; do
  [ -n "$s" ] || continue
  if [ "$k" = n ]; then h=null; else h=$(printf %s "$b" | base64 -d | sha256sum | cut -d' ' -f1); fi
  printf '%s\t%s\t%s\n' "$s" "$n" "$h"
done)
set_json=$(printf '%s\n' "$hashes" | jq -Rn -c '` + jqHashSet + `')
printf '%s' "$cfg" | jq -c --argjson h "$set_json" '{model: (` + jqMaskModel + `), set: $h}'
`

type envHash struct {
	Service string  `json:"service"`
	EnvName string  `json:"env_name"`
	SHA256  *string `json:"sha256"`
}

type verifyResult struct {
	Model json.RawMessage `json:"model"`
	Set   []envHash       `json:"set"`
}

func sum(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }

// expectedHashes is what the control plane computes in memory: service/name -> sha256.
func expectedHashes(resolved map[string]map[string]string) map[string]string {
	out := map[string]string{}
	for svc, env := range resolved {
		for name, v := range env {
			out[svc+"/"+name] = sum(v)
		}
	}
	return out
}

func hashSetOf(t *testing.T, r verifyResult) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range r.Set {
		if h.SHA256 == nil {
			out[h.Service+"/"+h.EnvName] = "null"
			continue
		}
		out[h.Service+"/"+h.EnvName] = *h.SHA256
	}
	return out
}

// runVerify writes the project into dir and runs verifyScript under env -i.
func runVerify(t *testing.T, n *fixtureNode, dir, compose string, envFiles map[string][]byte) verifyResult {
	t.Helper()
	n.shell(t, "rm -rf "+dir)
	writeNodeFile(t, n, dir+"/compose.yaml", []byte(compose))
	for name, data := range envFiles {
		writeNodeFile(t, n, dir+"/secrets/"+name, data)
	}
	writeNodeFile(t, n, "/srv/verify.sh", []byte(verifyScript))
	out, err := n.Exec(t.Context(), "env", "-i", "PATH="+nodePath, "bash", "-c", `bash /srv/verify.sh "$0" 2>/srv/verify.err || { cat /srv/verify.err; exit 1; }`, dir)
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	var r verifyResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &r); err != nil {
		t.Fatalf("verify output is not JSON: %v\n%s", err, out)
	}
	return r
}

const spikeCompose = `name: spike
services:
  api:
    image: ` + busyboxImage + `
    environment:
      PLAIN: "plain value"
      OVERRIDE: "from-environment"
      EMPTY: ""
      DOLLAR: "p$$q"
    env_file:
      - path: secrets/api.env
        format: raw
        required: true
  worker:
    image: ` + busyboxImage + `
    env_file:
      - path: secrets/worker.env
        format: raw
        required: true
`

var (
	apiEnv = []envPair{
		{"SECRET_DOLLAR", `s$ecret${X}$$`},
		{"SECRET_SPACES", `  padded value  `},
		{"SECRET_EMPTY", ``},
		{"OVERRIDE", `from-file-loses`},
		{"SECRET_QUOTES", `"a" 'b' #c`},
	}
	workerEnv = []envPair{{"WORKER_TOKEN", `w=o=r=k`}}
)

func spikeExpected() map[string]map[string]string {
	return map[string]map[string]string{
		"api": {
			"PLAIN": "plain value", "OVERRIDE": "from-environment", "EMPTY": "", "DOLLAR": "p$q",
			"SECRET_DOLLAR": `s$ecret${X}$$`, "SECRET_SPACES": `  padded value  `, "SECRET_EMPTY": ``,
			"SECRET_QUOTES": `"a" 'b' #c`,
		},
		"worker": {"WORKER_TOKEN": `w=o=r=k`},
	}
}

func spikeFiles() map[string][]byte {
	return map[string][]byte{"api.env": rawEnvFile(apiEnv), "worker.env": rawEnvFile(workerEnv)}
}

func TestFixtures_EnvHashResolvedPrecedenceAndTamper(t *testing.T) {
	n := startNode(t, fixture.Options{})
	const dir = "/srv/spike"
	want := expectedHashes(spikeExpected())

	t.Run("hash set equals the expected resolved values", func(t *testing.T) {
		r := runVerify(t, n, dir, spikeCompose, spikeFiles())
		got := hashSetOf(t, r)
		if !maps.Equal(got, want) {
			t.Errorf("hash set mismatch\n got: %v\nwant: %v", got, want)
		}
		if len(r.Set) != len(want) {
			t.Errorf("set has %d rows; want %d", len(r.Set), len(want))
		}
	})

	t.Run("masked model carries hashes and no plaintext", func(t *testing.T) {
		r := runVerify(t, n, dir, spikeCompose, spikeFiles())
		model := string(r.Model)
		for svc, env := range spikeExpected() {
			for name, v := range env {
				if v != "" && len(v) > 3 && strings.Contains(model, v) {
					t.Errorf("%s/%s: masked model leaks %q", svc, name, v)
				}
				if !strings.Contains(model, `"`+name+`":"sha256:`+sum(v)+`"`) {
					t.Errorf("%s/%s: masked model lacks sha256:%s", svc, name, sum(v))
				}
			}
		}
	})

	t.Run("environment beats env_file: dropping the override changes its hash", func(t *testing.T) {
		tampered := strings.Replace(spikeCompose, "      OVERRIDE: \"from-environment\"\n", "", 1)
		got := hashSetOf(t, runVerify(t, n, dir, tampered, spikeFiles()))
		if got["api/OVERRIDE"] != sum("from-file-loses") {
			t.Errorf("api/OVERRIDE = %s; want the env_file value hash", got["api/OVERRIDE"])
		}
		if got["api/OVERRIDE"] == want["api/OVERRIDE"] {
			t.Error("tampered wiring produced the expected hash")
		}
	})

	t.Run("wiring tamper is detected", func(t *testing.T) {
		cases := []struct {
			name    string
			compose string
			files   map[string][]byte
			diff    string
		}{
			{"changed secret value", spikeCompose, withFile(spikeFiles(), "worker.env", rawEnvFile([]envPair{{"WORKER_TOKEN", "w=o=r=K"}})), "worker/WORKER_TOKEN"},
			{"extra name in env file", spikeCompose, withFile(spikeFiles(), "worker.env", rawEnvFile(append([]envPair{{"EXTRA", "x"}}, workerEnv...))), "worker/EXTRA"},
			{"missing name in env file", spikeCompose, withFile(spikeFiles(), "worker.env", []byte{}), "worker/WORKER_TOKEN"},
			{"env_file swapped between services", strings.Replace(strings.Replace(spikeCompose, "secrets/api.env", "secrets/TMP", 1), "secrets/worker.env", "secrets/api.env", 1), spikeFiles(), "api/WORKER_TOKEN"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				compose := strings.Replace(c.compose, "secrets/TMP", "secrets/worker.env", 1)
				got := hashSetOf(t, runVerify(t, n, dir, compose, c.files))
				if maps.Equal(got, want) {
					t.Fatal("tampered wiring produced the expected hash set")
				}
				if got[c.diff] == want[c.diff] {
					t.Errorf("%s unchanged between expected and tampered sets", c.diff)
				}
			})
		}
	})

	t.Run("a name with no value resolves to null under env -i", func(t *testing.T) {
		compose := strings.Replace(spikeCompose, "      EMPTY: \"\"\n", "      EMPTY: \"\"\n      NOVALUE:\n", 1)
		got := hashSetOf(t, runVerify(t, n, dir, compose, spikeFiles()))
		if got["api/NOVALUE"] != "null" {
			t.Errorf("api/NOVALUE = %q; want null marker", got["api/NOVALUE"])
		}
	})

	t.Run("a service without environment contributes no rows", func(t *testing.T) {
		compose := "name: spike\nservices:\n  bare:\n    image: " + busyboxImage + "\n"
		r := runVerify(t, n, dir, compose, nil)
		if len(r.Set) != 0 {
			t.Errorf("set = %v; want empty", r.Set)
		}
		if strings.Contains(string(r.Model), `"environment"`) {
			t.Errorf("masked model invented an environment key: %s", r.Model)
		}
	})
}

func withFile(files map[string][]byte, name string, data []byte) map[string][]byte {
	out := maps.Clone(files)
	out[name] = data
	return out
}

// imageSizeScript prints the bytes (config + layers) of the manifest matching
// the node platform; exit 1 when it cannot be established (fail closed).
const imageSizeScript = `set -euo pipefail
os=$(docker version --format '{{.Server.Os}}')
arch=$(docker version --format '{{.Server.Arch}}')
docker manifest inspect --verbose ${2:-} "$1" | jq -e --arg os "$os" --arg arch "$arch" '
  (if type == "array" then . else [.] end)
  | map(select(.Descriptor.platform.os == $os and .Descriptor.platform.architecture == $arch))
  | if length == 1 then .[0] | (.SchemaV2Manifest // .OCIManifest) | (.config.size + ([.layers[].size] | add // 0)) else error("no unique platform match") end'
`

func TestFixtures_ManifestInspectVerboseSizes(t *testing.T) {
	n := startNode(t, fixture.Options{DemoContainer: true})
	n.shell(t, "docker run -d --name registry -p 127.0.0.1:5000:5000 registry:2")
	n.shell(t, `for i in $(seq 1 30); do bash -c 'exec 3<>/dev/tcp/127.0.0.1/5000' 2>/dev/null && exit 0; sleep 1; done; exit 1`)
	n.shell(t, "docker tag "+busyboxImage+" localhost:5000/bb:1 && docker push localhost:5000/bb:1 >/dev/null")
	n.shell(t, "docker manifest create --insecure localhost:5000/ml:1 localhost:5000/bb:1 >/dev/null")
	listPush := n.shell(t, "docker manifest push --insecure localhost:5000/ml:1")
	listDigest := listPush[strings.LastIndex(listPush, "sha256:"):]
	writeNodeFile(t, n, "/srv/size.sh", []byte(imageSizeScript))

	t.Run("sizes for an index digest sum config and layers of the node platform", func(t *testing.T) {
		out := n.shell(t, "bash /srv/size.sh localhost:5000/ml@"+listDigest+" --insecure")
		// Sizes from the pushed manifest: config 477 + one layer 1977510.
		want := n.shell(t, "docker manifest inspect --insecure localhost:5000/ml@"+listDigest+" --verbose | jq '[.[0].SchemaV2Manifest | .config.size, .layers[].size] | add'")
		t.Logf("node platform size = %s bytes", out)
		if out != want || out == "" || out == "0" {
			t.Errorf("size = %q; want %q (non-zero)", out, want)
		}
	})

	t.Run("an unknown digest fails closed", func(t *testing.T) {
		bogus := "sha256:" + strings.Repeat("0", 64)
		if out, err := n.tryShell(t, "bash /srv/size.sh localhost:5000/ml@"+bogus+" --insecure 2>&1"); err == nil {
			t.Errorf("size script succeeded for a missing digest: %s", out)
		}
	})
}
