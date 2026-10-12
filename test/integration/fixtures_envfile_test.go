//go:build fixtures

package integration

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/autarquico/supermgmt/test/fixtures/fixture"
)

// envCorpus is the value corpus of ADR-0010: every shape a secret value can
// take under the `secret.write` rule for apps/… (no NUL, CR, LF; valid UTF-8).
var envCorpus = []envPair{
	{"V_DOLLAR", `a$b`},
	{"V_DOLLAR_BRACE", `x${C}y`},
	{"V_DOLLAR_PAIR", `a$$b`},
	{"V_DOLLAR_ONLY", `$`},
	{"V_DOLLAR_TRAILING", `cost$`},
	{"V_DQUOTE", `"q's"`},
	{"V_SQUOTE", `'single'`},
	{"V_HASH", `v#notcomment`},
	{"V_HASH_LEADING", `#start`},
	{"V_SPACE_INNER", `two  words`},
	{"V_SPACE_LEADING", `  lead`},
	{"V_SPACE_TRAILING", `trail  `},
	{"V_SPACE_ONLY", `   `},
	{"V_EQUALS", `a=b=c`},
	{"V_BACKSLASH", `back\slash\n\\`},
	{"V_UNICODE", "héllo ✓ \U0001F512"},
	{"V_EMPTY", ``},
	{"V_PERCENT", `100%s`},
	{"V_BACKTICK", "`id`"},
	{"V_TAB", "a\tb"},
}

const (
	nodePath       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	envFileCompose = `name: envfile
services:
  web:
    image: ` + busyboxImage + `
    env_file:
      - path: secrets/web.env
        format: raw
        required: true
`
)

// writeNodeFile writes data byte-exact (mode 0600) inside the node.
func writeNodeFile(t *testing.T, n *fixtureNode, path string, data []byte) {
	t.Helper()
	dir := path[:strings.LastIndex(path, "/")]
	n.shell(t, "mkdir -p "+dir+" && printf %s "+base64.StdEncoding.EncodeToString(data)+" | base64 -d > "+path+" && chmod 0600 "+path)
}

func rawEnvFile(pairs []envPair) []byte {
	var b strings.Builder
	for _, p := range pairs {
		b.WriteString(p.name + "=" + p.value + "\n")
	}
	return []byte(b.String())
}

type envPair struct{ name, value string }

// unescapeComposeDollar undoes the `$` -> `$$` escaping `config` applies to
// every string so its output can be re-interpolated.
func unescapeComposeDollar(s string) string { return strings.ReplaceAll(s, "$$", "$") }

func TestEnvFile_CorpusRoundTrip(t *testing.T) {
	n := startNode(t, fixture.Options{DemoContainer: true})
	const dir = "/srv/envfile"
	writeNodeFile(t, n, dir+"/compose.yaml", []byte(envFileCompose))
	writeNodeFile(t, n, dir+"/secrets/web.env", rawEnvFile(envCorpus))
	compose := "env -i PATH=" + nodePath + " docker compose -f " + dir + "/compose.yaml -p envfile --project-directory " + dir

	t.Run("compose version is the pinned CLI", func(t *testing.T) {
		out := n.shell(t, "docker compose version --short")
		if out != "v5.5.1" && out != "5.5.1" {
			t.Errorf("docker compose version --short = %q; want 5.5.1", out)
		}
	})

	t.Run("config resolves every value verbatim", func(t *testing.T) {
		raw := n.shell(t, compose+" config --format json 2>/dev/null")
		var model struct {
			Services map[string]struct {
				Environment map[string]*string `json:"environment"`
			} `json:"services"`
		}
		if err := json.Unmarshal([]byte(raw), &model); err != nil {
			t.Fatalf("config json: %v\n%s", err, raw)
		}
		env := model.Services["web"].Environment
		for _, c := range envCorpus {
			got, ok := env[c.name]
			if !ok || got == nil {
				t.Errorf("%s: missing from resolved environment (got %v)", c.name, got)
				continue
			}
			if v := unescapeComposeDollar(*got); v != c.value {
				t.Errorf("%s: resolved %q; want %q", c.name, v, c.value)
			}
		}
		if len(env) != len(envCorpus) {
			t.Errorf("resolved %d names; want %d", len(env), len(envCorpus))
		}
	})

	t.Run("container environment is verbatim", func(t *testing.T) {
		names := make([]string, len(envCorpus))
		for i, c := range envCorpus {
			names[i] = c.name
		}
		probe := `for n in ` + strings.Join(names, " ") + `; do printf "%s " "$n"; printenv "$n" | base64 | tr -d "\n"; echo; done`
		out := n.shell(t, compose+" run --rm -T --no-deps web sh -c '"+probe+"' 2>/dev/null")
		seen := map[string]string{}
		for line := range strings.SplitSeq(out, "\n") {
			name, b64, _ := strings.Cut(strings.TrimSpace(line), " ")
			dec, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				t.Fatalf("decode %q: %v", line, err)
			}
			seen[name] = string(dec)
		}
		for _, c := range envCorpus {
			if got, want := seen[c.name], c.value+"\n"; got != want {
				t.Errorf("%s: container sees %q; want %q", c.name, got, want)
			}
		}
	})

	t.Run("a missing required env file fails closed", func(t *testing.T) {
		n.shell(t, "mv "+dir+"/secrets/web.env "+dir+"/secrets/web.env.gone")
		defer n.shell(t, "mv "+dir+"/secrets/web.env.gone "+dir+"/secrets/web.env")
		if out, err := n.tryShell(t, compose+" config --format json 2>&1"); err == nil {
			t.Errorf("config succeeded without the required env file:\n%s", out)
		}
	})
}
