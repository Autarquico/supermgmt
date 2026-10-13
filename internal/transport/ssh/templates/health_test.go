package templates

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestHealthTemplatesRenderTheSpecCommands(t *testing.T) {
	http, err := Render("health.http", map[string]string{"addr": "127.0.0.1", "port": "8080", "path": "/health", "timeout": "3"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(http.Line, "env -i PATH=/usr/bin:/bin sh -c '") || !strings.HasSuffix(http.Line, " sh '127.0.0.1' '8080' '/health' '3'") {
		t.Errorf("health.http line = %s", http.Line)
	}
	for _, part := range []string{"curl -q --noproxy", "--proto =http,https", "--max-redirs 0", `--max-time "$4"`, "--silent --show-error", "--output /dev/null"} {
		if !strings.Contains(http.Line, part) {
			t.Errorf("health.http lacks %q", part)
		}
	}
	tcp, err := Render("health.tcp", map[string]string{"addr": "::1", "port": "5432", "timeout": "3"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tcp.Line, "env -i PATH=/usr/bin:/bin sh -c '") || !strings.HasSuffix(tcp.Line, " sh '::1' '5432' '3'") ||
		!strings.Contains(tcp.Line, "/dev/tcp/") {
		t.Errorf("health.tcp line = %s", tcp.Line)
	}
	docker, err := Render("health.docker", map[string]string{"container": "shop-api-1"})
	if err != nil {
		t.Fatal(err)
	}
	want := `docker inspect --type container --format "$(printf '\173\173if .State.Health\175\175\173\173.State.Health.Status\175\175\173\173else\175\175none\173\173end\175\175')" 'shop-api-1'`
	if docker.Line != want {
		t.Errorf("health.docker\n got %s\nwant %s", docker.Line, want)
	}
}

func TestHealthHTTPBuildsTheURLFromItsArguments(t *testing.T) {
	requireTools(t, "sh")
	tests := []struct{ addr, url string }{
		{"127.0.0.1", "http://127.0.0.1:8080/health"},
		{"10.0.0.5", "http://10.0.0.5:8080/health"},
		{"::1", "http://[::1]:8080/health"},
	}
	for _, tc := range tests {
		argv := filepath.Join(t.TempDir(), "argv")
		res := script{
			interpreter: "sh", text: healthHTTPScript, args: []string{tc.addr, "8080", "/health", "3"},
			pathShims: map[string]string{"curl": `printf '%s\n' "$@" > "$ARGV"; printf 204`}, env: []string{"ARGV=" + argv},
		}.run(t)
		if res.err != nil || res.stdout != "204" {
			t.Fatalf("%s: %v %q", tc.addr, res.err, res.stdout)
		}
		raw, _ := os.ReadFile(argv)
		args := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if args[0] != "-q" || args[len(args)-1] != tc.url {
			t.Errorf("%s: curl argv = %q, want -q first and %s last", tc.addr, args, tc.url)
		}
		if !strings.Contains(strings.Join(args, " "), "--max-redirs 0 --max-time 3") {
			t.Errorf("%s: redirects or timeout not pinned: %q", tc.addr, args)
		}
	}
}

func TestHealthTCPSucceedsOnlyWhenSomethingListens(t *testing.T) {
	requireTools(t, "bash")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	probe := func() error {
		return script{
			interpreter: "sh", text: healthTCPScript, args: []string{"127.0.0.1", port, "3"},
			pathShims: map[string]string{"timeout": `shift; exec "$@"`},
		}.run(t).err
	}
	if err := probe(); err != nil {
		t.Errorf("open port: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if probe() == nil {
		t.Error("closed port reported healthy")
	}
}

func TestHealthParametersAreSyntacticallyStrict(t *testing.T) {
	tests := map[string]struct {
		validate func(string) error
		ok, bad  []string
	}{
		"addr": {
			ValidateHealthAddr,
			[]string{"127.0.0.1", "::1", "10.0.0.5", "2001:db8::1"},
			[]string{"localhost", "0.0.0.0", "::", "127.0.0.1:80", "fe80::1%eth0", "[::1]", "224.0.0.1", "::ffff:127.0.0.1", "127.1", "01.2.3.4", " 1.2.3.4", "1.2.3.4 ", "EXAMPLE.com", "::0001"},
		},
		"port":    {ValidateHealthPort, []string{"1", "8080", "65535"}, []string{"0", "65536", "08080", "-1", "80a", "", "1e3", "+80"}},
		"timeout": {ValidateHealthTimeout, []string{"1", "3", "60"}, []string{"0", "61", "3s", "03", "-1", "1.5"}},
		"path": {
			Matching(healthPathPattern),
			[]string{"/", "/health", "/a/b-c_d.e~f", "/" + strings.Repeat("a", 255)},
			[]string{"health", "/a?x=1", "/a#f", "/a b", "/a;b", "/$(id)", "/a'b", "/a\nb", "/%2e", "/" + strings.Repeat("a", 256), "http://x/"},
		},
	}
	for name, tc := range tests {
		for _, s := range tc.ok {
			if err := tc.validate(s); err != nil {
				t.Errorf("%s %q: %v", name, s, err)
			}
		}
		for _, s := range tc.bad {
			if tc.validate(s) == nil {
				t.Errorf("%s %q accepted", name, s)
			}
		}
	}
}
