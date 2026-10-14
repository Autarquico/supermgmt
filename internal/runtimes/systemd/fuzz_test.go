package systemd

import (
	"strings"
	"testing"
)

func FuzzParseProps(f *testing.F) {
	f.Add("ActiveState=active\nSubState=running\nExecStart=/bin/a\nExecStart=/bin/b\n")
	f.Add("=x\nnovalue\r\nK=\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		values := 0
		for key, vs := range parseProps(out) {
			if key == "" {
				t.Fatal("empty property key")
			}
			values += len(vs)
		}
		if lines := strings.Count(out, "\n") + 1; values > lines {
			t.Fatalf("%d values from %d lines", values, lines)
		}
	})
}

func FuzzParseUnits(f *testing.F) {
	f.Add("nginx.service loaded active running A web server\n● bad.service not-found failed failed Bad\n")
	f.Add("short.service loaded\nnotaservice.timer loaded active waiting x\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		if lines := strings.Count(out, "\n") + 1; len(parseUnits(out)) > lines {
			t.Fatalf("more units than the %d input lines", lines)
		}
	})
}

func FuzzParseSudoList(f *testing.F) {
	f.Add("User supermgmt may run the following commands on node:\n    (root) NOPASSWD: /usr/bin/systemctl start a.service, /usr/bin/systemctl stop a.service\n    (ALL) PASSWD: /bin/sh\n")
	f.Add("may run the following commands")
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		if commands := parseSudoList(out); len(commands) > len(out) {
			t.Fatalf("%d commands from %d bytes", len(commands), len(out))
		}
	})
}
