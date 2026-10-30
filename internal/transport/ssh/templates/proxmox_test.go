package templates

import "testing"

func TestRelayRendersTheFixedDestination(t *testing.T) {
	c, err := Relay{SocatPath: "/usr/local/bin/socat"}.Command()
	if err != nil {
		t.Fatal(err)
	}
	if want := `'/usr/local/bin/socat' STDIO TCP:127.0.0.1:8006`; c.Line != want {
		t.Errorf("line = %q, want %q", c.Line, want)
	}
}

func TestRelayAcceptsSocatOnlyInTheSystemDirectories(t *testing.T) {
	for _, ok := range []string{"/usr/bin/socat", "/bin/socat", "/usr/local/bin/socat"} {
		if _, err := (Relay{SocatPath: ok}).Command(); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "socat", "/socat", "/tmp/socat", "/usr/bin/socat2", "/usr/bin/sub/socat", "/usr/bin/../bin/socat",
		"/usr/bin/socat ", "/usr/bin/socat\n", "/usr/bin/socat; id", "/usr/sbin/socat", "/opt/bin/socat",
	} {
		if _, err := (Relay{SocatPath: bad}).Command(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRelayTakesNoArgumentOtherThanSocatsPath(t *testing.T) {
	if _, err := Render(RelayTemplate, map[string]string{"socat": "/usr/bin/socat", "addr": "10.0.0.1:22"}); err == nil {
		t.Error("an extra argument was accepted")
	}
	if _, err := Render(RelayTemplate, nil); err == nil {
		t.Error("the template rendered without socat's path")
	}
}
