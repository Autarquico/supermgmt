package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/autarquico/supermgmt/internal/audit"
	"github.com/autarquico/supermgmt/internal/join"
	"github.com/autarquico/supermgmt/internal/join/jointest"
)

const (
	cliConnectorToken = "eyJhIjoiYWNjb3VudCIsInQiOiJ0dW5uZWwtaWQiLCJzIjoic2VjcmV0LXNlbnRpbmVsLTEyMzQifQ=="
	cliHostKey        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/0rZjuLbOAYMUDGUQxdU6VZp13y6BXawIDIRfDnJPc"
	cliInstanceKey    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/0rZjuLbOAYMUDGUQxdU6VZp13y6BXawIDIRfDnJPc"
)

func runTunnelJoin(t *testing.T, host *jointest.StoppingHost, stdin string, prompt tokenPrompter, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	factory := func(string, []byte) (join.Joiner, error) {
		t.Error("the server-side join must not be built in tunnel mode")
		return join.Joiner{}, nil
	}
	root := &cobra.Command{Use: "sm", SilenceUsage: true, SilenceErrors: true}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErrorf("%s", err) })
	root.AddCommand(newJoinCmdFull(factory, func() join.TunnelJoiner { return join.TunnelJoiner{Host: host} }, prompt))
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"join"}, args...))
	err = root.Execute()
	if err != nil {
		reportError(&errOut, err, false)
	}
	return out.String(), errOut.String(), err
}

func tunnelArgs(extra ...string) []string {
	return append([]string{"--tunnel", "--instance", "inst-1", "--authorized-key", cliInstanceKey}, extra...)
}

func neverPrompt(t *testing.T) tokenPrompter {
	return func(io.Writer) (audit.Secret, error) {
		t.Error("the terminal was asked for a token")
		return "", nil
	}
}

func TestJoinTunnelReadsTheTokenFromStdinAndInstalls(t *testing.T) {
	host := &jointest.StoppingHost{HostKey: cliHostKey}

	_, errOut, err := runTunnelJoin(t, host, cliConnectorToken+"\n", neverPrompt(t), tunnelArgs("--token-stdin")...)

	if !errors.Is(err, jointest.ErrStopped) || !host.Mutated {
		t.Fatalf("err = %v, mutated = %v; want the install reached", err, host.Mutated)
	}
	if strings.Contains(errOut, cliConnectorToken) {
		t.Errorf("stderr carries the token: %q", errOut)
	}
}

func TestJoinTunnelAsksTheTerminalWhenNoStdinFlag(t *testing.T) {
	host := &jointest.StoppingHost{HostKey: cliHostKey}
	asked := false
	prompt := func(io.Writer) (audit.Secret, error) {
		asked = true
		return cliConnectorToken, nil
	}

	_, _, err := runTunnelJoin(t, host, "", prompt, tunnelArgs()...)

	if !asked || !errors.Is(err, jointest.ErrStopped) {
		t.Fatalf("asked = %v, err = %v", asked, err)
	}
}

func TestJoinTunnelRefusesABadTokenBeforeChangingAnything(t *testing.T) {
	host := &jointest.StoppingHost{HostKey: cliHostKey}

	_, errOut, err := runTunnelJoin(t, host, "not a token\n", neverPrompt(t), tunnelArgs("--token-stdin")...)

	if exitCode(err) != exitUsage || host.Mutated {
		t.Fatalf("code = %d, mutated = %v", exitCode(err), host.Mutated)
	}
	if strings.Contains(errOut, "not a token") {
		t.Errorf("stderr echoes the token: %q", errOut)
	}
}

func TestJoinTunnelDoesNotAskForTheTokenWhenAPreflightFails(t *testing.T) {
	host := &jointest.StoppingHost{HostKey: cliHostKey, PreflightErr: jointest.ErrStopped}

	_, _, err := runTunnelJoin(t, host, cliConnectorToken, neverPrompt(t), tunnelArgs("--token-stdin")...)

	if !errors.Is(err, jointest.ErrStopped) || host.Mutated {
		t.Fatalf("err = %v, mutated = %v", err, host.Mutated)
	}
}

func TestJoinTunnelRefusesATokenInTheArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"flag":                tunnelArgs("--token", cliConnectorToken),
		"flag with =":         tunnelArgs("--token=" + cliConnectorToken),
		"positional":          tunnelArgs(cliConnectorToken),
		"as the key":          {"--tunnel", "--instance", "inst-1", "--authorized-key", cliConnectorToken},
		"as the --token-file": tunnelArgs("--token-file", "/x"),
	} {
		t.Run(name, func(t *testing.T) {
			host := &jointest.StoppingHost{HostKey: cliHostKey}

			_, errOut, err := runTunnelJoin(t, host, "", neverPrompt(t), args...)

			if err == nil || host.Mutated {
				t.Fatalf("err = %v, mutated = %v", err, host.Mutated)
			}
			if name != "as the key" && strings.Contains(errOut, cliConnectorToken) {
				t.Errorf("stderr echoes the token: %q", errOut)
			}
		})
	}
}

func TestJoinTunnelRejectsInvalidFlagCombinations(t *testing.T) {
	for name, args := range map[string][]string{
		"no instance":         {"--tunnel", "--authorized-key", cliInstanceKey},
		"no key":              {"--tunnel", "--instance", "inst-1"},
		"with a server":       tunnelArgs("--server", "https://mgmt.example.com"),
		"with a ca file":      tunnelArgs("--ca-file", "/x"),
		"instance, no tunnel": {"--instance", "inst-1", "--server", "https://mgmt.example.com", "--token-stdin"},
	} {
		t.Run(name, func(t *testing.T) {
			host := &jointest.StoppingHost{HostKey: cliHostKey}

			_, _, err := runTunnelJoin(t, host, cliConnectorToken, neverPrompt(t), args...)

			if exitCode(err) != exitUsage || host.Mutated {
				t.Fatalf("code = %d, mutated = %v", exitCode(err), host.Mutated)
			}
		})
	}
}

func TestReadBoundedLineStopsAtTheLimitAndTheLineBreak(t *testing.T) {
	line, err := readBoundedLine(strings.NewReader("abc\nrest"), 10)
	if err != nil || line != "abc" {
		t.Fatalf("line = %q, %v", line, err)
	}
	reader := strings.NewReader(strings.Repeat("a", 50) + "\n")
	if _, err := readBoundedLine(reader, 10); exitCode(err) != exitUsage {
		t.Errorf("err = %v, want a usage error", err)
	}
	if reader.Len() < 30 {
		t.Errorf("kept reading past the limit: %d bytes left", reader.Len())
	}
	if _, err := readBoundedLine(strings.NewReader(""), 10); err == nil {
		t.Error("an empty terminal was accepted")
	}
}

func FuzzReadBoundedLine(f *testing.F) {
	f.Add("abc\n", 10)
	f.Add("abc", 2)
	f.Add("\r\n", 4)
	f.Add("", 1)
	f.Fuzz(func(t *testing.T, input string, limit int) {
		if limit < 0 || limit > 1<<12 {
			return
		}
		line, err := readBoundedLine(strings.NewReader(input), limit)
		if err == nil && (len(line) > limit || strings.ContainsAny(line, "\r\n")) {
			t.Fatalf("line %q breaks the bound %d or holds a line break", line, limit)
		}
	})
}

func FuzzReadConnectorTokenFromStream(f *testing.F) {
	f.Add(cliConnectorToken + "\n")
	f.Add("")
	f.Add(strings.Repeat("a", maxConnectorTokenInput+10))
	f.Fuzz(func(t *testing.T, input string) {
		token, err := readConnectorTokenFromStream(strings.NewReader(input))
		if err == nil && len(token.Reveal()) > maxConnectorTokenInput {
			t.Fatalf("read %d bytes past the bound", len(token.Reveal()))
		}
	})
}
