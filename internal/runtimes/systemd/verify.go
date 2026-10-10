package systemd

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/runtimes"
	"github.com/autarquico/supermgmt/internal/transport"
)

// VerifyParams is what the dedicated user must be able to do after Setup.
type VerifyParams struct {
	User          string
	SystemctlPath string
	Grants        []runtimes.UnitGrant
	LogsMode      runtimes.LogsMode
}

// Verify is ADR-0009 (f) step 8. ex must be a fresh session as the dedicated
// user: it checks the identity, that the markers directory is writable and
// that `sudo -n -l` lists exactly the rendered commands and nothing else.
func Verify(ctx context.Context, ex transport.Executor, p VerifyParams) error {
	want, err := SudoCommands(p.SystemctlPath, p.Grants, p.LogsMode)
	if err != nil {
		return err
	}
	if err := verifyIdentity(ctx, ex, p.User); err != nil {
		return err
	}
	if err := CheckSystemctlTrust(ctx, ex, p.SystemctlPath); err != nil {
		return err
	}
	got, err := listedSudo(ctx, ex)
	if err != nil {
		return err
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return verifyFailed("sudo -l does not match the rendered sudoers lines")
	}
	return nil
}

func verifyIdentity(ctx context.Context, ex transport.Executor, user string) error {
	id, err := succeeded(ctx, ex, "setup.verify_id", nil)
	if err != nil {
		return verifyFailed("cannot log in as the dedicated user")
	}
	if strings.TrimSpace(id) != user {
		return verifyFailed("the session is not the dedicated user")
	}
	markers, err := succeeded(ctx, ex, "setup.verify_markers", nil)
	if err != nil || strings.TrimSpace(markers) != "writable" {
		return verifyFailed("the markers directory is not writable")
	}
	return nil
}

// listedSudo returns what `sudo -n -l` lets the user run. A user with no sudo
// rights at all makes sudo fail, which is the empty list.
func listedSudo(ctx context.Context, ex transport.Executor) ([]string, error) {
	res, err := read(ctx, ex, "setup.verify_sudo", nil)
	if err != nil {
		return nil, err
	}
	if res.Truncated {
		return nil, verifyFailed("sudo -l output exceeds the limit")
	}
	if res.ExitStatus != 0 {
		return nil, nil
	}
	return parseSudoList(string(res.Stdout)), nil
}

var sudoEntry = regexp.MustCompile(`\(([^)]*)\) (?:([A-Z]+): )?`)

// parseSudoList extracts the commands of a `sudo -l` listing. sudo merges
// consecutive entries with the same run-as user and tags into one comma
// separated line and wraps long lines, so whitespace is normalized first.
// An entry that is not a plain `(root) NOPASSWD:` grant is reported as
// "<run-as>/<tag>: <command>" so it never equals a rendered command.
func parseSudoList(out string) []string {
	_, listing, found := strings.Cut(out, "may run the following commands")
	if !found {
		return nil
	}
	_, listing, _ = strings.Cut(listing, "\n")
	flat := strings.Join(strings.Fields(listing), " ")
	var commands []string
	heads := sudoEntry.FindAllStringSubmatchIndex(flat, -1)
	for i, h := range heads {
		end := len(flat)
		if i+1 < len(heads) {
			end = heads[i+1][0]
		}
		runAs, tag := flat[h[2]:h[3]], ""
		if h[4] >= 0 {
			tag = flat[h[4]:h[5]]
		}
		for _, command := range strings.Split(strings.TrimSpace(flat[h[1]:end]), ", ") {
			if runAs == "root" && tag == "NOPASSWD" {
				commands = append(commands, command)
			} else {
				commands = append(commands, fmt.Sprintf("%s/%s: %s", runAs, tag, command))
			}
		}
	}
	return commands
}

func verifyFailed(why string) error {
	return smerr.New(smerr.CodeCapabilityUnavailable, "", "node.setup verification failed: "+why)
}
