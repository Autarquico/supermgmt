package systemd

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	smerr "github.com/autarquico/supermgmt/internal/errors"
	"github.com/autarquico/supermgmt/internal/transport"
	"github.com/autarquico/supermgmt/internal/transport/ssh/templates"
)

var ansiSequence = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)

// read renders a read template and runs it. A non-zero exit status is a
// Result for the caller to judge, not an error.
func read(ctx context.Context, ex transport.Executor, name string, args map[string]string) (transport.Result, error) {
	c, err := templates.Render(name, args)
	if err != nil {
		return transport.Result{}, err
	}
	res, err := ex.Run(ctx, c)
	if err != nil {
		return transport.Result{}, fmt.Errorf("%s: %w", name, err)
	}
	return res, nil
}

// succeeded runs a read template and requires exit status 0 and complete output.
func succeeded(ctx context.Context, ex transport.Executor, name string, args map[string]string) (string, error) {
	res, err := read(ctx, ex, name, args)
	if err != nil {
		return "", err
	}
	if res.ExitStatus != 0 {
		return "", smerr.New(smerr.CodeCapabilityUnavailable, "", fmt.Sprintf("%s exited with status %d", name, res.ExitStatus))
	}
	if res.Truncated {
		return "", smerr.New(smerr.CodeInternal, "", name+": output exceeds the template limit")
	}
	return string(res.Stdout), nil
}

// sanitize makes remote text safe to store and display (spec §30): ANSI escape
// sequences, C0 and C1 controls (but tab) are dropped and invalid UTF-8 is
// replaced. Transports sanitize too; this keeps adapters safe on their own.
func sanitize(s string) string {
	s = ansiSequence.ReplaceAllString(s, "")
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	return strings.Map(func(r rune) rune {
		if r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, s)
}

// splitLines splits output into sanitized lines, without the trailing empty one.
func splitLines(out []byte) []string {
	text := strings.TrimRight(string(out), "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = sanitize(strings.TrimSuffix(line, "\r"))
	}
	return lines
}
