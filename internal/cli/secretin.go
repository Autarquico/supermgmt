package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// secretInput says how one secret is read. Secrets (passphrases, secret
// values, tokens, bootstrap codes) are never flags, arguments or environment
// variables: they come from a terminal without echo, or from standard input.
type secretInput struct {
	// prompt is shown on stderr when stdin is a terminal.
	prompt string
	// whole reads all of stdin (a multi-line secret such as a PEM key). On a
	// terminal a secret is always a single line.
	whole bool
	// confirm asks twice on a terminal.
	confirm bool
	// limit bounds the size in bytes.
	limit int
}

// readSecret reads one secret from cmd's stdin. The value has its final line
// break removed and is never empty.
func readSecret(cmd *cobra.Command, in secretInput) (string, error) {
	stdin := cmd.InOrStdin()
	if file, ok := stdin.(*os.File); ok && isTerminal(file) {
		return readSecretFromTerminal(cmd, file, in)
	}
	return readSecretFromStream(stdin, in)
}

func readSecretFromStream(r io.Reader, in secretInput) (string, error) {
	var raw string
	if in.whole {
		data, err := io.ReadAll(io.LimitReader(r, int64(in.limit)+1))
		if err != nil {
			return "", fmt.Errorf("read standard input: %w", err)
		}
		raw = string(data)
	} else {
		line, err := bufio.NewReaderSize(io.LimitReader(r, int64(in.limit)+1), in.limit+2).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read standard input: %w", err)
		}
		raw = line
	}
	return checkSecret(strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r"), in.limit)
}

func readSecretFromTerminal(cmd *cobra.Command, tty *os.File, in secretInput) (string, error) {
	restore, err := disableEcho(int(tty.Fd()))
	if err != nil {
		return "", usageErrorf("cannot turn off terminal echo (%v): pipe the value on standard input instead", err)
	}
	defer restore()
	out := cmd.ErrOrStderr()
	first, err := promptLine(tty, out, in.prompt)
	if err != nil {
		return "", err
	}
	if in.confirm {
		again, err := promptLine(tty, out, "Repeat: ")
		if err != nil {
			return "", err
		}
		if again != first {
			return "", usageErrorf("the two entries differ")
		}
	}
	return checkSecret(first, in.limit)
}

// promptLine writes the prompt and reads one line byte by byte, so nothing
// past the line break is consumed from the terminal.
func promptLine(tty io.Reader, out io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(out, prompt)
	defer func() { _, _ = fmt.Fprintln(out) }()
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := tty.Read(buf)
		if n == 1 {
			if buf[0] == '\n' || buf[0] == '\r' {
				return string(line), nil
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return string(line), nil
			}
			return "", fmt.Errorf("read from the terminal: %w", err)
		}
	}
}

func checkSecret(value string, limit int) (string, error) {
	switch {
	case value == "":
		return "", usageErrorf("no value was given")
	case len(value) > limit:
		return "", usageErrorf("the value is longer than %d bytes", limit)
	}
	return value, nil
}
